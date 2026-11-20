"""What's wrong with a connection: its problem, the details and what was checked.

The problem is the first of: disabled, not set up locally (interface, charon,
route), why it last failed (see vpnc.services.failures), or what its state and
the peer's packets tell.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from ipaddress import ip_network
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel

from vpnc import config, eventlog
from vpnc.api import config_files, events, status
from vpnc.models import enums
from vpnc.models.ipsec import Initiation
from vpnc.network import namespace
from vpnc.services import charon, failures, peers, probes
from vpnc.services.strongswan import identity, strongswan

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

IPSEC = enums.ConnectionType.IPSEC
WIREGUARD = enums.ConnectionType.WIREGUARD
SSH = enums.ConnectionType.SSH
PHYSICAL = enums.ConnectionType.PHYSICAL

# Seconds without a packet from a peer before it counts as silent: longer than
# the pauses between its tries.
SILENT_AFTER = 90

# A noted failure from longer before the connection went down isn't why it's down.
STALE = 120
# This often down in FLAPPING_PERIOD seconds: flapping.
FLAPPING = 5
FLAPPING_PERIOD = 3600
# Packets sent through a child SA without any received: one way.
ONE_WAY_PACKETS = 10
# States of a child SA that carries traffic; REKEYING until its successor does.
CHILD_SA_IN_USE = ("INSTALLED", "REKEYING")

# Problems that aren't a failure reason (those are in failures.REASONS).
PROBLEMS = {
    "ADMIN_DOWN": "it's disabled in the configuration",
    "NO_INTERFACE": "its interface doesn't exist",
    "ML_KEM_UNSUPPORTED": "charon lacks the ML-KEM key exchange it's configured with",
    "NOT_LOADED": "charon doesn't have the connection",
    "NOT_IN_FIREWALL": "EXTERNAL's firewall doesn't let the peer in",
    "NO_ROUTE": "there's no route to the peer",
    "PROBES_FAILING": "it's up, but none of its probes is answered",
    "ONE_WAY_TRAFFIC": "it's up and sends packets, but receives none",
    "FLAPPING": "it's up now, but keeps going down",
    "NO_RESPONSE": "nothing is received from the peer",
    "WAITING_FOR_PEER": "it only responds, and the peer doesn't set it up",
    "CONNECTING": "it's being set up",
    "KEY_MISMATCH": "the peer sends packets, but no handshake completes",
    "NO_CARRIER": "the interface has no carrier",
    "DOWN": "it's down; no reason was noted",
}
# Found before anything is tried, and while a connection is up.
LOCAL = (
    "ADMIN_DOWN",
    "NO_INTERFACE",
    "ML_KEM_UNSUPPORTED",
    "NOT_LOADED",
    "NOT_IN_FIREWALL",
    "NO_ROUTE",
)
WHILE_UP = ("PROBES_FAILING", "ONE_WAY_TRAFFIC", "FLAPPING")
# What's configured that a problem is about, shown next to what the peer sent.
_IDS = (
    "configured_local_id",
    "configured_remote_id",
    "configured_local_id_type",
    "configured_remote_id_type",
)
CONFIGURED = {
    "AUTH_FAILED_REMOTE": _IDS,
    "AUTH_FAILED_LOCAL": _IDS,
    "ID_MISMATCH": _IDS,
    "PPK_MISMATCH": ("configured_ppk_id",),
    "IKE_PROPOSAL_MISMATCH": ("configured_ike_proposal",),
    "CHILD_PROPOSAL_MISMATCH": ("configured_ipsec_proposal",),
    "TS_MISMATCH": ("configured_local_ts", "configured_remote_ts"),
}
# An ID_MISMATCH where the peer's id has the configured value, so its type differs.
ID_TYPE_HINT = (
    "the peer uses {id} with another type than the configured {type}: set "
    "{side}_id's type as the peer has it, e.g. with a prefix such as fqdn:"
)
# What to do about a problem; {name} is the connection.
HINTS = {
    "ADMIN_DOWN": "vpnctl connections start {name}",
    "NO_INTERFACE": "see vpnctl connections logs {name}",
    "ML_KEM_UNSUPPORTED": "strongSwan 6 is needed (Ubuntu 26.04), or disable "
    "post_quantum",
    "NOT_LOADED": "see vpnctl logs --source charon and vpnctl connections logs {name}",
    "NOT_IN_FIREWALL": "see vpnctl firewall EXTERNAL and vpnctl logs",
    "NO_ROUTE": "check EXTERNAL's addresses and routes: vpnctl routes EXTERNAL",
    "PROBES_FAILING": "see vpnctl connections probes {name}; the peer may not route "
    "or allow them",
    "ONE_WAY_TRAFFIC": "ESP (IP protocol 50, or UDP 4500 behind NAT) may be blocked "
    "towards this side, or the peer has no route back",
    "FLAPPING": "see vpnctl connections events {name} for when and why",
    "NO_RESPONSE": "check remote_addrs, that the peer is up, and that firewalls and "
    "NAT in between pass the traffic",
    "NO_RESPONSE_AUTH": "UDP 4500 or IP fragments may be blocked in between; some "
    "peers also stay silent on a wrong PSK or id",
    "DPD_TIMEOUT": "the peer or the path to it went down; it's retried",
    "CLOSED_BY_PEER": "the peer ended it, e.g. disabled or reconfigured there",
    "WAITING_FOR_PEER": "have the peer initiate, or set initiation to START",
    "AUTH_FAILED_REMOTE": "compare psk, the PPK's key, local_id and remote_id with the "
    "peer's",
    "AUTH_FAILED_LOCAL": "compare psk and the PPK's key with the peer's",
    "AUTH_METHOD_MISMATCH": "the peer must use a preshared key (PSK)",
    "ID_MISMATCH": "set local_id and remote_id to what the peer uses, or change "
    "the peer's",
    "PPK_MISMATCH": "compare post_quantum.ppk with the peer's",
    "IKE_VERSION_MISMATCH": "set ike_version as the peer has it",
    "IKE_CONFIG_MISMATCH": "compare ike_version and remote_addrs with the peer's",
    "IKE_PROPOSAL_MISMATCH": "set ike_proposal (and post_quantum) as the peer has it",
    "CHILD_PROPOSAL_MISMATCH": "set ipsec_proposal (and post_quantum) as the peer "
    "has it",
    "TS_MISMATCH": "set traffic_selectors so local and remote overlap the peer's",
    "REJECTED_BY_PEER": "see the peer's log for why",
    "CHILD_REJECTED_BY_PEER": "see the peer's log for why",
    "KERNEL_FAILED": "see vpnctl logs --source charon; the kernel may lack an "
    "algorithm",
    "KEY_MISMATCH": "compare public_key and the peer's private key, and this side's "
    "public key with what the peer has",
    "PERMISSION_DENIED": "install this side's key on the server: vpnctl connections "
    "ssh-setup {name}",
    "HOST_KEY_MISMATCH": "if the server was replaced, delete host_key from the "
    "connection's configuration to accept its new key, or set it",
    "REFUSED": "check that sshd runs on the server and listens on the port",
    "NEGOTIATION_FAILED": "the server's OpenSSH may be too old for post_quantum",
    "TUNNEL_REFUSED": "set up the server: vpnctl connections ssh-setup {name}",
    "NO_CARRIER": "check the cable or the virtual network of the interface",
}


class Check(BaseModel):
    """Something that was looked at, and what it showed."""

    name: str
    # INFO: neither good nor bad.
    result: Literal["OK", "FAILED", "INFO"]
    detail: str


class Diagnosis(BaseModel):
    """What's wrong with a connection, if anything."""

    id: str
    type: enums.ConnectionType
    admin_status: status.AdminStatus
    oper_status: status.OperStatus
    last_change: str
    # E.g. ID_MISMATCH; None: nothing wrong was found.
    problem: str | None
    summary: str
    hint: str | None
    # Of the problem: what's configured, sent and received.
    details: dict[str, Any]
    # A noted failure: how long and how often it happened.
    first_seen: str | None = None
    last_seen: str | None = None
    count: int | None = None
    # What charon or ssh reported.
    evidence: list[str] = []
    checks: list[Check]


def _timestamp(seconds: float) -> str:
    return dt.datetime.fromtimestamp(seconds).astimezone().isoformat(timespec="seconds")


def _seconds(timestamp: str) -> float:
    return dt.datetime.fromisoformat(timestamp).timestamp()


def _ago(seconds: float) -> str:
    return f"{eventlog.duration(time.time() - seconds)} ago"


def _route(address: str) -> str | None:
    """Return EXTERNAL's route to an address, e.g. via 192.0.2.1 dev eth1."""
    result = namespace.run(
        config.EXTERNAL_NI,
        ["/usr/sbin/ip", "-j", "route", "get", address],
        timeout=5,
    )
    try:
        route = json.loads(result.stdout or "[]")[0]
    except (ValueError, IndexError):
        return None
    if route.get("type", "unicast") != "unicast" or not route.get("dev"):
        return None
    gateway = f"via {route['gateway']} " if route.get("gateway") else ""
    return f"{gateway}dev {route['dev']}"


def _id(tunnel: status.Tunnel, side: str, configured: str) -> str:
    """Return a session's id, with its type if known and the configured one."""
    kind = getattr(tunnel, f"{side}_identity_type")
    known = f"{kind}, " if kind else ""
    return f"{getattr(tunnel, f'{side}_identity')} ({known}configured {configured})"


def _within(selectors: list[str], configured: list[str]) -> bool:
    """Return whether each traffic selector is part of a configured one."""
    try:
        wanted = [ip_network(item) for item in configured]
        return all(
            any(net.version == w.version and net.subnet_of(w) for w in wanted)  # type: ignore[arg-type]
            for net in map(ip_network, selectors)
        )
    except ValueError:
        # With a protocol or port.
        return False


class _Diagnoser:
    """Check a connection and decide what its problem is."""

    def __init__(self, ni: NetworkInstance, connection: Connection) -> None:
        self.ni = ni
        self.connection = connection
        self.cfg = connection.config
        self.name = connection.name(ni)
        self.state = next(
            s for s in status.connection_states([ni]) if s.id == self.name
        )
        self.up = self.state.oper_status == "UP"
        self.checks: list[Check] = []
        self.details: dict[str, Any] = {}
        # Of the first check that failed.
        self.problem: str | None = None

    def check(self, name: str, detail: str, *, ok: bool | None, problem: str) -> None:
        """Add a check; a failed one is the problem if there's none yet."""
        result: Literal["OK", "FAILED", "INFO"] = (
            "INFO" if ok is None else "OK" if ok else "FAILED"
        )
        self.checks.append(Check(name=name, result=result, detail=detail))
        if ok is False and self.problem is None:
            self.problem = problem

    def local(self) -> None:
        """Check what this side needs: enabled, an interface, charon, a route."""
        enabled = self.connection.enabled
        self.check(
            "admin status",
            "enabled" if enabled else "disabled (enabled: false)",
            ok=enabled,
            problem="ADMIN_DOWN",
        )
        if not enabled:
            return
        if config_files.staged(self.ni.tenant_id):
            self.check(
                "configuration",
                "has staged changes that aren't committed",
                ok=None,
                problem="",
            )
        interface = self.state.interface
        self.check(
            "interface",
            interface or "missing",
            ok=interface is not None,
            problem="NO_INTERFACE",
        )
        if self.cfg.type == IPSEC:
            for what, _ in self.cfg.weaknesses().values():
                self.check("cryptography", f"weak: {what}", ok=None, problem="")
            self.charon()
        if self.cfg.type in (IPSEC, WIREGUARD):
            routes = {a: _route(a) for a in map(str, self.cfg.remote_addrs)}
            for address, route in routes.items():
                self.check(
                    "route to peer",
                    f"{address} {route}" if route else f"none to {address}",
                    # One address with a route is enough.
                    ok=True if route else None if any(routes.values()) else False,
                    problem="NO_ROUTE",
                )

    def charon(self) -> None:
        """Check that charon has the connection."""
        if self.name in strongswan.REFUSED:
            self.check(
                "charon",
                f"lacks {self.cfg.post_quantum.ml_kem.value}",
                ok=False,
                problem="ML_KEM_UNSUPPORTED",
            )
            return
        with charon.session() as vcs:
            loaded = self.name in charon.loaded_connections(vcs)
        self.check(
            "charon",
            "has the connection" if loaded else "doesn't have the connection",
            ok=loaded,
            problem="NOT_LOADED",
        )

    def peer_silent(self) -> bool | None:
        """Check the packets of the peer; return whether it's silent, if known."""
        if self.cfg.type not in (IPSEC, WIREGUARD):
            return None
        seen = peers.seen(self.connection)
        now = time.time()
        silent: list[bool] = []
        for address in map(str, self.cfg.remote_addrs):
            if (counted := seen.get(address)) is None:
                self.check(
                    "packets from peer",
                    f"{address} isn't in EXTERNAL's firewall",
                    ok=False,
                    problem="NOT_IN_FIREWALL",
                )
                continue
            if counted.last is not None:
                quiet = now - counted.last > SILENT_AFTER
                detail = f"{address}: last one {_ago(counted.last)}"
            elif now - counted.since > SILENT_AFTER:
                quiet = True
                detail = f"{address}: none since {_timestamp(counted.since)}"
            else:
                # Counted too short to tell.
                continue
            silent.append(quiet)
            self.check(
                "packets from peer",
                detail,
                # One address that's used is enough.
                ok=None if quiet and (self.up or not all(silent)) else not quiet,
                problem="NO_RESPONSE",
            )
        return all(silent) if silent else None

    def ipsec(self) -> None:
        """Add what's configured next to what's negotiated: ids, traffic selectors."""
        if (conn := strongswan.connections(self.ni).get(self.name)) is None:
            return
        child = conn[0]["children"][self.name]
        local_id, remote_id = conn[0]["local"]["id"], conn[0]["remote"]["id"]
        self.details.update(
            configured_local_id=local_id,
            configured_remote_id=remote_id,
            configured_local_id_type=identity.parse(local_id)[0],
            configured_remote_id_type=identity.parse(remote_id)[0],
            configured_ike_proposal=conn[0]["proposals"][0],
            configured_ipsec_proposal=child["esp_proposals"][0],
            configured_local_ts=child["local_ts"],
            configured_remote_ts=child["remote_ts"],
            configured_ppk_id=conn[0].get("ppk_id"),
        )
        if (tunnel := self.state.tunnel) is None:
            self.check("IKE SA", "none", ok=None, problem="")
            return
        self.check(
            "IKE SA",
            f"{tunnel.state}, local id {_id(tunnel, 'local', local_id)}, "
            f"remote id {_id(tunnel, 'remote', remote_id)}",
            ok=tunnel.state == "ESTABLISHED",
            problem="CONNECTING",
        )
        wanted = f"{' '.join(child['local_ts'])} === {' '.join(child['remote_ts'])}"
        in_use = any(sa.state in CHILD_SA_IN_USE for sa in tunnel.sas)
        for sa in tunnel.sas:
            sides = (
                (sa.local_ts, child["local_ts"]),
                (sa.remote_ts, child["remote_ts"]),
            )
            if all(sorted(got) == sorted(want) for got, want in sides):
                compared = "as configured"
            elif all(_within(got, want) for got, want in sides):
                compared = f"narrowed from {wanted}"
            else:
                # E.g. negotiated before the configuration changed.
                compared = f"differs from the configured {wanted}"
            self.check(
                "child SA",
                f"{sa.state}, traffic selectors {' '.join(sa.local_ts)} === "
                f"{' '.join(sa.remote_ts)} ({compared})",
                # A rekey's other child SA isn't a problem.
                ok=sa.state in CHILD_SA_IN_USE or (None if in_use else False),
                problem="CONNECTING",
            )
            sent, received = sa.out_pkts or 0, sa.in_pkts or 0
            if sa.state == "INSTALLED" and sent >= ONE_WAY_PACKETS and not received:
                self.check(
                    "traffic",
                    f"{sent} packets sent, none received",
                    ok=False,
                    problem="ONE_WAY_TRAFFIC",
                )
        if not tunnel.sas:
            self.check("child SA", "none", ok=False, problem="CONNECTING")

    def session(self) -> None:
        """Check the session of a VPN connection."""
        tunnel = self.state.tunnel
        if self.cfg.type == IPSEC:
            self.ipsec()
        elif self.cfg.type == WIREGUARD:
            handshake = tunnel.last_handshake if tunnel else None
            self.check(
                "handshake",
                f"last one {_ago(_seconds(handshake))}" if handshake else "none yet",
                ok=self.up,
                problem="DOWN",
            )
        elif self.cfg.type == SSH:
            self.check(
                "session",
                (tunnel.state or "none") if tunnel else "ssh isn't running",
                ok=bool(tunnel and tunnel.state == "ESTABLISHED"),
                problem="CONNECTING" if tunnel else "DOWN",
            )

    def while_up(self) -> None:
        """Check a connection that's up: its probes, and how often it went down."""
        if self.connection.probes:
            failing = probes.failing(self.name)
            self.check(
                "probes",
                "none is answered" if failing else "answered",
                ok=not failing,
                problem="PROBES_FAILING",
            )
        query = events.Query(
            connection=self.name,
            event="OPER_DOWN",
            since=FLAPPING_PERIOD,
        )
        if (downs := len(query.last(FLAPPING * 10))) >= FLAPPING:
            self.check(
                "stability",
                f"went down {downs} times in the last hour",
                ok=False,
                problem="FLAPPING",
            )
        if resets := self.state.auto_resets_24h:
            self.check(
                "auto resets",
                f"reset by vpnc {resets} times in the last 24 hours",
                ok=None,
                problem="",
            )

    def derived(self, *, silent: bool | None) -> str:
        """Return the problem of a connection that's down without a noted failure."""
        ctype = self.cfg.type
        if ctype == PHYSICAL:
            return "NO_CARRIER"
        if silent:
            return "NO_RESPONSE"
        if ctype == WIREGUARD:
            # WireGuard doesn't say why; unknown until the peer's packets are counted.
            return "KEY_MISMATCH" if silent is False else "DOWN"
        if ctype == IPSEC and self.cfg.initiation != Initiation.INITIATOR:
            return "WAITING_FOR_PEER"
        return "CONNECTING" if self.problem == "CONNECTING" else "DOWN"

    def relevant(
        self,
        problem: str | None,
        failure: failures.Failure | None,
    ) -> dict[str, Any]:
        """Return the details of the problem: what the peer sent, what's configured."""
        details: dict[str, Any] = dict(failure.details) if failure else {}
        if "configured_proposals" in details:
            # As charon names them, next to the received ones.
            return details
        keys = CONFIGURED.get(problem or "", ())
        return {**details, **{k: self.details[k] for k in keys if k in self.details}}

    def id_type_mismatch(self, details: dict[str, Any]) -> dict[str, str] | None:
        """Return the id the peer uses with the configured value, if any."""
        for received, side in (
            ("received_remote_id", "remote"),
            ("requested_local_id", "local"),
        ):
            kind, value = identity.parse(self.details.get(f"configured_{side}_id", ""))
            if kind and details.get(received) == value:
                return {"id": value, "type": kind, "side": side}
        return None

    def run(self) -> Diagnosis:
        """Check the connection and return what's wrong with it."""
        self.local()
        silent = None
        if self.connection.enabled:
            silent = self.peer_silent()
            self.session()
            if self.up:
                self.while_up()
        failure = None
        if self.problem in LOCAL:
            problem: str | None = self.problem
        elif self.up:
            problem = self.problem if self.problem in WHILE_UP else None
        else:
            noted = failures.get(self.name)
            since = status.down_since(self.name)
            if noted and (since is None or noted.last >= since - STALE):
                failure = noted
            problem = failure.reason if failure else self.derived(silent=silent)
        summary = "nothing wrong was found"
        if problem is not None:
            summary = {**failures.REASONS, **PROBLEMS}.get(problem, problem)
        details = self.relevant(problem, failure)
        hint = HINTS.get(problem or "")
        hint = hint.format(name=self.name) if hint else None
        if problem == "ID_MISMATCH" and (same := self.id_type_mismatch(details)):
            hint = ID_TYPE_HINT.format(**same)
        return Diagnosis(
            id=self.name,
            type=self.cfg.type,
            admin_status=self.state.admin_status,
            oper_status=self.state.oper_status,
            last_change=self.state.last_change,
            problem=problem,
            summary=summary,
            hint=hint,
            details=details,
            first_seen=_timestamp(failure.first) if failure else None,
            last_seen=_timestamp(failure.last) if failure else None,
            count=failure.count if failure else None,
            evidence=failure.evidence if failure else [],
            checks=self.checks,
        )


def diagnose(ni: NetworkInstance, connection: Connection) -> Diagnosis:
    """Return what's wrong with a connection, if anything."""
    return _Diagnoser(ni, connection).run()
