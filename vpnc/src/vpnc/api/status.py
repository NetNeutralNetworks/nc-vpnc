"""Live state of tenants, network instances and connections, read on request."""

from __future__ import annotations

import collections
import contextlib
import dataclasses
import datetime as dt
import json
import logging
import os
import re
import subprocess
import threading
import time
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel
from pyroute2.netlink.exceptions import NetlinkError

import vpnc
from vpnc import config, eventlog, helpers
from vpnc.api import config_files, diagnostics
from vpnc.models import enums
from vpnc.network import nftables, state, traffic
from vpnc.services import (
    charon,
    configuration,
    failures,
    probes,
    ssh,
    vpncmangle,
    wireguard,
)
from vpnc.services.strongswan import identity, strongswan

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# A WireGuard peer without a handshake for this long is down (it renews every
# two minutes while there's traffic, and keepalives cause traffic).
WIREGUARD_TIMEOUT = 180

IPAddress = IPv4Address | IPv6Address

# Named and valued as in OpenConfig, like the counters and rates.
AdminStatus = Literal["UP", "DOWN"]
# DORMANT: being set up (an IKE SA that isn't established yet).
OperStatus = Literal["UP", "DOWN", "DORMANT"]


class Counters(BaseModel):
    """Traffic through a connection's interface since it was created."""

    in_octets: int
    in_pkts: int
    in_errors: int
    in_discards: int
    out_octets: int
    out_pkts: int
    out_errors: int
    out_discards: int


class Rates(BaseModel):
    """Traffic through a connection's interface: the average of the last seconds."""

    # Seconds the rates are measured over.
    load_interval: int
    # Bits per second.
    in_bits_rate: int
    out_bits_rate: int


class ProbeState(BaseModel):
    """A probe of a connection and its last test, named as in OpenConfig."""

    description: str | None
    address: str
    test_type: enums.TestType
    port: int | None
    # None: not tested in the last full check, as the connection wasn't up.
    failed: bool | None
    last_test_timestamp: str | None


class ProbeTest(BaseModel):
    """A test of a probe."""

    timestamp: str
    failed: bool
    # Microseconds until the answer.
    avg_delay: int | None


class ProbeDetail(ProbeState):
    """A probe of a connection with its last tests, oldest first."""

    history: list[ProbeTest]


class SecurityAssociation(BaseModel):
    """An IPsec child SA as negotiated."""

    name: str
    # Changes when it's set up again (rekeyed).
    id: int | None
    # E.g. INSTALLED, REKEYED, DELETED.
    state: str | None
    encryption: str | None
    # None with AEAD encryption (e.g. AES_GCM).
    integrity: str | None
    # Of PFS: the classical one and the additional (ML-KEM) ones; empty without.
    key_exchange: list[str]
    spi_in: str | None
    spi_out: str | None
    local_ts: list[str]
    remote_ts: list[str]
    in_octets: int | None
    in_pkts: int | None
    out_octets: int | None
    out_pkts: int | None
    installed: str | None
    rekey: str | None
    expires: str | None


class Tunnel(BaseModel):
    """A VPN connection's session as set up. None/empty where the type lacks it."""

    # IPsec: the IKE SA's, e.g. ESTABLISHED or CONNECTING; SSH: the same two.
    state: str | None = None
    # Changes when the session is set up again: IKE SA id, ssh's process id.
    session_id: int | None = None
    # Address:port.
    local: str | None = None
    remote: str | None = None
    # IKE ids; WireGuard public keys; SSH username and the server's host key.
    local_identity: str | None = None
    remote_identity: str | None = None
    # IPsec: the ids' type, e.g. IPV4_ADDR or FQDN; None if unknown.
    local_identity_type: str | None = None
    remote_identity_type: str | None = None
    # As negotiated; WireGuard: fixed by the protocol.
    encryption: str | None = None
    # None with an AEAD cipher.
    integrity: str | None = None
    prf: str | None = None
    # The classical one, then the additional (ML-KEM) ones. SSH: one, hybrid or not.
    key_exchange: list[str] = []
    # IPsec: a post-quantum preshared key was used.
    ppk: bool | None = None
    # IPsec: who is behind NAT: NONE, LOCAL, REMOTE or BOTH.
    nat: str | None = None
    established: str | None = None
    rekey: str | None = None
    # WireGuard.
    last_handshake: str | None = None
    allowed_ips: list[str] = []
    # IPsec: the child SAs.
    sas: list[SecurityAssociation] = []


class ConnectionState(BaseModel):
    """The live state of a connection."""

    id: str
    tenant: str
    network_instance: str
    type: enums.ConnectionType
    # DOWN: disabled in the configuration.
    admin_status: AdminStatus
    oper_status: OperStatus
    # When oper_status last changed, or vpnc first saw the connection.
    last_change: str
    # How often oper_status changed since vpnc started.
    interface_transitions: int
    interface: str | None
    mtu: int | None
    addresses: list[str]
    remote: str | None
    # VPN connections; None while there's no session.
    tunnel: Tunnel | None
    # VPN connections: resets by vpnc (stuck or probes failing).
    auto_resets_24h: int | None
    # Tested every full check while the connection is up.
    probes: list[ProbeState]
    # None without interface.
    counters: Counters | None
    # None until measured.
    rates: Rates | None


class Translation(BaseModel):
    """A NAT64 or NPTv6 translation: local (CORE side) to remote prefix."""

    type: Literal["NAT64", "NPTV6"]
    local: str
    remote: str


class NetworkInstanceState(BaseModel):
    """The live state of a network instance."""

    id: str
    tenant: str
    type: enums.NetworkInstanceType
    connections_up: int
    connections: int
    nat64_scope: str | None = None
    nptv6_scope: str | None = None
    # The rest only for one network instance.
    translations: list[Translation] | None = None
    # By type: NAT64, NPTV6, ROUTED.
    sessions: dict[str, int] | None = None
    # Packets the firewall dropped or rejected since it was last replaced.
    firewall_dropped: int | None = None
    # DNS answers vpncmangle translated and dropped (hub downlinks), since it started.
    dns_answers_translated: int | None = None
    dns_answers_dropped: int | None = None
    # By reason: as the service's, without the ones of no network instance.
    dns_drop_reasons: dict[str, int] | None = None


class TenantState(BaseModel):
    """The live state of a tenant."""

    id: str
    name: str
    network_instances: list[str]
    connections_up: int
    connections: int


class VpncmangleState(BaseModel):
    """vpncmangle, which rewrites DNS answers (hub mode)."""

    running: bool
    # DNS64 and DNS66 translations over all network instances.
    translations: int
    # DNS answers since vpncmangle started; None if it hasn't counted (yet).
    answers_translated: int | None
    answers_dropped: int | None
    # By reason: NOT_DNS, NO_TRANSLATIONS, UNKNOWN_SOURCE, ERROR; over the dns
    # limits OVERSIZED, TOO_MANY_RECORDS, RATE_LIMITED; QUEUE_FULL (the kernel's).
    drop_reasons: dict[str, int]


class Status(BaseModel):
    """An overview of the service."""

    mode: enums.ServiceMode
    tenants: int
    network_instances: int
    connections_up: int
    connections: int
    vpncmangle: VpncmangleState | None
    # Service settings that only apply after vpnc restarts.
    restart_needed: list[str]


class BgpPrefixes(BaseModel):
    """A BGP session's prefixes in an address family, after policy."""

    received: int | None
    sent: int | None


class BgpAfiSafi(BaseModel):
    """An address family of a BGP session."""

    # E.g. IPV6_UNICAST.
    afi_safi_name: str
    prefixes: BgpPrefixes


class BgpNeighbor(BaseModel):
    """A BGP session in CORE, named as in OpenConfig."""

    neighbor_address: str
    hostname: str | None
    peer_as: int | None
    # IDLE, CONNECT, ACTIVE, OPENSENT, OPENCONFIRM or ESTABLISHED.
    session_state: str | None
    # When the session last became established, or stopped being so.
    last_established: str | None
    afi_safis: list[BgpAfiSafi]


class Ids(BaseModel):
    """The ids of what's configured, e.g. to complete commands."""

    tenants: list[str]
    network_instances: list[str]
    connections: list[str]
    # Tenants with an active or staged configuration.
    config_tenants: list[str]


def ids() -> Ids:
    """Return the ids of the tenants, network instances and connections."""
    configured = helpers.network_instances()
    return Ids(
        tenants=sorted(config.VPNC_CONFIG_TENANT),
        network_instances=sorted(configured),
        connections=sorted(
            connection.name(ni)
            for ni in configured.values()
            for connection in ni.connections.values()
        ),
        config_tenants=config_files.tenant_ids(),
    )


def _ipsec_sas(
    listing: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Return the IKE SAs by connection name; listed, unless a listing is given."""
    if listing is None:
        try:
            with charon.session() as vcs:
                listing = list(vcs.list_sas())
        except OSError:
            logger.warning("Reading the IPsec SAs failed.", exc_info=True)
            return {}
    sas: dict[str, dict[str, Any]] = {}
    for item in listing:
        for name, sa in item.items():
            # A connection can have several (rekeying, duplicates): the one
            # that's up counts.
            if name not in sas or (charon.sa_up(sa) and not charon.sa_up(sas[name])):
                sas[name] = sa
    return sas


def _timestamp(seconds: float | None = None) -> str:
    """Return a time (Unix; default now) as in the rest of the API: ISO 8601."""
    time_ = dt.datetime.fromtimestamp(seconds or time.time()).astimezone()
    return time_.isoformat(timespec="seconds")


@dataclasses.dataclass
class _Seen:
    """A connection's oper_status as last seen."""

    status: OperStatus
    enabled: bool
    last_change: str
    # When (Unix time) it became UP, or stopped being UP.
    since: float
    transitions: int = 0


# By connection; updated whenever the states are read (every full check at least).
_SEEN: dict[str, _Seen] = {}
_SEEN_LOCK = threading.Lock()


def _track(name: str, current: OperStatus, *, enabled: bool) -> tuple[str, int]:
    """Return when a connection's oper_status last changed, and how often.

    Records the changes as events.
    """
    now = time.time()
    with _SEEN_LOCK:
        if (seen := _SEEN.get(name)) is None:
            seen = _SEEN[name] = _Seen(current, enabled, _timestamp(now), now)
        if seen.enabled != enabled:
            seen.enabled = enabled
            eventlog.record(
                "ADMIN_UP" if enabled else "ADMIN_DOWN",
                f"admin status {'UP: enabled' if enabled else 'DOWN: disabled'}",
                connection=name,
            )
        if seen.status != current:
            if "UP" in (seen.status, current):
                # DOWN and DORMANT alternate while a connection is being set up.
                new, old = ("UP", "DOWN") if current == "UP" else ("DOWN", "UP")
                lasted = eventlog.duration(now - seen.since)
                eventlog.record(
                    f"OPER_{new}",
                    f"oper status {new}, was {old} for {lasted}",
                    connection=name,
                )
                seen.since = now
            seen.status, seen.last_change = current, _timestamp(now)
            seen.transitions += 1
        # After the change: why it went down is an event after that it did.
        failures.seen(name, up=current == "UP")
        return seen.last_change, seen.transitions


def down_since(name: str) -> float | None:
    """Return since when (Unix time) a connection isn't UP; None if it is."""
    with _SEEN_LOCK:
        seen = _SEEN.get(name)
        return seen.since if seen and seen.status != "UP" else None


def _endpoint(address: Any, port: Any) -> str | None:  # noqa: ANN401
    """Return address:port, with an IPv6 address in brackets."""
    if address is None:
        return None
    if port is None:
        return str(address)
    return helpers.endpoint(address, port)


def _in(seconds: Any) -> str | None:  # noqa: ANN401
    """Return the time in seconds (as vici gives it, a string) from now."""
    return _timestamp(time.time() + int(seconds)) if seconds is not None else None


def _algorithm(sa: dict[str, Any], kind: str) -> str | None:
    """Return an algorithm with its key size, e.g. AES_GCM_16_256."""
    if (name := sa.get(f"{kind}-alg")) is None:
        return None
    keysize = sa.get(f"{kind}-keysize")
    return f"{name}_{keysize}" if keysize else name


def _key_exchanges(sa: dict[str, Any]) -> list[str]:
    """Return the classical key exchange, then the additional ones (ake1-7)."""
    keys = ["dh-group", *(f"ake{n}" for n in range(1, 8))]
    return [sa[key] for key in keys if sa.get(key)]


def _nat(sa: dict[str, Any]) -> str:
    local, remote = sa.get("nat-local") == "yes", sa.get("nat-remote") == "yes"
    return {
        (False, False): "NONE",
        (True, False): "LOCAL",
        (False, True): "REMOTE",
        (True, True): "BOTH",
    }[local, remote]


def _child_sa(child: dict[str, Any]) -> SecurityAssociation:
    def count(key: str) -> int | None:
        return int(child[key]) if key in child else None

    installed = child.get("install-time")
    return SecurityAssociation(
        name=child.get("name", ""),
        id=int(child["uniqueid"]) if "uniqueid" in child else None,
        state=child.get("state"),
        encryption=_algorithm(child, "encr"),
        integrity=_algorithm(child, "integ"),
        key_exchange=_key_exchanges(child),
        spi_in=child.get("spi-in"),
        spi_out=child.get("spi-out"),
        local_ts=child.get("local-ts", []),
        remote_ts=child.get("remote-ts", []),
        in_octets=count("bytes-in"),
        in_pkts=count("packets-in"),
        out_octets=count("bytes-out"),
        out_pkts=count("packets-out"),
        installed=_in(-int(installed)) if installed is not None else None,
        rekey=_in(child.get("rekey-time")),
        expires=_in(child.get("life-time")),
    )


def _ipsec(
    ni: NetworkInstance,
    connection: Connection,
    sas: dict[str, dict[str, Any]],
) -> tuple[OperStatus, str | None, Tunnel | None]:
    sa = sas.get(connection.name(ni))
    if sa is None:
        return "DOWN", str(connection.config.remote_addrs[0]), None
    sa = charon.decode(sa)
    established = sa.get("established")
    local_id, remote_id = strongswan.ids(connection.config)
    # With %any charon sends its address.
    local_type = (
        identity.parse(local_id)[0] or identity.parse(sa.get("local-id", ""))[0]
    )
    tunnel = Tunnel(
        state=sa.get("state"),
        session_id=int(sa.get("uniqueid", 0)) or None,
        local=_endpoint(sa.get("local-host"), sa.get("local-port")),
        remote=_endpoint(sa.get("remote-host"), sa.get("remote-port")),
        local_identity=sa.get("local-id"),
        remote_identity=sa.get("remote-id"),
        local_identity_type=local_type,
        remote_identity_type=identity.parse(remote_id)[0],
        encryption=_algorithm(sa, "encr"),
        integrity=_algorithm(sa, "integ"),
        prf=sa.get("prf-alg"),
        key_exchange=_key_exchanges(sa),
        ppk=sa.get("ppk") == "yes",
        nat=_nat(sa),
        established=_in(-int(established)) if established is not None else None,
        rekey=_in(sa.get("rekey-time") or sa.get("reauth-time")),
        sas=[_child_sa(child) for child in sa.get("child-sas", {}).values()],
    )
    current: OperStatus = "UP" if charon.sa_up(sa) else "DORMANT"
    return current, sa.get("remote-host"), tunnel


# Fixed by the protocol, named as strongSwan names them.
WIREGUARD_ENCRYPTION = "CHACHA20_POLY1305"
WIREGUARD_KEY_EXCHANGE = "CURVE_25519"


def _wireguard(
    ni: NetworkInstance,
    ifname: str,
) -> tuple[OperStatus, str | None, Tunnel | None]:
    try:
        peer = wireguard.peer_status(ni.id, ifname)
    except Exception:  # noqa: BLE001
        return "DOWN", None, None
    handshake = peer["last_handshake"]
    tunnel = Tunnel(
        local=f"*:{peer['listen_port']}" if peer["listen_port"] else None,
        remote=_endpoint(peer["endpoint"], peer["endpoint_port"]),
        local_identity=peer["public_key"],
        remote_identity=peer["peer_public_key"],
        encryption=WIREGUARD_ENCRYPTION,
        key_exchange=[WIREGUARD_KEY_EXCHANGE],
        last_handshake=_timestamp(handshake) if handshake else None,
        allowed_ips=peer["allowed_ips"],
    )
    recent = handshake and time.time() - handshake < WIREGUARD_TIMEOUT
    return ("UP" if recent else "DOWN"), peer["endpoint"], tunnel


SSH_PORT = 22


def _ssh(name: str, connection: Connection) -> Tunnel | None:
    session = ssh.session(name)
    if session is None:
        return None
    cfg = connection.config
    return Tunnel(
        state="ESTABLISHED" if session.authenticated else "CONNECTING",
        session_id=session.pid,
        remote=_endpoint(cfg.remote_addrs[0], SSH_PORT),
        local_identity=cfg.username,
        remote_identity=ssh.host_key(name),
        encryption=session.cipher,
        integrity=session.mac,
        key_exchange=[session.key_exchange] if session.key_exchange else [],
        established=(
            _timestamp(session.authenticated) if session.authenticated else None
        ),
    )


def probe_details(ni: NetworkInstance, connection: Connection) -> list[ProbeDetail]:
    """Return a connection's probes with their last tests."""
    name = connection.name(ni)
    current = probes.tested(name)
    return [
        ProbeDetail(
            description=probe.description,
            address=str(probe.address),
            test_type=probe.test_type,
            port=probe.port,
            failed=tests[-1].failed if current and tests else None,
            last_test_timestamp=_timestamp(tests[-1].timestamp) if tests else None,
            history=[
                ProbeTest(
                    timestamp=_timestamp(test.timestamp),
                    failed=test.failed,
                    avg_delay=(
                        round(test.delay * 1_000_000)
                        if test.delay is not None
                        else None
                    ),
                )
                for test in tests
            ],
        )
        for probe, tests in probes.results(name, connection)
    ]


def _snapshot(ni_id: str) -> state.NetnsState:
    """Read the links and addresses of a network instance (not its routes)."""
    try:
        return state.NetnsState.read(ni_id, routes=False)
    except FileNotFoundError:
        return state.NetnsState(name=ni_id)


def connection_states(
    selected: list[NetworkInstance] | None = None,
    *,
    interfaces: bool = True,
    sas_listing: list[dict[str, Any]] | None = None,
) -> list[ConnectionState]:
    """Return the live state of the connections of the network instances.

    Without interfaces, network instances with only IPsec connections aren't read:
    their state comes from the SAs. Enough to count connections that are up. The
    SAs are listed, unless a listing (as vici returns it) is given.
    """
    everything = selected is None
    if selected is None:
        selected = list(helpers.network_instances().values())
    sas = (
        _ipsec_sas(sas_listing)
        if any(
            c.config.type == enums.ConnectionType.IPSEC
            for ni in selected
            for c in ni.connections.values()
        )
        else {}
    )
    output: list[ConnectionState] = []
    for ni in selected:
        if interfaces or any(
            c.config.type != enums.ConnectionType.IPSEC for c in ni.connections.values()
        ):
            snapshot = _snapshot(ni.id)
        else:
            snapshot = state.NetnsState(name=ni.id)
        for connection in ni.connections.values():
            name = connection.name(ni)
            ifname = connection.intf_name(ni)
            link = snapshot.links.get(ifname) if ifname else None
            addresses = sorted(
                str(a) for a in snapshot.addresses.get(ifname or "", set())
            )
            remote_addrs = getattr(connection.config, "remote_addrs", None)
            remote = str(remote_addrs[0]) if remote_addrs else None
            tunnel: Tunnel | None = None
            ctype = connection.config.type
            current: OperStatus
            if ctype == enums.ConnectionType.IPSEC:
                current, remote, tunnel = _ipsec(ni, connection, sas)
            elif ctype == enums.ConnectionType.WIREGUARD and link is not None:
                current, endpoint, tunnel = _wireguard(ni, ifname)
                remote = endpoint or remote
            else:
                # SSH (tun has carrier while ssh runs) and physical interfaces.
                current = "UP" if link is not None and link.passes_traffic else "DOWN"
                if ctype == enums.ConnectionType.SSH:
                    tunnel = _ssh(name, connection)
            last_change, transitions = _track(
                name,
                current,
                enabled=connection.enabled,
            )
            counters = snapshot.counters.get(ifname or "")
            rates = traffic.rates(ni.id, ifname) if counters else None
            output.append(
                ConnectionState(
                    id=name,
                    tenant=ni.tenant_id,
                    network_instance=ni.id,
                    type=ctype,
                    admin_status="UP" if connection.enabled else "DOWN",
                    oper_status=current,
                    last_change=last_change,
                    interface_transitions=transitions,
                    interface=ifname if link is not None else None,
                    mtu=link.mtu if link is not None else None,
                    addresses=addresses,
                    remote=remote,
                    tunnel=tunnel,
                    auto_resets_24h=(
                        helpers.auto_resets(name)
                        if ctype != enums.ConnectionType.PHYSICAL
                        else None
                    ),
                    probes=[
                        ProbeState(**detail.model_dump(exclude={"history"}))
                        for detail in probe_details(ni, connection)
                    ],
                    counters=(
                        Counters(**dataclasses.asdict(counters)) if counters else None
                    ),
                    rates=Rates(**dataclasses.asdict(rates)) if rates else None,
                ),
            )
    if everything:
        # Connections that aren't configured anymore.
        with _SEEN_LOCK:
            for name in set(_SEEN) - {s.id for s in output}:
                del _SEEN[name]
    return output


def _counts(states: list[ConnectionState]) -> tuple[int, int]:
    return sum(s.oper_status == "UP" for s in states), len(states)


def network_instance_states(
    selected: list[NetworkInstance],
    *,
    detail: bool = False,
) -> list[NetworkInstanceState]:
    """Return the live state of network instances."""
    by_ni: dict[str, list[ConnectionState]] = {}
    for s in connection_states(selected, interfaces=False):
        by_ni.setdefault(s.network_instance, []).append(s)
    hub = helpers.is_hub()
    output: list[NetworkInstanceState] = []
    for ni in selected:
        up, total = _counts(by_ni.get(ni.id, []))
        item = NetworkInstanceState(
            id=ni.id,
            tenant=ni.tenant_id,
            type=ni.type,
            connections_up=up,
            connections=total,
        )
        if hub and ni.type == enums.NetworkInstanceType.DOWNLINK:
            nat64 = ni.nat64_scope()
            nptv6 = ni.nptv6_scope()
            item.nat64_scope = str(nat64) if nat64 else None
            item.nptv6_scope = str(nptv6) if nptv6 else None
            if detail:
                item.translations = _translations(ni.id)
                counts = vpncmangle.stats().get("network_instances", {}).get(ni.id, {})
                item.dns_answers_translated = counts.get("translated", 0)
                item.dns_answers_dropped = counts.get("dropped", 0)
                item.dns_drop_reasons = counts.get("reasons", {})
        if detail:
            _add_datapath(item, ni)
        output.append(item)
    return output


def _add_datapath(item: NetworkInstanceState, ni: NetworkInstance) -> None:
    """Add the session counts and the firewall's drops, if they can be read."""
    try:
        found = diagnostics.session_list(ni)
    except (OSError, NetlinkError):
        logger.warning("Reading the sessions of %s failed.", ni.id, exc_info=True)
    else:
        item.sessions = dict(collections.Counter(s.type for s in found))
    try:
        item.firewall_dropped = diagnostics.dropped(diagnostics.firewall(ni.id))
    except (OSError, nftables.NftablesError):
        logger.warning("Reading the firewall of %s failed.", ni.id, exc_info=True)


def _translations(ni_id: str) -> list[Translation]:
    """Return the NAT64 and NPTv6 translations as applied (Jool and nftables)."""
    output: list[Translation] = []
    if nat64 := configuration.nat64_mapping(ni_id):
        output.append(
            Translation(type="NAT64", local=str(nat64[0]), remote=str(nat64[1])),
        )
    output.extend(
        Translation(type="NPTV6", local=str(local), remote=str(remote))
        for local, remote in configuration.nptv6_mappings(
            ni_id,
        )
    )
    return output


def tenant_states(selected: list[str] | None = None) -> list[TenantState]:
    """Return the live state of tenants."""
    tenants = {
        t.id: t
        for t in list(config.VPNC_CONFIG_TENANT.values())
        if selected is None or t.id in selected
    }
    nis = [ni for t in tenants.values() for ni in t.network_instances.values()]
    by_tenant: dict[str, list[ConnectionState]] = {}
    for s in connection_states(nis, interfaces=False):
        by_tenant.setdefault(s.tenant, []).append(s)
    output: list[TenantState] = []
    for tenant_id, tenant_config in sorted(tenants.items()):
        up, total = _counts(by_tenant.get(tenant_id, []))
        output.append(
            TenantState(
                id=tenant_id,
                name=tenant_config.name,
                network_instances=sorted(
                    ni.id for ni in tenant_config.network_instances.values()
                ),
                connections_up=up,
                connections=total,
            ),
        )
    return output


def status() -> Status:
    """Return an overview of the service."""
    states = connection_states(interfaces=False)
    up, total = _counts(states)
    return Status(
        mode=helpers.get_default_tenant().mode,
        tenants=len(config.VPNC_CONFIG_TENANT),
        network_instances=len(helpers.network_instances()),
        connections_up=up,
        connections=total,
        vpncmangle=_vpncmangle(),
        restart_needed=config_files.restart_needed(),
    )


def _vpncmangle() -> VpncmangleState | None:
    if not helpers.is_hub():
        return None
    process = vpncmangle.PROCESS
    try:
        translations = json.loads(vpncmangle.CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        translations = {}
    counters = vpncmangle.stats()
    reasons = counters.get("dropped", {})
    return VpncmangleState(
        running=process is not None and process.poll() is None,
        translations=sum(
            len(ni.get("dns64", [])) + len(ni.get("dns66", []))
            for ni in translations.values()
        ),
        answers_translated=counters.get("translated"),
        answers_dropped=sum(reasons.values()) if counters else None,
        drop_reasons=reasons,
    )


class BgpNeighborDetail(BgpNeighbor):
    """A BGP session in CORE, in detail."""

    local_as: int | None
    # How often the session became established.
    established_transitions: int | None
    connections_dropped: int | None
    last_reset: str | None
    # Seconds, as negotiated.
    hold_time: int | None
    keepalive_interval: int | None
    bfd: str | None


class BgpRoute(BaseModel):
    """A BGP path to a prefix."""

    prefix: str
    next_hops: list[str]
    as_path: str
    best: bool
    valid: bool
    local_pref: int | None
    metric: int | None
    # The neighbor (hostname if known) it was learned from; None: local.
    learned_from: str | None


def vtysh(command: str) -> Any:  # noqa: ANN401
    """Run a vtysh show command with JSON output and return the decoded output."""
    try:
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/vtysh", "-c", f"{command} json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return json.loads(result.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as err:
        detail = "FRR doesn't answer."
        raise config_files.ConfigError(503, "Service unavailable", detail) from err


def _session_state(state: str | None) -> str | None:
    """Return FRR's session state as in OpenConfig, e.g. Idle (Admin) as IDLE."""
    return state.split()[0].upper() if state else None


def _afi_safi(family: str, received: int | None, sent: int | None) -> BgpAfiSafi:
    """Return an address family with FRR's name as in OpenConfig: IPV6_UNICAST."""
    return BgpAfiSafi(
        afi_safi_name=re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", family).upper(),
        prefixes=BgpPrefixes(received=received, sent=sent),
    )


def bgp_neighbors() -> list[BgpNeighbor]:
    """Return the BGP sessions in CORE (hub mode)."""
    output: dict[str, BgpNeighbor] = {}
    for family, summary in vtysh(f"show bgp vrf {config.CORE_NI} summary").items():
        for peer, info in summary.get("peers", {}).items():
            neighbor = output.setdefault(
                peer,
                BgpNeighbor(
                    neighbor_address=peer,
                    hostname=info.get("hostname"),
                    peer_as=info.get("remoteAs"),
                    session_state=_session_state(info.get("state")),
                    last_established=(
                        _timestamp(epoch)
                        if (epoch := info.get("peerUptimeEstablishedEpoch"))
                        else None
                    ),
                    afi_safis=[],
                ),
            )
            neighbor.afi_safis.append(
                _afi_safi(family, info.get("pfxRcd"), info.get("pfxSnt")),
            )
    return list(output.values())


def bgp_neighbor(neighbor: IPAddress) -> BgpNeighborDetail | None:
    """Return a BGP session in CORE in detail; None if it doesn't exist."""
    data = vtysh(f"show bgp vrf {config.CORE_NI} neighbors {neighbor}")
    if not (info := data.get(str(neighbor))):
        return None
    hold = info.get("bgpTimerHoldTimeMsecs")
    keepalive = info.get("bgpTimerKeepAliveIntervalMsecs")
    bfd = (info.get("peerBfdInfo") or {}).get("status")
    return BgpNeighborDetail(
        neighbor_address=str(neighbor),
        hostname=info.get("hostname"),
        peer_as=info.get("remoteAs"),
        local_as=info.get("localAs"),
        session_state=_session_state(info.get("bgpState")),
        last_established=(
            _timestamp(epoch)
            if (epoch := info.get("bgpTimerUpEstablishedEpoch"))
            else None
        ),
        afi_safis=[
            _afi_safi(
                family,
                af.get("acceptedPrefixCounter"),
                af.get("sentPrefixCounter"),
            )
            for family, af in (info.get("addressFamilyInfo") or {}).items()
        ],
        established_transitions=info.get("connectionsEstablished"),
        connections_dropped=info.get("connectionsDropped"),
        last_reset=info.get("lastResetDueTo"),
        hold_time=hold // 1000 if hold is not None else None,
        keepalive_interval=keepalive // 1000 if keepalive is not None else None,
        bfd=bfd.upper() if bfd else None,
    )


FAMILIES = ("ipv4 unicast", "ipv6 unicast")


def bgp_routes() -> list[BgpRoute]:
    """Return the BGP table of CORE: every path to every prefix."""
    output: list[BgpRoute] = []
    for family in FAMILIES:
        data = vtysh(f"show bgp vrf {config.CORE_NI} {family}")
        for prefix, paths in (data.get("routes") or {}).items():
            for path in paths:
                hops = path.get("nexthops") or []
                peer = path.get("peerId")
                from_peer = peer if peer and peer != "(unspec)" else None
                output.append(
                    BgpRoute(
                        prefix=prefix,
                        next_hops=[h["ip"] for h in hops if h.get("ip")],
                        as_path=path.get("path", ""),
                        best=bool(path.get("bestpath")),
                        valid=bool(path.get("valid")),
                        local_pref=path.get("locPrf"),
                        metric=path.get("metric"),
                        learned_from=(
                            hops[0].get("hostname", from_peer)
                            if from_peer and hops
                            else from_peer
                        ),
                    ),
                )
    return output


def bgp_neighbor_routes(
    neighbor: IPAddress,
    direction: Literal["received", "advertised"],
) -> list[BgpRoute]:
    """Return the routes received from (before policy) or advertised to a neighbor."""
    output: list[BgpRoute] = []
    key = f"{direction}Routes"
    for family in FAMILIES:
        data = vtysh(
            f"show bgp vrf {config.CORE_NI} {family} neighbors {neighbor} "
            f"{direction}-routes",
        )
        for prefix, route in (data.get(key) or {}).items():
            hop = route.get("nextHopGlobal") or route.get("nextHop")
            output.append(
                BgpRoute(
                    prefix=prefix,
                    next_hops=[hop] if hop else [],
                    as_path=route.get("path", ""),
                    best=bool(route.get("best")),
                    valid=bool(route.get("valid")),
                    local_pref=route.get("locPrf"),
                    metric=route.get("metric"),
                    learned_from=str(neighbor) if direction == "received" else None,
                ),
            )
    return output


class Version(BaseModel):
    """The versions of vpnc and the software it runs."""

    vpnc: str
    kernel: str
    strongswan: str | None
    frr: str | None


def version() -> Version:
    """Return the versions of vpnc, the kernel, strongSwan and FRR (hub mode)."""
    strongswan = None
    try:
        with charon.session() as vcs:
            strongswan = charon.decode(vcs.version()).get("version")
    except OSError:
        logger.warning("Reading the strongSwan version failed.", exc_info=True)
    frr = None
    if helpers.is_hub():
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            result = subprocess.run(
                ["/usr/bin/vtysh", "-c", "show version"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            if match := re.search(r"FRRouting (\S+)", result.stdout):
                frr = match[1]
    return Version(
        vpnc=vpnc.__version__,
        kernel=os.uname().release,
        strongswan=strongswan,
        frr=frr,
    )
