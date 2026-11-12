"""Manage the strongswan service."""

from __future__ import annotations

import contextlib
import logging
import re
import socket
import threading
import time
from collections.abc import Callable
from types import MappingProxyType
from typing import Any, TypeAlias

import vici
import vici.exception

from vpnc import config, shared
from vpnc.network import namespace
from vpnc.services.charon import VICI_SOCKET, VICI_TIMEOUT

logger = logging.getLogger("vpnc")


IkeProperties: TypeAlias = MappingProxyType[str, Any]
IkeData: TypeAlias = MappingProxyType[str, bytes | IkeProperties]
EventType: TypeAlias = bytes
Event: TypeAlias = tuple[EventType, IkeData]

# Interval in seconds at which all XFRM interface states are checked against the
# state of their tunnels, to correct missed events.
XFRM_RESYNC_INTERVAL = 30
# Interface flag (linux/if.h).
IFF_UP = 0x1

POLICY_DIR_RE = re.compile(r"^\s+dir (\w+)")
POLICY_IF_ID_RE = re.compile(r"^\s+if_id (0x[0-9a-f]+)")

# An XFRM policy: (selector, direction, if_id).
XfrmPolicy: TypeAlias = tuple[str, str, int]


def is_initiator(connection: dict[str, Any]) -> bool:
    """Return whether a list-conns entry is an initiator (close_action=start)."""
    return any(
        child.get("close_action") == b"start"
        for child in connection.get("children", {}).values()
    )


def tunnel_is_up(ike_sa: dict[str, Any]) -> bool:
    """Return whether an IKE SA is established and has an installed child SA.

    During rekeying, reauthentication or with duplicate SAs a connection has
    multiple SAs, some of which are being deleted: it's up if any of them is.
    """
    return ike_sa.get("state", b"") == b"ESTABLISHED" and any(
        child.get("state", b"") == b"INSTALLED"
        for child in ike_sa.get("child-sas", {}).values()
    )


def xfrm_policies() -> set[XfrmPolicy]:
    """Return the XFRM policies with an if_id in the EXTERNAL network instance."""
    result = namespace.run(
        config.EXTERNAL_NI,
        ["/usr/sbin/ip", "xfrm", "policy", "list", "nosock"],
        timeout=10,
    )
    if result.returncode:
        msg = f"Listing the XFRM policies failed: {result.stderr.strip()}"
        raise RuntimeError(msg)
    output = result.stdout
    policies: set[XfrmPolicy] = set()
    selector = direction = ""
    for line in output.splitlines():
        if not line[:1].isspace():
            selector, direction = line.strip(), ""
        elif match := POLICY_DIR_RE.match(line):
            direction = match.group(1)
        elif (match := POLICY_IF_ID_RE.match(line)) and selector and direction:
            policies.add((selector, direction, int(match.group(1), 16)))
    return policies


def delete_xfrm_policy(policy: XfrmPolicy) -> None:
    """Delete an XFRM policy in the EXTERNAL network instance."""
    selector, direction, if_id = policy
    namespace.run(
        config.EXTERNAL_NI,
        [
            "/usr/sbin/ip",
            "xfrm",
            "policy",
            "delete",
            "dir",
            direction,
            *selector.split(),
            "if_id",
            hex(if_id),
        ],
        timeout=10,
    )


class Monitor(threading.Thread):
    """Monitor the strongswan service and components.

    This is blocking and as such, runs in separate threads.
    """

    # Policies without a child SA at the previous check.
    stale_policies: frozenset[XfrmPolicy] = frozenset()

    def run(self) -> None:
        """Override and entrypoint of the threading.Thread class."""
        # Policies without a child SA at the previous check.
        # The event listeners restart themselves, so they're started only once.
        logger.info("Starting duplicate SA monitor.")
        threading.Thread(
            target=self.supervise,
            args=("Duplicate SA monitor", self.monitor_duplicate_sa_events),
            daemon=True,
        ).start()
        logger.info("Starting interface state monitor.")
        threading.Thread(
            target=self.supervise,
            args=("Interface state monitor", self.monitor_xfrm_interface_state),
            daemon=True,
        ).start()

    def reconcile_connections(self) -> None:
        """Sync connections, initiate missing initiator SAs, remove unknown SAs."""
        # Imported here: the package imports this module first.
        from vpnc.services.strongswan import strongswan  # noqa: PLC0415

        vcs = self.connect()
        strongswan.sync(vcs)

        conns: dict[str, dict[str, Any]] = {
            name: details for conn in vcs.list_conns() for name, details in conn.items()
        }
        sas: set[str] = {name for sa in vcs.list_sas() for name in sa}
        logger.debug("Configured connections: %s", list(conns))
        logger.debug("Active connections: %s", sas)

        # TODO@draggeta: Implement IKE SA without IPsec SAs check?

        for con, details in conns.items():
            if con in sas:
                continue
            if not is_initiator(details):
                logger.debug("Waiting for the peer of connection '%s'.", con)
                continue
            logger.info("Initiating connection '%s'", con)
            self.initiate_sa(vcs=vcs, ike=con, child=con)

        for sa in sas - conns.keys():
            logger.info("Terminating connection '%s'", sa)
            self.terminate_sa(vcs=vcs, ike=sa)

        self.remove_stale_policies(vcs)

    def remove_stale_policies(self, vcs: vici.Session) -> None:
        """Delete XFRM policies whose if_id has had no child SA for two checks.

        Policies don't expire, so they stay when charon dies and the SA doesn't
        come back. Waiting a check avoids racing an SA that is being set up.
        """
        active: set[int] = set()
        for sa in vcs.list_sas():
            for ike in sa.values():
                for child in ike.get("child-sas", {}).values():
                    for key in ("if-id-in", "if-id-out"):
                        with contextlib.suppress(KeyError, ValueError):
                            active.add(int(child[key], 16))

        stale = {p for p in xfrm_policies() if p[2] not in active}
        for policy in stale & self.stale_policies:
            logger.warning("Deleting stale XFRM policy %s.", policy)
            delete_xfrm_policy(policy)
        self.stale_policies = frozenset(stale - self.stale_policies)

    def supervise(self, name: str, func: Callable[[], None]) -> None:
        """Run func until stopped, restarting it if it fails or returns.

        The listeners depend on the VICI socket. When charon restarts or the socket
        breaks, they raise; without a restart their state would never update again.
        """
        while not shared.STOP_EVENT.is_set():
            try:
                func()
            except Exception:
                logger.warning("%s failed. Restarting.", name, exc_info=True)
            if not shared.STOP_EVENT.is_set():
                time.sleep(1)

    def monitor_duplicate_sa_events(self) -> None:
        """Monitor for SA events.

        check if there are duplicates and take action accordingly.
        """
        vcs = self.connect(timeout=None)
        for event in vcs.listen(
            event_types=["ike-updown", "child-updown"],
            timeout=0.1,
        ):
            if shared.STOP_EVENT.is_set():
                return
            if event == (None, None):
                continue
            event_type, event_data = event
            if event_type is None or event_data is None:
                continue
            keys = list(event_data.keys())
            ike_name = keys[1] if len(keys) == 2 else keys[0]  # noqa: PLR2004
            self.resolve_duplicate_sas(ike_name)

    def monitor_xfrm_interface_state(self) -> None:
        """Monitor VPN tunnel state and set interface state accordingly.

        Acts on IKE/child up/down events, and every XFRM_RESYNC_INTERVAL seconds
        checks all configured connections, so a missed event or a wrong interface
        state is corrected.
        """
        vcs = self.connect(timeout=None)

        # At startup check all interface states
        self.resync_xfrm_interface_states()
        last_resync = time.monotonic()

        # Then check the queue for new events
        for event in vcs.listen(
            event_types=["ike-updown", "child-updown"],
            timeout=1,
        ):
            if shared.STOP_EVENT.is_set():
                return
            if time.monotonic() - last_resync >= XFRM_RESYNC_INTERVAL:
                self.resync_xfrm_interface_states()
                last_resync = time.monotonic()
            if event == (None, None):
                continue
            event_type, event_data = event
            if event_type is None or event_data is None:
                continue
            self.resolve_xfrm_interface_state(event_data)

    def resync_xfrm_interface_states(self) -> None:
        """Set the XFRM interface state of all configured connections.

        With one list of all SAs and one socket per network instance.
        """
        vcs = self.connect()
        up = {
            name
            for sa in vcs.list_sas()
            for name, ike_data in sa.items()
            if tunnel_is_up(ike_data)
        }
        interfaces: dict[str, list[tuple[str, str]]] = {}
        for ike_name in vcs.get_conns()["conns"]:
            name = ike_name.decode()
            if (interface := self.xfrm_interface(name)) is not None:
                interfaces.setdefault(interface[0], []).append((name, interface[1]))
        for network_instance_name, connections in interfaces.items():
            try:
                with namespace.IPRoute(network_instance_name) as netns:
                    for name, ifname in connections:
                        self.set_link_state(
                            netns,
                            ifname,
                            up=name in up,
                            missing_ok=True,
                        )
            except OSError as err:
                # E.g. a network instance that is being removed.
                logger.debug(
                    "Setting the interface states in %s failed: %s",
                    network_instance_name,
                    err,
                )

    def resolve_xfrm_interface_state(self, ike_event: IkeData) -> None:
        """Set the XFRM interface state for the connection of an IKE/child event."""
        ike_name: str
        if len(keys := ike_event.keys()) == 2:  # noqa: PLR2004
            _, ike_name = list(keys)
        else:
            ike_name = next(iter(keys))
        self.set_xfrm_interface_state(ike_name)

    def xfrm_interface(self, ike_name: str) -> tuple[str, str] | None:
        """Return the network instance and XFRM interface of a connection.

        None if its tenant has no configuration (anymore).
        """
        if ike_name.startswith(config.CORE_NI):
            return config.CORE_NI, f"xfrm{ike_name[-1]}"
        if not (match := config.DOWNLINK_CON_RE.match(ike_name)):
            msg = f"Invalid connection name '{ike_name}'"
            raise ValueError(msg)
        network_instance, tenant_id, connection_id = match.groups()
        # A deleted connection's SA is terminated by the reconciler. Until then
        # it can still rekey or change state.
        if not config.VPNC_A_CONFIG_DIR.joinpath(f"{tenant_id}.yaml").exists():
            logger.info("No configuration file found for '%s'", tenant_id)
            return None
        return network_instance, f"xfrm{connection_id}"

    def set_xfrm_interface_state(self, ike_name: str) -> None:
        """Set a connection's XFRM interface up if its tunnel is up, down otherwise.

        The routes service reacts to the interface state, so a wrong state leaves
        routes blackholed or advertised.
        """
        if (interface := self.xfrm_interface(ike_name)) is None:
            return
        network_instance_name, ifname = interface

        vcs = self.connect()
        tunnel_up = any(
            tunnel_is_up(ike_sa.get(ike_name, {}))
            for ike_sa in vcs.list_sas({"ike": ike_name})
        )
        with namespace.IPRoute(network_instance_name) as netns:
            self.set_link_state(netns, ifname, up=tunnel_up)

    def set_link_state(
        self,
        netns: namespace.IPRoute,
        ifname: str,
        *,
        up: bool,
        missing_ok: bool = False,
    ) -> None:
        """Set an interface up or down, if it isn't."""
        if not (iflookup := netns.link_lookup(ifname=ifname)):
            log = logger.debug if missing_ok else logger.warning
            log(
                "Network instance %s interface %s doesn't exist.",
                netns.netns,
                ifname,
            )
            return
        ifidx = iflookup[0]
        if bool(netns.get_links(ifidx)[0]["flags"] & IFF_UP) == up:
            return

        action = "up" if up else "down"
        logger.info(
            "Bringing network instance %s interface '%s' %s.",
            netns.netns,
            ifname,
            action,
        )
        netns.link("set", index=ifidx, state=action)

    def resolve_duplicate_sas(self, ike_name: str) -> None:
        """Keep the newest IKE/CHILD SA of an initiator connection, terminate the rest.

        Only initiators resolve, so both peers don't delete different SAs.
        """
        vcs: vici.Session = self.connect()
        conns = [
            c[ike_name] for c in vcs.list_conns({"ike": ike_name}) if ike_name in c
        ]
        if not conns or not is_initiator(conns[0]):
            return

        ike_sas: list[dict[str, Any]] = [
            sa[ike_name] for sa in vcs.list_sas({"ike": ike_name}) if ike_name in sa
        ]
        established = [sa for sa in ike_sas if sa.get("state") == b"ESTABLISHED"]
        if len(established) > 1:
            keep = min(
                established,
                key=lambda sa: (int(sa.get("established", 0)), sa.get("initiator-spi")),
            )
            for sa in established:
                if sa is keep:
                    continue
                logger.info("Terminating duplicate IKE SA of '%s'.", ike_name)
                self.terminate_sa(vcs=vcs, ike_id=sa["uniqueid"])
            established = [keep]

        for ike_sa in established:
            self.resolve_duplicate_child_sas(vcs, ike_name, ike_sa)

    def resolve_duplicate_child_sas(
        self,
        vcs: vici.Session,
        ike_name: str,
        ike_sa: dict[str, Any],
    ) -> None:
        """Terminate all but the most recent CHILD SA per traffic selector pair."""
        per_ts: dict[str, list[dict[str, Any]]] = {}
        for child in ike_sa.get("child-sas", {}).values():
            if child.get("state") != b"INSTALLED":
                continue
            ts_key = str((child.get("local-ts"), child.get("remote-ts")))
            per_ts.setdefault(ts_key, []).append(child)
        for children in per_ts.values():
            if len(children) <= 1:
                continue
            keep = min(
                children,
                key=lambda c: (
                    int(c.get("install-time", 0)),
                    sorted((c.get("spi-in", b""), c.get("spi-out", b""))),
                ),
            )
            for child in children:
                if child is keep:
                    continue
                logger.info("Terminating duplicate CHILD SA of '%s'.", ike_name)
                self.terminate_sa(vcs=vcs, child_id=child["uniqueid"])

    def connect(
        self,
        tries: int = 10,
        delay: int = 2,
        timeout: float | None = VICI_TIMEOUT,
    ) -> vici.Session:
        """Connect to the VICI socket. Use timeout=None for event listeners."""
        for i in range(tries):
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(timeout)
            try:
                sock.connect(VICI_SOCKET)
                return vici.Session(sock)
            except (ConnectionRefusedError, FileNotFoundError, TimeoutError) as err:  # noqa: PERF203
                sock.close()
                if i >= tries - 1:
                    msg = f"VICI socket not available after {tries} tries."
                    raise ConnectionError(msg) from err
                logger.info("VICI socket is not yet available. Retrying.")
                time.sleep(delay)

        raise ConnectionAbortedError

    def initiate_sa(
        self,
        vcs: vici.Session,
        ike: str | bytes | None = None,
        child: str | bytes | None = None,
    ) -> None:
        """Initiate IKE/IPsec security associations."""
        _filter: dict[str, bytes] = {}
        if isinstance(ike, str):
            ike = ike.encode("utf-8")
        if ike is not None:
            _filter.update({"ike": ike})
        if isinstance(child, str):
            child = child.encode("utf-8")
        if child is not None:
            _filter.update({"child": child})

        logger.info("Initiating SA with parameters: '%s'", _filter)
        # Don't wait: an unreachable peer would block forever.
        _filter["timeout"] = b"-1"
        try:
            for i in vcs.initiate(_filter):
                logger.debug(i)
        except vici.exception.CommandException:
            logger.warning("Initiation of SA '%s' failed.", _filter, exc_info=True)

    def terminate_sa(
        self,
        vcs: vici.Session,
        ike: str | bytes | None = None,
        ike_id: str | bytes | None = None,
        child: str | bytes | None = None,
        child_id: str | bytes | None = None,
    ) -> None:
        """Terminates IKE/IPsec security associations."""
        _filter: dict[str, bytes] = {}
        if isinstance(ike, str):
            ike = ike.encode("utf-8")
        if ike is not None:
            _filter.update({"ike": ike})
        if isinstance(ike_id, str):
            ike_id = ike_id.encode("utf-8")
        if ike_id is not None:
            _filter.update({"ike-id": ike_id})
        if isinstance(child, str):
            child = child.encode("utf-8")
        if child is not None:
            _filter.update({"child": child})
        if isinstance(child_id, str):
            child_id = child_id.encode("utf-8")
        if child_id is not None:
            _filter.update({"child-id": child_id})

        logger.info("Terminating SA with parameters: '%s'", _filter)
        # Don't wait for an unreachable peer to confirm.
        _filter["timeout"] = b"-1"
        try:
            for i in vcs.terminate(_filter):
                logger.debug(i)

        except vici.exception.SessionException:
            logger.warning(
                "Termination of SA '%s' may have failed.",
                _filter,
                exc_info=True,
            )
        except vici.exception.CommandException:
            logger.warning("Termination of SA '%s' failed.", _filter, exc_info=True)
