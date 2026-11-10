"""Manage the strongswan service."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
import subprocess
import threading
import time
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Awaitable, Callable, TypeAlias

import pyroute2
import vici
import vici.exception

from vpnc import config, shared
from vpnc.models import info

if TYPE_CHECKING:
    from pathlib import Path

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

VICI_SOCKET = "/var/run/charon.vici"
# Seconds before a VICI request fails, so a hanging charon can't block vpnc.
VICI_TIMEOUT = 10
SWANCTL_CONNECTION_RE = re.compile(r"^    (\S+) \{$")
POLICY_DIR_RE = re.compile(r"^\s+dir (\w+)")
POLICY_IF_ID_RE = re.compile(r"^\s+if_id (0x[0-9a-f]+)")

# An XFRM policy: (selector, direction, if_id).
XfrmPolicy: TypeAlias = tuple[str, str, int]


def swanctl_connection_names(path: Path) -> set[str]:
    """Return the connection names in a generated swanctl file."""
    names: set[str] = set()
    in_connections = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "connections {":
            in_connections = True
        elif line == "}":
            in_connections = False
        elif in_connections and (match := SWANCTL_CONNECTION_RE.match(line)):
            names.add(match.group(1))
    return names


def is_initiator(connection: dict[str, Any]) -> bool:
    """Return whether a list-conns entry is an initiator (close_action=start)."""
    return any(
        child.get("close_action") == b"start"
        for child in connection.get("children", {}).values()
    )


def xfrm_policies() -> set[XfrmPolicy]:
    """Return the XFRM policies with an if_id in the EXTERNAL network instance."""
    output = subprocess.run(  # noqa: S603
        [
            "/usr/sbin/ip",
            "netns",
            "exec",
            config.EXTERNAL_NI,
            "/usr/sbin/ip",
            "xfrm",
            "policy",
            "list",
            "nosock",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout
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
    subprocess.run(  # noqa: S603
        [
            "/usr/sbin/ip",
            "netns",
            "exec",
            config.EXTERNAL_NI,
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
        capture_output=True,
        check=False,
        timeout=10,
    )


class Monitor(threading.Thread):
    """Monitor the strongswan service and components.

    This is blocking and as such, runs in separate threads.
    """

    def run(self) -> None:
        """Override and entrypoint of the threading.Thread class."""
        # Policies without a child SA at the previous check.
        self.stale_policies: set[XfrmPolicy] = set()
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

        while not shared.STOP_EVENT.is_set():
            try:
                logger.info("Starting VPNC Strongswan monitors")
                asyncio.run(self.monitor())
            # TODO @draggeta: make sure this doesn't infinitely retry
            except Exception:  # noqa: BLE001, PERF203
                logger.warning("VPNC strongswan monitor crashed", exc_info=True)
                time.sleep(1)
        logger.info("Exiting VPNC Strongswan monitor")

    async def monitor(self) -> None:
        """Check for inactive and active connections every interval."""
        logger.info("Starting inactive/active connection monitor.")
        await self.repeat(30, self.monitor_connections, init_wait=False)

    async def repeat(
        self,
        interval: int,
        func: Callable[[], Awaitable[None]],
        *args: Any,  # noqa: ANN401
        init_wait: bool = False,
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        """Run func every interval seconds.

        If func has not finished before *interval*, will run again
        immediately when the previous iteration finished.

        *args and **kwargs are passed as the arguments to func.
        """
        if init_wait:
            await asyncio.sleep(interval)
        while not shared.STOP_EVENT.is_set():
            await asyncio.gather(
                func(*args, **kwargs),
                asyncio.sleep(interval),
            )

    async def monitor_connections(self) -> None:
        """Reload connections, initiate missing initiator SAs, remove unknown SAs."""
        vcs = self.connect()
        self.load_connections(vcs)

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
        self.stale_policies = stale - self.stale_policies

    def load_connections(self, vcs: vici.Session) -> None:
        """Reload the swanctl files if charon's connections differ from them."""
        expected: set[str] = set()
        for path in config.IPSEC_CONFIG_DIR.glob("*.conf"):
            expected |= swanctl_connection_names(path)
        loaded = {name.decode() for name in vcs.get_conns()["conns"]}
        if expected == loaded:
            return

        logger.warning(
            "Reloading swanctl config (missing: %s, unknown: %s).",
            sorted(expected - loaded),
            sorted(loaded - expected),
        )
        proc = subprocess.run(
            ["/usr/sbin/swanctl", "--load-all", "--clear"],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if proc.returncode:
            logger.error(
                "Loading the swanctl configuration failed: %s",
                proc.stderr.decode(errors="replace"),
            )

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
        """Set the XFRM interface state of all configured connections."""
        vcs = self.connect()
        for ike_name in vcs.get_conns()["conns"]:
            self.set_xfrm_interface_state(ike_name.decode(), missing_ok=True)

    def resolve_xfrm_interface_state(self, ike_event: IkeData) -> None:
        """Set the XFRM interface state for the connection of an IKE/child event."""
        ike_name: str
        if len(keys := ike_event.keys()) == 2:  # noqa: PLR2004
            _, ike_name = list(keys)
        else:
            ike_name = next(iter(keys))
        self.set_xfrm_interface_state(ike_name)

    def set_xfrm_interface_state(
        self,
        ike_name: str,
        *,
        missing_ok: bool = False,
    ) -> None:
        """Set a connection's XFRM interface up if its tunnel is up, down otherwise.

        The tunnel is up if any IKE SA of the connection is established and has an
        installed child SA. During rekeying, reauthentication or with duplicate SAs
        there are multiple SAs, some of which are being deleted, so all of them must
        be checked.

        The routes service reacts to the interface state, so a wrong state leaves
        routes blackholed or advertised.
        """
        if ike_name.startswith(config.CORE_NI):
            network_instance_name: str | None = config.CORE_NI
            connection_id: str | None = ike_name[-1]
        else:
            ni_info = info.parse_downlink_network_instance_name(ike_name)
            tenant_id = ni_info.tenant
            network_instance_name = ni_info.network_instance
            connection_id = ni_info.connection_id
            tenant_config_file = config.VPNC_A_CONFIG_DIR.joinpath(f"{tenant_id}.yaml")
            # When a connection configuration is deleted, the SA is deleted when the
            # monitor_connection function runs. Before this happens however, there is a
            # chance  it rekeys or switches state. To prevent errors, we check if the
            # file exists.
            if not tenant_config_file.exists():
                logger.info("No configuration file found for '%s'", tenant_id)
                return

        vcs = self.connect()
        tunnel_up = False
        for ike_sa in vcs.list_sas({"ike": ike_name}):
            ike_data: dict[str, Any] = ike_sa.get(ike_name, {})
            if ike_data.get("state", b"") != b"ESTABLISHED":
                continue
            if any(
                child.get("state", b"") == b"INSTALLED"
                for child in ike_data.get("child-sas", {}).values()
            ):
                tunnel_up = True
                break
        action = "up" if tunnel_up else "down"

        with pyroute2.IPRoute(netns=network_instance_name, flags=0) as netns:
            ifname = f"xfrm{connection_id}"
            if not (iflookup := netns.link_lookup(ifname=ifname)):
                log = logger.debug if missing_ok else logger.warning
                log(
                    "Network instance %s interface %s doesn't exist.",
                    network_instance_name,
                    ifname,
                )
                return
            ifidx = iflookup[0]
            is_up = bool(netns.get_links(ifidx)[0]["flags"] & IFF_UP)
            if is_up == tunnel_up:
                return

            logger.info(
                "Bringing network instance %s interface '%s' %s.",
                network_instance_name,
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
            logger.warning(("Initiation of SA '%s' failed.", _filter), exc_info=True)

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
                ("Termination of SA '%s' may have failed.", _filter),
                exc_info=True,
            )
        except vici.exception.CommandException:
            logger.warning(("Termination of SA '%s' failed.", _filter), exc_info=True)
