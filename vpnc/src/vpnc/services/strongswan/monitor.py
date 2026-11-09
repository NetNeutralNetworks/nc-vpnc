"""Manage the strongswan service."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from types import MappingProxyType
from typing import Any, Awaitable, Callable, TypeAlias

import pyroute2
import vici
import vici.exception

from vpnc import config, shared
from vpnc.models import info

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


class Monitor(threading.Thread):
    """Monitor the strongswan service and components.

    This is blocking and as such, runs in separate threads.
    """

    def run(self) -> None:
        """Override and entrypoint of the threading.Thread class."""
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
        """Monitor for inactive connections.

        Monitor for inactive connection definitions where the connection is set to
        initiate/start.
        This doesn't check for IKE SAs without IPsec SAs.
        Also checks for SAs that aren't configured and removes these
        """
        vcs = self.connect()
        conns: list[str] = [x.decode() for x in vcs.get_conns()["conns"]]
        sas: list[str] = [next(iter(i.keys())) for i in vcs.list_sas()]
        logger.debug("Configured connections: %s", conns)
        logger.debug("Active connections: %s", sas)

        # TODO@draggeta: Implement IKE SA without IPsec SAs check?

        # For each configured connection, check if there is a SA. If not, start
        # the connection.
        for con in conns:
            if con in sas:
                continue
            logger.info("Initiating connection '%s'", con)
            self.initiate_sa(vcs=vcs, ike=con, child=con)

        # For each SA, check if there is a configured connection. If not, delete
        # the connection.
        for sa in sas:
            if sa in conns:
                continue
            logger.info("Terminating connection '%s'", sa)
            self.terminate_sa(vcs=vcs, ike=sa)

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
        vcs = self.connect()
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
            match event_type:
                # check for duplicate IKE associations
                case b"ike-updown":
                    self.resolve_duplicate_ike_sa(event_data)
                # check for duplicate IPSec associations
                case b"child-updown":
                    self.resolve_duplicate_ipsec_sa(event_data)

    def monitor_xfrm_interface_state(self) -> None:
        """Monitor VPN tunnel state and set interface state accordingly.

        Acts on IKE/child up/down events, and every XFRM_RESYNC_INTERVAL seconds
        checks all configured connections, so a missed event or a wrong interface
        state is corrected.
        """
        vcs = self.connect()

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

        with pyroute2.NetNS(network_instance_name) as netns:
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

    def resolve_duplicate_ike_sa(self, ike_event: IkeData) -> None:
        """Check for duplicate IPsec security associations.

        If SAs need be removed, the older ones are removed in favor of the youngest.
        """
        vcs: vici.Session = self.connect()
        if len(keys := ike_event.keys()) == 2:  # noqa: PLR2004
            ike_name = list(keys)[1]
        else:
            ike_name = next(iter(keys))

        logger.debug("IKE event received for SA '%s'", ike_name)

        ike_sas: list[IkeData] = list(vcs.list_sas({"ike": ike_name}))

        if len(ike_sas) <= 1:
            logger.debug(
                "Skipping IKE event for SA '%s'. Two or fewer SAs active.",
                ike_name,
            )
            return

        best_ike_sa_event: IkeData = {}

        for idx, ike_sa_event in enumerate(ike_sas):
            for ike_name, ike_sa in ike_sa_event.items():
                # First item has nothing to compare to.
                if idx == 0:
                    best_ike_sa_event = ike_sa_event
                    continue

                # Compare the seconds since the SA was established. Choose the most
                # recent one.
                try:
                    ike_sa_established = int(ike_sa["established"])
                    best_sa_established = int(
                        best_ike_sa_event[ike_name]["established"],
                    )
                except TypeError:
                    continue
                except KeyError:
                    continue

                if ike_sa_established <= best_sa_established:
                    self.terminate_sa(
                        vcs=vcs,
                        ike_id=best_ike_sa_event[ike_name]["uniqueid"],
                    )
                    best_ike_sa_event = ike_sa_event
                else:
                    self.terminate_sa(vcs=vcs, ike_id=ike_sa["uniqueid"])

    def resolve_duplicate_ipsec_sa(self, ike_event: IkeData) -> None:
        """Check for duplicate IPsec security associations.

        If SAs need be removed, the older ones are removed in favor of the youngest.
        """
        vcs = self.connect()
        if len(keys := ike_event.keys()) == 2:  # noqa: PLR2004
            _, ike_name = list(keys)
        else:
            ike_name = next(iter(keys))
        ike_sas: list[IkeData] = list(vcs.list_sas({"ike": ike_name}))

        for ike_sa in ike_sas:
            ike_sa_props = ike_sa[ike_name]

            # Get the most recent SA for each TS pair.
            ts_unique: dict[str, Any] = {}

            for ipsec_sa in ike_sa_props["child-sas"].values():
                # The check must be done per traffic selector pair.
                # If this is the first time seeing the traffic selector for the IKE SA,
                # don't do anything.
                ts_key = str((ipsec_sa["local-ts"], ipsec_sa["remote-ts"]))
                if ts_key not in ts_unique:
                    ts_unique[ts_key] = ipsec_sa
                    continue

                # Compare the seconds since the SA was established. Choose the most
                # recent one.
                try:
                    ipsec_sa_established = int(ipsec_sa["install-time"])
                    best_sa_established = int(ts_unique[ts_key]["install-time"])
                except TypeError:
                    continue
                except KeyError:
                    continue

                if ipsec_sa_established <= best_sa_established:
                    self.terminate_sa(vcs=vcs, child_id=ts_unique[ts_key]["uniqueid"])
                    ts_unique[ts_key] = ipsec_sa
                else:
                    self.terminate_sa(vcs=vcs, child_id=ipsec_sa["uniqueid"])

    def connect(self, tries: int = 10, delay: int = 2) -> vici.Session:
        """Try to connect to the VICI socket."""
        for i in range(tries):
            try:
                return vici.Session()
            except (ConnectionRefusedError, FileNotFoundError) as err:  # noqa: PERF203
                if i >= tries:
                    logger.warning(
                        "VICI socket not available after %s tries. Exiting.",
                        tries,
                    )
                    raise ConnectionError from err
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
