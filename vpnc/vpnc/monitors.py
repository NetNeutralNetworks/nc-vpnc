"""
Monitors the VPN security associations for unwanted duplicates. These can be caused by
simultaneous connections from both parties or intermittent internet connectivity issues.
"""

import asyncio

# import concurrent.futures
import logging
import queue
import subprocess
import threading
import time
from ipaddress import IPv6Address, IPv6Network
from types import MappingProxyType
from typing import Any, TypeAlias

import vici
import vici.exception

from . import config

IkeProperties: TypeAlias = MappingProxyType[str, Any]
IkeData: TypeAlias = MappingProxyType[str, bytes | IkeProperties]
EventType: TypeAlias = bytes
Event: TypeAlias = tuple[EventType, IkeData]


logger = logging.getLogger("vpnc-monitor")


class VpncMonitor(threading.Thread):
    """
    Monitors the VPNC service and components. This is blocking and as such in a separate threads.
    """

    def run(self):
        while True:
            try:
                logger.info("Starting VPNC Monitors")
                asyncio.run(self.monitor())
            except Exception:
                logger.warning("VPNC Monitors crashed", exc_info=True)
                time.sleep(1)

    async def monitor(self):
        """
        Test function
        """

        # Wait for startup before starting to manage VPNs
        await asyncio.sleep(30)

        loop = asyncio.get_running_loop()
        # executor = concurrent.futures.ThreadPoolExecutor()
        # loop.run_in_executor(executor, self.monitor_sa_events)

        updown_q = queue.Queue()

        # Run the task to monitor the security associations for duplicates.
        logger.info("Starting SA monitor.")
        t0 = threading.Thread(
            target=self.monitor_sa_events, args=[updown_q], daemon=True
        )
        t0.start()

        # Run the task to monitor the route advertisements.
        logger.info("Starting route advertisement monitor.")
        t1 = threading.Thread(
            target=self.monitor_route_advertisements, args=[updown_q], daemon=True
        )
        t1.start()

        # Run the task to check for inactive connections every interval.
        logger.info("Starting inactive connection monitor.")
        t2 = loop.create_task(
            self.repeat(60, self.monitor_conn_inactive, init_wait=True)
        )
        await t2

    async def repeat(self, interval, func, *args, init_wait=False, **kwargs):
        """Run func every interval seconds.

        If func has not finished before *interval*, will run again
        immediately when the previous iteration finished.

        *args and **kwargs are passed as the arguments to func.
        """
        if init_wait:
            await asyncio.sleep(interval)
        while True:
            await asyncio.gather(
                func(*args, **kwargs),
                asyncio.sleep(interval),
            )

    async def monitor_conn_inactive(self):
        """
        Monitors for inactive connection definitions where the connection is set to initiate/start.
        This doesn't check for IKE SAs without IPsec SAs.
        """
        vcs = self.connect()
        conns = [i.decode() for i in vcs.get_conns()["conns"]]
        sas = [list(i.keys())[0] for i in vcs.list_sas()]
        logger.debug("Configured connections: %s", conns)
        logger.debug("Active connections: %s", sas)

        # TODO: Implement IKE SA without IPsec SAs check?

        for con in conns:
            if con in sas:
                continue
            logger.info("Starting connection '%s'", con)
            self.initiate_sa(vcs=vcs, ike=con, child=con)

    def monitor_sa_events(self, q: queue.Queue):
        """
        Monitor for SA events and take action accordingly.
        """

        vcs = self.connect()
        for event in vcs.listen(
            event_types=["ike-updown", "child-updown"]  # , timeout=0.05
        ):
            event_type, event_data = event
            if event_type is None or event_data is None:
                continue
            match event_type:
                case b"ike-updown":
                    q.put_nowait(event_data)
                    self.resolve_duplicate_ike_sa(event_data)
                case b"child-updown":
                    q.put_nowait(event_data)
                    self.resolve_duplicate_ipsec_sa(event_data)

    def monitor_route_advertisements(self, q: queue.Queue) -> None:
        """
        Receives child updown events and tries to check if the route for the remote should be
        advertised or retracted.
        """

        vcs = self.connect()

        for i in vcs.list_sas():
            self.resolve_route_advertisements(i)

        while True:
            ike_event = q.get()
            time.sleep(0.1)
            self.resolve_route_advertisements(ike_event)

    def resolve_route_advertisements(self, ike_event: IkeData):
        """
        Resolver for monitor monitor_route_advertisements
        """

        ike_name: str
        if len(keys := ike_event.keys()) == 2:
            _, ike_name = list(keys)
        else:
            ike_name: str = list(keys)[0]

        if ike_name.startswith("uplink"):
            return

        vcs = self.connect()

        trusted_netns = config.TRUSTED_NETNS
        interface = f"{ike_name}_I"
        ipv6_prefix = config.VPNC_SERVICE_CONFIG.prefix_downlink_v6
        ipv6_base = int(ipv6_prefix[0])

        v6_seg_3 = ike_name[0]
        v6_seg_4 = int(ike_name[1:5])
        v6_seg_5 = int(ike_name[6:])

        v6_offset = int(IPv6Address(f"0:0:{v6_seg_3}:{v6_seg_4}:{v6_seg_5}::"))
        v6_address = IPv6Address(ipv6_base + v6_offset)
        v6_network = IPv6Network(v6_address).supernet(new_prefix=96)

        action = "Retracting"
        cmd = f"ip -n {trusted_netns} -6 route del {v6_network} dev {interface}"

        vpn: dict[str, Any] = {}
        if v := list(vcs.list_sas({"ike": ike_name, "child": ike_name})):
            vpn = v[0]
        ike_data = vpn.get(ike_name, {})
        # ike_data = ike_event[ike_name]
        if list(ike_data.get("child-sas", {}).keys()):
            child_id: str = list(ike_data.get("child-sas").keys())[0]
        else:
            child_id = ""
        child_data = ike_data.get("child-sas", {}).get(child_id, {})
        if (
            ike_data.get("state") == b"ESTABLISHED"
            and child_data.get("state") == b"INSTALLED"
        ):
            action = "Advertising"
            cmd = f"ip -n {trusted_netns} -6 route add {v6_network} via fe80::1 dev {interface}"

        logger.info(
            "%s route for tunnel '%s'.\n%s",
            action,
            ike_name,
            cmd,
        )
        sp = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        if sp.stdout.decode().strip() != "RTNETLINK answers: File exists":
            logger.info(sp.stdout.decode())

    def resolve_duplicate_ike_sa(self, ike_event: IkeData) -> None:
        """
        Checks for duplicate IPsec security associations and if these need to be removed.
        If SAs need be removed, the older ones are removed in favor of the youngest.
        """
        vcs = self.connect()
        if len(keys := ike_event.keys()) == 2:
            _, ike_name = list(keys)
        else:
            ike_name = list(keys)[0]

        logger.debug("IKE event received for SA '%s'", ike_name)

        ike_sas: list[IkeData] = list(vcs.list_sas({"ike": ike_name}))

        if len(ike_sas) <= 1:
            logger.debug(
                "Skipping IKE event for SA '%s'. Two or fewer SAs active.", ike_name
            )
            return

        best_ike_sa_event: IkeData = {}

        for idx, ike_sa_event in enumerate(ike_sas):
            for ike_name, ike_sa in ike_sa_event.items():
                # First item has nothing to compare to.
                if idx == 0:
                    best_ike_sa_event = ike_sa_event
                    continue

                # Compare the seconds since the SA was established. Choose the most recent one.
                try:
                    ike_sa_established = int(ike_sa["established"])
                    best_sa_established = int(
                        best_ike_sa_event[ike_name]["established"]
                    )
                except TypeError:
                    continue
                except KeyError:
                    continue

                if ike_sa_established <= best_sa_established:
                    self.terminate_sa(
                        vcs=vcs, ike_id=best_ike_sa_event[ike_name]["uniqueid"]
                    )
                    best_ike_sa_event = ike_sa_event
                else:
                    self.terminate_sa(vcs=vcs, ike_id=ike_sa["uniqueid"])

    def resolve_duplicate_ipsec_sa(self, ike_event: IkeData):
        """
        Checks for duplicate IPsec security associations and if these need to be removed.
        If SAs need be removed, the older ones are removed in favor of the youngest.
        """
        vcs = self.connect()
        if len(keys := ike_event.keys()) == 2:
            _, ike_name = list(keys)
        else:
            ike_name = list(keys)[0]
        ike_sas: list[IkeData] = list(vcs.list_sas({"ike": ike_name}))

        for ike_sa in ike_sas:
            ike_sa_props = ike_sa[ike_name]

            # Get the most recent SA for each TS pair.
            ts_unique: dict[str, Any] = {}

            for _, ipsec_sa in ike_sa_props["child-sas"].items():
                # The check must be done per traffic selector pair.
                # If this is the first time seeing the traffic selector for the IKE SA, don't do
                # anything.
                ts_key = str((ipsec_sa["local-ts"], ipsec_sa["remote-ts"]))
                if ts_key not in ts_unique:
                    ts_unique[ts_key] = ipsec_sa
                    continue

                # Compare the seconds since the SA was established. Choose the most recent one.
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

    def connect(self, tries: int = 10, delay: int = 2):
        """
        Tries to connect to the VICI socket
        """
        for i in range(tries):
            try:
                return vici.Session()
            except ConnectionRefusedError as err:
                if i >= tries:
                    logger.warning(
                        "VICI socket not available after %s tries. Exiting.", tries
                    )
                    raise err
                logger.info("VICI socket is not yet available. Retrying.")
                time.sleep(delay)

        raise ConnectionAbortedError

    def initiate_sa(
        self,
        vcs: vici.Session,
        ike: str | bytes | None = None,
        child: str | bytes | None = None,
    ):
        """
        Initiates IKE/IPsec security associations.
        """

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
    ):
        """
        Terminates IKE/IPsec security associations.
        """
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
            # if not vcs.list_sas(_filter):
            #     logger.info("SA not found. It may already be deleted: '%s'", _filter)
            #     return
            for i in vcs.terminate(_filter):
                logger.debug(i)

        except vici.exception.CommandException:
            logger.warning(("Termination of SA '%s' failed.", _filter), exc_info=True)


def main():
    """
    Test function
    """
    monitor = VpncMonitor(daemon=True)
    monitor.start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
