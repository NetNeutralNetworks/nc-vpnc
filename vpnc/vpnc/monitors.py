"""
Monitors the VPN security associations for unwanted duplicates. These can be caused by
simultaneous connections from both parties or intermittent internet connectivity issues.
"""

import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import Any, TypeAlias

import vici

IkeProperties: TypeAlias = MappingProxyType[str, Any]
IkeData: TypeAlias = MappingProxyType[str, bytes | IkeProperties]
EventType: TypeAlias = bytes
Event: TypeAlias = tuple[EventType, IkeData]


logger = logging.getLogger("vpnc")


class VpncSecAssocMonitor(threading.Thread):
    """
    Monitors the IKE and IPsec security associations for duplicates.
    """

    session: vici.Session = None

    def __init__(
        self,
        group: None = None,
        target: Callable[..., object] | None = None,
        name: str | None = None,
        args: Iterable[Any] = ...,
        kwargs: Mapping[str, Any] | None = None,
        *,
        daemon: bool | None = None,
    ) -> None:
        super().__init__(group, target, name, args, kwargs, daemon=daemon)

        for i in range(10):
            try:
                self.session = vici.Session()
                break
            except ConnectionRefusedError as err:
                if i == 10:
                    raise err
                time.sleep(1)

    def run(self):
        self.monitor_events()

    def monitor_events(self):
        """
        Monitor for SA events and take action accordingly.
        """
        for event in self.session.listen(event_types=["ike-updown", "child-updown"]):
            event_type, event_data = event
            match event_type:
                case b"ike-updown":
                    self.resolve_duplicate_ike_sa(event_data)
                case b"child-updown":
                    self.resolve_duplicate_ipsec_sa(event_data)

    def resolve_duplicate_ike_sa(self, ike_event: IkeData) -> None:
        """
        Checks for duplicate IPsec security associations and if these need to be removed.
        If SAs need be removed, the older ones are removed in favor of the youngest.
        """
        if len(keys := ike_event.keys()) == 2:
            _, ike_name = list(keys)
        else:
            ike_name = list(keys)[0]

        logger.debug("IKE event received for SA '%s'", ike_name)

        ike_sas: list[IkeData] = list(self.session.list_sas({"ike": ike_name}))

        # During rekeys there can be two IKE SAs active.
        if len(ike_sas) <= 2:
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
                    best_sa_established = int(best_ike_sa_event[ike_name]["established"])
                except TypeError:
                    continue
                except KeyError:
                    continue
                if ike_sa_established <= best_sa_established:
                    self.terminate_sa(ike_id=best_ike_sa_event[ike_name]["uniqueid"])
                    best_ike_sa_event = ike_sa_event
                else:
                    self.terminate_sa(ike_id=ike_sa["uniqueid"])

    def resolve_duplicate_ipsec_sa(self, ike_event: IkeData):
        """
        Checks for duplicate IPsec security associations and if these need to be removed.
        If SAs need be removed, the older ones are removed in favor of the youngest.
        """
        if len(keys := ike_event.keys()) == 2:
            _, ike_name = list(keys)
        else:
            ike_name = list(keys)[0]
        ike_sas: list[IkeData] = list(self.session.list_sas({"ike": ike_name}))

        for ike_sa in ike_sas:
            ike_sa_props = ike_sa[ike_name]

            # During rekeys there can be two IPsec SAs active.
            unique: dict[str, Any] = {}

            for _, ipsec_sa in ike_sa_props["child-sas"].items():
                # The check must be done per traffic selector pair.
                # If this is the first time seeing the traffic selector for the IKE SA, don't do
                # anything.
                ts_key = str((ipsec_sa["local-ts"], ipsec_sa["remote-ts"]))
                if ts_key not in unique:
                    unique[ts_key] = {"rest": [], "best": ipsec_sa}
                    continue

                # Compare the seconds since the SA was established. Choose the most recent one.
                try:
                    ipsec_sa_established = int(ipsec_sa["install-time"])
                    best_sa_established = int(unique[ts_key]["best"]["install-time"])
                except TypeError:
                    continue
                if ipsec_sa_established <= best_sa_established:
                    unique[ts_key]["rest"].append(unique[ts_key]["best"])
                    unique[ts_key]["best"] = ipsec_sa
                else:
                    unique[ts_key]["rest"].append(ipsec_sa)

            # For each TS pair, check if there are any that need to be removed
            for _, ipsec_sas in unique.items():
                # Set to 0 so that only 1 pair is allowed.
                if len(ipsec_sas["rest"]) == 0:
                    continue

                for ipsec_sa in ipsec_sas["rest"]:
                    print(f"UNIQUEID IS !!!!!!!!!!!!!!!!!! {ipsec_sa['uniqueid']}")
                    print(f"{ipsec_sa}")
                    self.terminate_sa(child_id=ipsec_sa["uniqueid"])

    def terminate_sa(
        self, ike_id: str | bytes | None = None, child_id: str | bytes | None = None
    ):
        """
        Terminates IKE/IPsec security associations.
        """
        _filter: dict[str, bytes] = {}
        if ike_id is not None:
            _filter.update({"ike-id": bytes(ike_id)})
        if child_id is not None:
            _filter.update({"child-id": bytes(child_id)})
        logger.info("Terminating SA with parameters: '%s'", _filter)
        for i in self.session.terminate(_filter):
            logger.info(i)


def main():
    """
    Test function
    """
    monitor = VpncSecAssocMonitor()
    monitor.start()


if __name__ == "__main__":
    main()
