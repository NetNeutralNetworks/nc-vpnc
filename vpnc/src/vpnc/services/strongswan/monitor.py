"""Manage the strongswan service."""

from __future__ import annotations

import contextlib
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from typing import Any, TypeAlias

import vici
from pyroute2.netlink.exceptions import NetlinkError

from vpnc import config, helpers, shared
from vpnc.network import namespace, state
from vpnc.services import charon

logger = logging.getLogger("vpnc")


POLICY_DIR_RE = re.compile(r"^\s+dir (\w+)")
POLICY_IF_ID_RE = re.compile(r"^\s+if_id (0x[0-9a-f]+)")

# Tries to connect to charon, which may be (re)starting.
CONNECT_TRIES = 10
# An XFRM policy: (selector, direction, if_id).
XfrmPolicy: TypeAlias = tuple[str, str, int]


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

    def reconcile_connections(self) -> list[dict[str, Any]]:
        """Sync connections, initiate missing initiator SAs, remove unknown SAs.

        Also corrects the XFRM interface states (missed events). The SAs are
        listed once, and returned for the checks that follow.
        """
        # Imported here: the package imports this module first.
        from vpnc.services.strongswan import strongswan  # noqa: PLC0415

        with charon.session(tries=CONNECT_TRIES) as vcs:
            strongswan.sync(vcs)

            conns: dict[str, dict[str, Any]] = {
                name: details
                for conn in vcs.list_conns()
                for name, details in conn.items()
            }
            listing: list[dict[str, Any]] = list(vcs.list_sas())
            # Right away: an event may change a state after the listing.
            self.resync_xfrm_interface_states(conns, listing)
            sas: set[str] = {name for sa in listing for name in sa}
            logger.debug("Configured connections: %s", list(conns))
            logger.debug("Active connections: %s", sas)

            # TODO@draggeta: Implement IKE SA without IPsec SAs check?

            for con, details in conns.items():
                if con in sas:
                    continue
                if not charon.is_initiator(details):
                    logger.debug("Waiting for the peer of connection '%s'.", con)
                    continue
                logger.info("Initiating connection '%s'", con)
                charon.initiate(vcs, con)

            for sa in sas - conns.keys():
                logger.info("Terminating connection '%s'", sa)
                charon.terminate(vcs, ike=sa)

        self.remove_stale_policies(listing)
        return listing

    def remove_stale_policies(self, listing: list[dict[str, Any]]) -> None:
        """Delete XFRM policies whose if_id has had no child SA for two checks.

        Policies don't expire, so they stay when charon dies and the SA doesn't
        come back. Waiting a check avoids racing an SA that is being set up.
        """
        active: set[int] = set()
        for sa in listing:
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

    def ike_events(self, timeout: float) -> Iterator[str]:
        """Yield the connection of each IKE/child up/down event, until stopped.

        The timeout (seconds) is how often it checks whether to stop.
        """
        with charon.session(None, tries=CONNECT_TRIES) as vcs:
            for event_type, event_data in vcs.listen(
                event_types=["ike-updown", "child-updown"],
                timeout=timeout,
            ):
                if shared.STOP_EVENT.is_set():
                    return
                if event_type is None or event_data is None:
                    continue
                keys = list(event_data)
                yield keys[1] if len(keys) == 2 else keys[0]  # noqa: PLR2004

    def monitor_duplicate_sa_events(self) -> None:
        """Resolve duplicate SAs of the connections with IKE/child up/down events."""
        for ike_name in self.ike_events(timeout=0.1):
            self.resolve_duplicate_sas(ike_name)

    def monitor_xfrm_interface_state(self) -> None:
        """Monitor VPN tunnel state and set interface state accordingly.

        Acts on IKE/child up/down events. Events missed while it wasn't listening
        are corrected when it starts, others by the full check.
        """
        with charon.session(tries=CONNECT_TRIES) as vcs:
            self.resync_xfrm_interface_states(
                charon.loaded_connections(vcs),
                list(vcs.list_sas()),
            )
        for ike_name in self.ike_events(timeout=1):
            self.set_xfrm_interface_state(ike_name)

    def resync_xfrm_interface_states(
        self,
        names: Iterable[str],
        listing: list[dict[str, Any]],
    ) -> None:
        """Set the XFRM interface state of the connections (names), from the SAs.

        With one read per network instance.
        """
        up = {
            name
            for sa in listing
            for name, ike_data in sa.items()
            if charon.sa_up(ike_data)
        }
        interfaces: dict[str, list[tuple[str, str]]] = {}
        for name in names:
            if (interface := self.xfrm_interface(name)) is not None:
                interfaces.setdefault(interface[0], []).append((name, interface[1]))
        for network_instance_name, connections in interfaces.items():
            try:
                with state.session(), state.netns(network_instance_name) as netns:
                    for name, ifname in connections:
                        state.ensure_link_state(
                            netns.ipr,
                            netns.state,
                            ifname,
                            up=name in up,
                        )
            except (OSError, NetlinkError) as err:
                # E.g. a network instance that is being removed.
                logger.debug(
                    "Setting the interface states in %s failed: %s",
                    network_instance_name,
                    err,
                )

    def xfrm_interface(self, ike_name: str) -> tuple[str, str] | None:
        """Return the network instance and XFRM interface of a connection.

        None if its tenant has no configuration (anymore).
        """
        if ike_name.startswith(config.CORE_NI):
            number = helpers.split_connection_name(ike_name)[1]
            return config.CORE_NI, helpers.xfrm_interface_name(number)
        if not (match := config.DOWNLINK_CON_RE.match(ike_name)):
            msg = f"Invalid connection name '{ike_name}'"
            raise ValueError(msg)
        network_instance, tenant_id, connection_id = match.groups()
        # A deleted connection's SA is terminated by the reconciler. Until then
        # it can still rekey or change state.
        if not config.VPNC_A_CONFIG_DIR.joinpath(f"{tenant_id}.yaml").exists():
            logger.info("No configuration file found for '%s'", tenant_id)
            return None
        return network_instance, helpers.xfrm_interface_name(connection_id)

    def set_xfrm_interface_state(self, ike_name: str) -> None:
        """Set a connection's XFRM interface up if its tunnel is up, down otherwise.

        The routes service reacts to the interface state, so a wrong state leaves
        routes blackholed or advertised.
        """
        if (interface := self.xfrm_interface(ike_name)) is None:
            return
        network_instance_name, ifname = interface

        with charon.session(tries=CONNECT_TRIES) as vcs:
            tunnel_up = any(
                charon.sa_up(ike_sa.get(ike_name, {}))
                for ike_sa in vcs.list_sas({"ike": ike_name})
            )
        # Only this interface is read, not the whole namespace.
        snapshot = state.NetnsState(name=network_instance_name)
        with namespace.IPRoute(network_instance_name) as ipr:
            if state.refresh_link(ipr, snapshot, ifname) is None:
                logger.warning(
                    "Network instance %s interface %s doesn't exist.",
                    network_instance_name,
                    ifname,
                )
                return
            state.ensure_link_state(ipr, snapshot, ifname, up=tunnel_up)

    def resolve_duplicate_sas(self, ike_name: str) -> None:
        """Keep the newest IKE/CHILD SA of an initiator connection, terminate the rest.

        Only initiators resolve, so both peers don't delete different SAs.
        """
        with charon.session(tries=CONNECT_TRIES) as vcs:
            conns = [
                c[ike_name] for c in vcs.list_conns({"ike": ike_name}) if ike_name in c
            ]
            if not conns or not charon.is_initiator(conns[0]):
                return

            ike_sas: list[dict[str, Any]] = [
                sa[ike_name] for sa in vcs.list_sas({"ike": ike_name}) if ike_name in sa
            ]
            established = [sa for sa in ike_sas if sa.get("state") == b"ESTABLISHED"]
            if len(established) > 1:
                keep = min(
                    established,
                    key=lambda sa: (
                        int(sa.get("established", 0)),
                        sa.get("initiator-spi"),
                    ),
                )
                for sa in established:
                    if sa is keep:
                        continue
                    logger.info("Terminating duplicate IKE SA of '%s'.", ike_name)
                    charon.terminate(vcs, ike_id=sa["uniqueid"])
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
                charon.terminate(vcs, child_id=child["uniqueid"])
