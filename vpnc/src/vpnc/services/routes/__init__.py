"""Manage the network instance routes."""

from __future__ import annotations

import atexit
import logging
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from typing import TYPE_CHECKING, Any, Callable

import pyroute2

import vpnc.models.connections
import vpnc.models.tenant
from vpnc import config
from vpnc.models import enums, info
from vpnc.network import route
from vpnc.network.events import LinkMonitor
from vpnc.services import configuration
from vpnc.shared import NI_LOCK

if TYPE_CHECKING:
    import vpnc.models.network_instance

logger = logging.getLogger("vpnc")

NI_ROUTE_MONITORS: dict[
    str,
    tuple[vpnc.models.network_instance.NetworkInstance | None, LinkMonitor],
] = {}


def create_handler(network_instance_id: str) -> Callable[..., None]:
    """Closure to add the network instance id to the handler function."""

    def resolve_route_advertisements(event: Any) -> None:  # noqa: ANN401
        """Resolve route advertisement statuses.

        Used by monitor monitor_route_advertisements.

        Tries to resolve the current routes as in the FDB and what should be advertised.
        If the connection is down, the advertisements should be retracted.
        """
        nonlocal network_instance_id
        default_tenant = vpnc.models.tenant.get_default_tenant()

        connection_event: str = event["event"]
        if connection_event not in ("RTM_NEWLINK", "RTM_DELLINK"):
            return

        if network_instance_id in (
            config.CORE_NI,
            config.DEFAULT_NI,
            config.ENDPOINT_NI,
            config.EXTERNAL_NI,
        ):
            tenant_id = "DEFAULT"
            net_inst = default_tenant.network_instances[network_instance_id]
        else:
            ni_info = info.parse_downlink_network_instance_name(
                network_instance_id,
            )
            tenant_id = ni_info.tenant
            net_inst = None
            if tenant := vpnc.models.tenant.get_tenant(tenant_id):
                net_inst = tenant.network_instances.get(network_instance_id)

        active_net_inst, ni_handler = NI_ROUTE_MONITORS[network_instance_id]
        connection_name: str = event.get("ifname")

        # Only connection interfaces affect routes (configured or still active).
        active_connection = _find_connection(active_net_inst, connection_name)
        if not (_find_connection(net_inst, connection_name) or active_connection):
            return

        ni_dl = pyroute2.IPRoute(netns=network_instance_id, flags=0)
        ni_core = pyroute2.IPRoute(netns=config.CORE_NI, flags=0)
        logger.info("Acquiring lock for %s", network_instance_id)
        with ni_dl, ni_core, NI_LOCK[network_instance_id]:
            # The interface of a connection is deleted.
            if (
                active_net_inst
                and active_connection
                and connection_event == "RTM_DELLINK"
            ):
                delete_all_routes(
                    ni_dl,
                    ni_core,
                    active_net_inst,
                    active_connection,
                )
            # Recompute the routes of all connections, as the state of one connection
            # affects the advertisements of the others.
            if net_inst:
                reconcile_routes(ni_dl, ni_core, net_inst, active_net_inst)
        logger.info("Releasing lock for %s", network_instance_id)

        NI_ROUTE_MONITORS[network_instance_id] = (net_inst, ni_handler)

    return resolve_route_advertisements


# Interface flags (linux/if.h).
IFF_UP = 0x1
IFF_LOWER_UP = 0x10000


def _find_connection(
    net_inst: vpnc.models.network_instance.NetworkInstance | None,
    interface_name: str,
) -> vpnc.models.connections.Connection | None:
    """Return the connection of a network instance that uses an interface."""
    if not net_inst:
        return None
    for conn in net_inst.connections.values():
        if conn.intf_name(net_inst) == interface_name:
            return conn
    return None


def interface_is_up(ni: pyroute2.IPRoute, interface_name: str) -> bool:
    """Return whether an interface can pass traffic.

    The interface must be administratively up and have carrier (lower layer up).
    The admin state alone isn't enough: e.g. a tun interface without an attached
    SSH session is admin up but has no carrier.
    """
    if not (ifidx := ni.link_lookup(ifname=interface_name)):
        return False
    if not (links := ni.get_links(*ifidx)):
        return False
    flags: int = links[0]["flags"]
    return bool(flags & IFF_UP) and bool(flags & IFF_LOWER_UP)


def reconcile_routes(
    ni_dl: pyroute2.IPRoute,
    ni_core: pyroute2.IPRoute,
    net_inst: vpnc.models.network_instance.NetworkInstance,
    active_net_inst: vpnc.models.network_instance.NetworkInstance | None,
) -> None:
    """Set the routes of all connections of a network instance to their state.

    Each connection's routes in the network instance follow that connection's
    state: via the interface when it is up, blackholed when it is down.
    The advertisements in CORE (NPTv6/IPv6 prefixes and the NAT64 scope) are only
    active when all connections of the network instance are up, and blackholed
    otherwise.

    Everything is recomputed on each call, so the result doesn't depend on the
    order in which interfaces changed state.
    """
    default_tenant = vpnc.models.tenant.get_default_tenant()
    if (
        net_inst.type == enums.NetworkInstanceType.CORE
        and default_tenant.mode == enums.ServiceMode.HUB
    ):
        return

    connections_up = {
        conn_id: interface_is_up(ni_dl, conn.intf_name(net_inst))
        for conn_id, conn in net_inst.connections.items()
    }
    all_up = bool(connections_up) and all(connections_up.values())
    logger.debug(
        "Network instance %s connection states: %s",
        net_inst.id,
        connections_up,
    )

    for conn_id, conn in net_inst.connections.items():
        active_conn = None
        if active_net_inst:
            active_conn = active_net_inst.connections.get(conn_id)
        # Remove the routes of the previous configuration of this connection.
        if active_conn and conn != active_conn:
            delete_all_routes(ni_dl, ni_core, net_inst, active_conn)
        if connections_up[conn_id]:
            _set_connection_routes_up(
                ni_dl,
                ni_core,
                net_inst,
                conn,
                advertise=all_up,
            )
        else:
            _set_connection_routes_down(ni_dl, ni_core, net_inst, conn)

    nat64_scope = configuration.get_network_instance_nat64_scope(net_inst)
    if nat64_scope and net_inst.type == enums.NetworkInstanceType.DOWNLINK:
        if all_up:
            route.command(
                ni_core,
                "replace",
                dst=nat64_scope,
                gateway=IPv6Address("fe80::1"),
                ifname=f"{net_inst.id}_C",
            )
        else:
            route.command(ni_core, "replace", dst=nat64_scope, type="blackhole")


def _core_ipv6_advertisement(
    net_inst: vpnc.models.network_instance.NetworkInstance,
    route6: vpnc.models.connections.RouteIPv6,
) -> IPv6Network | None:
    """Return the prefix advertised in CORE for a connection's IPv6 route."""
    if net_inst.type == enums.NetworkInstanceType.DOWNLINK and route6.nptv6:
        # None until the NPTv6 prefix has been calculated.
        return route6.nptv6_prefix
    if net_inst.type in (
        enums.NetworkInstanceType.DOWNLINK,
        enums.NetworkInstanceType.ENDPOINT,
    ):
        return route6.to
    return None


def _set_connection_routes_up(
    ni_dl: pyroute2.IPRoute,
    ni_core: pyroute2.IPRoute,
    net_inst: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
    *,
    advertise: bool,
) -> None:
    """Route a connection's routes via its interface.

    The IPv6 advertisements in CORE are only activated if advertise is set, and
    blackholed otherwise.
    """
    interface_name_downlink = connection.intf_name(net_inst)
    interface_name_core = f"{net_inst.id}_C"

    for route6 in connection.routes.ipv6:
        # routes in current the namespace
        route.command(
            ni_dl,
            "replace",
            dst=route6.to,
            gateway=route6.via,
            ifname=interface_name_downlink,
        )
        # routes in CORE for downlink
        if (adv6_route := _core_ipv6_advertisement(net_inst, route6)) is None:
            continue
        if advertise:
            route.command(
                ni_core,
                "replace",
                dst=adv6_route,
                gateway=IPv6Address("fe80::1"),
                ifname=interface_name_core,
            )
        else:
            route.command(ni_core, "replace", dst=adv6_route, type="blackhole")

    for route4 in connection.routes.ipv4:
        # routes in current the namespace
        route.command(
            ni_dl,
            "replace",
            dst=route4.to,
            gateway=route4.via,
            ifname=interface_name_downlink,
        )
        # routes in CORE for downlink
        if net_inst.type == enums.NetworkInstanceType.ENDPOINT:
            route.command(
                ni_core,
                "replace",
                dst=route4.to,
                gateway=IPv4Address("169.254.0.2"),
                ifname=interface_name_core,
            )


def _set_connection_routes_down(
    ni_dl: pyroute2.IPRoute,
    ni_core: pyroute2.IPRoute,
    net_inst: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Blackhole a connection's routes and its advertisements in CORE."""
    for route6 in connection.routes.ipv6:
        # routes in current the namespace
        route.command(ni_dl, "replace", dst=route6.to, type="blackhole")
        # routes in CORE for downlink
        if (adv6_route := _core_ipv6_advertisement(net_inst, route6)) is None:
            continue
        route.command(ni_core, "replace", dst=adv6_route, type="blackhole")

    for route4 in connection.routes.ipv4:
        # routes in current the namespace
        route.command(ni_dl, "replace", dst=route4.to, type="blackhole")
        # routes in CORE for downlink
        if net_inst.type == enums.NetworkInstanceType.ENDPOINT:
            route.command(ni_core, "replace", dst=route4.to, type="blackhole")


def delete_all_routes(
    ni_dl: pyroute2.IPRoute,
    ni_core: pyroute2.IPRoute,
    net_inst: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Delete all routes for a connection.

    This function is called when a connection is removed.
    """
    interface_name_downlink = connection.intf_name(net_inst)
    nat64_scope = None
    if net_inst:
        nat64_scope = configuration.get_network_instance_nat64_scope(net_inst)
    for route6 in connection.routes.ipv6:
        # routes in current the namespace
        route.command(
            ni_dl,
            "del",
            dst=route6.to,
            ifname=interface_name_downlink,
            gateway=route6.via,
        )

        # routes in CORE for downlink
        if net_inst.type in (
            enums.NetworkInstanceType.DOWNLINK,
            enums.NetworkInstanceType.ENDPOINT,
        ):
            adv6_route_del: IPv6Network = route6.to
            if (
                net_inst.type == enums.NetworkInstanceType.DOWNLINK
                and route6.nptv6
                and route6.nptv6_prefix
            ):
                adv6_route_del = route6.nptv6_prefix
            route.command(
                ni_core,
                "del",
                dst=adv6_route_del,
            )

    for route4 in connection.routes.ipv4:
        # routes in current the namespace
        route.command(
            ni_dl,
            "del",
            dst=route4.to,
            ifname=interface_name_downlink,
            gateway=route4.via,
        )
        # routes in CORE for downlink
        if net_inst.type == enums.NetworkInstanceType.ENDPOINT:
            route.command(
                ni_core,
                "del",
                dst=route4.to,
            )
            # routes in CORE for downlink
    if nat64_scope and net_inst.type == enums.NetworkInstanceType.DOWNLINK:
        route.command(
            ni_core,
            "del",
            dst=nat64_scope,
        )


def start(network_instance_id: str) -> None:
    """Start monitoring routes in a network_instance."""
    if network_instance_id in NI_ROUTE_MONITORS:
        logger.debug(
            "Network instance %s routes are already monitored.",
            network_instance_id,
        )
        return

    logger.info(
        "Starting network instance %s routes monitor.",
        network_instance_id,
    )
    monitor = LinkMonitor(network_instance_id, create_handler(network_instance_id))
    NI_ROUTE_MONITORS[network_instance_id] = (None, monitor)
    monitor.start()

    atexit.register(stop, network_instance_id=network_instance_id)


def stop(network_instance_id: str) -> None:
    """Stop monitoring routes in a network_instance."""
    if network_instance_id not in NI_ROUTE_MONITORS:
        logger.warning(
            "Network instance '%s' routes are not being monitored.",
            network_instance_id,
        )
        return

    logger.info(
        "Stopping network instance '%s' routes monitoring.",
        network_instance_id,
    )

    NI_ROUTE_MONITORS[network_instance_id][1].stop()
    del NI_ROUTE_MONITORS[network_instance_id]
