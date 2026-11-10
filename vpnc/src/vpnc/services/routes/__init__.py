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
from vpnc.network import state
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
            # Recompute the routes of all connections, as the state of one connection
            # affects the advertisements of the others.
            if net_inst:
                reconcile_routes(ni_dl, ni_core, net_inst, active_net_inst)
        logger.info("Releasing lock for %s", network_instance_id)

        NI_ROUTE_MONITORS[network_instance_id] = (net_inst, ni_handler)

    return resolve_route_advertisements


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


def desired_routes(
    net_inst: vpnc.models.network_instance.NetworkInstance,
    links: dict[str, state.Link],
) -> tuple[list[state.Route], list[state.Route]]:
    """Return the routes of a network instance and its routes in CORE.

    A connection's routes go via its interface when it passes traffic, and are
    blackholed otherwise. The advertisements in CORE (IPv6 prefixes and the NAT64
    scope) are only active when all connections of the network instance are up.
    """
    core_link = f"{net_inst.id}_C"
    ni_routes: list[state.Route] = []
    core_routes: list[state.Route] = []

    def route_or_blackhole(dst, gateway, dev, *, up):  # noqa: ANN001, ANN202
        return (
            state.Route(dst, gateway=gateway, dev=dev)
            if up
            else state.Route.blackhole(dst)
        )

    connections_up = {
        conn_id: (link := links.get(conn.intf_name(net_inst))) is not None
        and link.passes_traffic
        for conn_id, conn in net_inst.connections.items()
    }
    all_up = bool(connections_up) and all(connections_up.values())

    for conn_id, conn in net_inst.connections.items():
        up = connections_up[conn_id]
        dev = conn.intf_name(net_inst)
        for route6 in conn.routes.ipv6:
            ni_routes.append(route_or_blackhole(route6.to, route6.via, dev, up=up))
            if (adv6 := _core_ipv6_advertisement(net_inst, route6)) is not None:
                core_routes.append(
                    route_or_blackhole(
                        adv6,
                        IPv6Address("fe80::1"),
                        core_link,
                        up=all_up,
                    ),
                )
        for route4 in conn.routes.ipv4:
            ni_routes.append(route_or_blackhole(route4.to, route4.via, dev, up=up))
            if net_inst.type == enums.NetworkInstanceType.ENDPOINT:
                core_routes.append(
                    route_or_blackhole(
                        route4.to,
                        IPv4Address("169.254.0.2"),
                        core_link,
                        up=up,
                    ),
                )

    nat64_scope = configuration.get_network_instance_nat64_scope(net_inst)
    if nat64_scope and net_inst.type == enums.NetworkInstanceType.DOWNLINK:
        core_routes.append(
            route_or_blackhole(
                nat64_scope,
                IPv6Address("fe80::1"),
                core_link,
                up=all_up,
            ),
        )

    ni_routes.extend(_uplink_routes(net_inst))
    return ni_routes, core_routes


def _uplink_routes(
    net_inst: vpnc.models.network_instance.NetworkInstance,
) -> list[state.Route]:
    """Return the routes from a DOWNLINK/ENDPOINT network instance to the uplinks."""
    if net_inst.type not in (
        enums.NetworkInstanceType.DOWNLINK,
        enums.NetworkInstanceType.ENDPOINT,
    ):
        return []
    default_tenant = vpnc.models.tenant.get_default_tenant()
    veth = f"{net_inst.id}_D"
    routes: list[state.Route] = []
    core_ni = default_tenant.network_instances[config.CORE_NI]
    for connection in core_ni.connections.values():
        routes.extend(
            state.Route(route6.to, gateway=IPv6Address("fe80::"), dev=veth)
            for route6 in connection.routes.ipv6
        )
        if default_tenant.mode != enums.ServiceMode.HUB:
            routes.extend(
                state.Route(route4.to, gateway=IPv4Address("169.254.0.1"), dev=veth)
                for route4 in connection.routes.ipv4
            )
    return routes


def reconcile_routes(
    ni_dl: pyroute2.IPRoute,
    ni_core: pyroute2.IPRoute,
    net_inst: vpnc.models.network_instance.NetworkInstance,
    active_net_inst: vpnc.models.network_instance.NetworkInstance | None,
) -> None:
    """Make the routes of a network instance, and its routes in CORE, as desired.

    Routes of removed connections or destinations are deleted. In CORE only this
    network instance's destinations (current and previous) and routes via its link
    are managed, as CORE holds the routes of all network instances.
    """
    default_tenant = vpnc.models.tenant.get_default_tenant()
    if (
        net_inst.type == enums.NetworkInstanceType.CORE
        and default_tenant.mode == enums.ServiceMode.HUB
    ):
        return

    ni_state = state.NetnsState.read(ni_dl)
    ni_routes, core_routes = desired_routes(net_inst, ni_state.links)
    previous_ni: list[state.Route] = []
    previous_core: list[state.Route] = []
    if active_net_inst:
        previous_ni, previous_core = desired_routes(active_net_inst, {})

    if net_inst.type == enums.NetworkInstanceType.CORE:
        # CORE also holds other network instances' routes.
        managed = {r.dst for r in [*ni_routes, *previous_ni]}
        state.ensure_routes(ni_dl, ni_state, ni_routes, managed=managed)
        return
    state.ensure_routes(ni_dl, ni_state, ni_routes)

    core_state = state.NetnsState.read(ni_core)
    core_link = f"{net_inst.id}_C"
    managed = {r.dst for r in [*core_routes, *previous_core]} | {
        dst for dst, route in core_state.routes.items() if route.dev == core_link
    }
    state.ensure_routes(ni_core, core_state, core_routes, managed=managed)


def delete_core_routes(
    net_inst: vpnc.models.network_instance.NetworkInstance,
) -> None:
    """Delete a network instance's routes in CORE (e.g. when it's removed)."""
    _, core_routes = desired_routes(net_inst, {})
    core_link = f"{net_inst.id}_C"
    with pyroute2.IPRoute(netns=config.CORE_NI, flags=0) as ni_core:
        core_state = state.NetnsState.read(ni_core)
        managed = {r.dst for r in core_routes} | {
            dst for dst, route in core_state.routes.items() if route.dev == core_link
        }
        state.ensure_routes(ni_core, core_state, [], managed=managed)


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
