"""Manage the network instance routes."""

from __future__ import annotations

import atexit
import logging
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from typing import TYPE_CHECKING, Any, Callable

import pyroute2
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg

import vpnc.models.connections
import vpnc.models.tenant
from vpnc import config
from vpnc.models import enums, info
from vpnc.network import route
from vpnc.services import configuration
from vpnc.shared import NI_LOCK

if TYPE_CHECKING:
    import vpnc.models.network_instance

logger = logging.getLogger("vpnc")

NI_ROUTE_MONITORS: dict[
    str,
    tuple[vpnc.models.network_instance.NetworkInstance, pyroute2.NDB],
] = {}


def create_handler(network_instance_id: str) -> Callable[..., None]:
    """Closure to add the network instance id to the handler function."""

    def resolve_route_advertisements(_: str, event: dict[str, Any]) -> None:
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
        ni_dl = pyroute2.NetNS(network_instance_id)
        ni_core = pyroute2.NetNS(config.CORE_NI)

        connection: vpnc.models.connections.Connection | None = None
        active_connection: vpnc.models.connections.Connection | None = None
        connection_name_downlink: str = event["attrs"][0][1]

        try:
            ifidx = ni_dl.link_lookup(ifname=connection_name_downlink)
            if intf := ni_dl.get_links(*ifidx):
                interface_state: str = intf[0].get("state", event["state"])
            else:
                interface_state = event["state"]
        except AttributeError:
            interface_state = event["state"]

        if net_inst:
            for conn in net_inst.connections.values():
                if connection_name_downlink == conn.intf_name(net_inst):
                    connection = conn
                    break

        if active_net_inst:
            for conn in active_net_inst.connections.values():
                if connection_name_downlink == conn.intf_name(active_net_inst):
                    active_connection = conn
                    break

        logger.info("Acquiring lock for %s", network_instance_id)
        with ni_dl, ni_core, NI_LOCK[network_instance_id]:
            # Connection is deleted
            if active_connection and connection_event == "RTM_DELLINK":
                delete_all_routes(
                    ni_dl,
                    ni_core,
                    active_net_inst,
                    active_connection,
                )

            if (
                net_inst
                and connection_event == "RTM_NEWLINK"
                and interface_state == "up"
                and connection
            ):
                set_routes_up(
                    ni_dl,
                    ni_core,
                    net_inst,
                    connection,
                    active_connection,
                )

            if (
                net_inst
                and connection_event == "RTM_NEWLINK"
                and interface_state == "down"
                and connection
            ):
                set_routes_down(ni_dl, ni_core, net_inst, connection, active_connection)
        logger.info("Releasing lock for %s", network_instance_id)

        NI_ROUTE_MONITORS[network_instance_id] = (net_inst, ni_handler)

    return resolve_route_advertisements


def set_routes_up(
    ni_dl: pyroute2.NetNS,
    ni_core: pyroute2.NetNS,
    net_inst: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
    active_connection: vpnc.models.connections.Connection | None,
) -> None:
    """Activates routes when connections go down."""
    default_tenant = vpnc.models.tenant.get_default_tenant()

    if (
        net_inst.type == enums.NetworkInstanceType.CORE
        and default_tenant.mode == enums.ServiceMode.HUB
    ):
        return

    interface_name_downlink = connection.intf_name(net_inst)
    interface_name_core = f"{net_inst.id}_C"

    interfaces_all_up_list: list[bool] = []
    for conn in net_inst.connections.values():
        ifidx = ni_dl.link_lookup(ifname=conn.intf_name(net_inst))
        if intf := ni_dl.get_links(*ifidx):
            interfaces_all_up_list.append(intf[0].get("state", "down") == "up")
            continue
        interfaces_all_up_list.append(False)

    interfaces_all_up: bool = all(
        interfaces_all_up_list,
    )

    nat64_scope = configuration.get_network_instance_nat64_scope(net_inst)

    # This is the lazy, but for now efficient way to make sure that the routes
    # are correct.
    if active_connection and connection != active_connection:
        delete_all_routes(ni_dl, ni_core, net_inst, active_connection)
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
        if net_inst.type in (
            enums.NetworkInstanceType.DOWNLINK,
            enums.NetworkInstanceType.ENDPOINT,
        ):
            adv6_route_up = None
            if (
                net_inst.type == enums.NetworkInstanceType.DOWNLINK
                and route6.nptv6
                and interfaces_all_up
            ):
                adv6_route_up = route6.nptv6_prefix
            elif interfaces_all_up:
                adv6_route_up = route6.to

            if adv6_route_up is None:
                continue
            route.command(
                ni_core,
                "replace",
                dst=adv6_route_up,
                gateway=IPv6Address("fe80::1"),
                ifname=interface_name_core,
            )

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
    if (
        nat64_scope
        and net_inst.type == enums.NetworkInstanceType.DOWNLINK
        and interfaces_all_up
    ):
        route.command(
            ni_core,
            "replace",
            dst=nat64_scope,
            gateway=IPv6Address("fe80::1"),
            ifname=interface_name_core,
        )


def set_routes_down(
    ni_dl: pyroute2.NetNS,
    ni_core: pyroute2.NetNS,
    net_inst: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
    active_connection: vpnc.models.connections.Connection | None,
) -> None:
    """Disables/blackholes routes when connections go down."""
    default_tenant = vpnc.models.tenant.get_default_tenant()

    if (
        net_inst.type == enums.NetworkInstanceType.CORE
        and default_tenant.mode == enums.ServiceMode.HUB
    ):
        return
    nat64_scope = configuration.get_network_instance_nat64_scope(net_inst)
    # This is the lazy, but for now efficient way to make sure that the routes
    # are correct.
    if active_connection and connection != active_connection:
        delete_all_routes(ni_dl, ni_core, net_inst, active_connection)
    for route6 in connection.routes.ipv6:
        # routes in current the namespace
        route.command(ni_dl, "replace", dst=route6.to, type="blackhole")
        # routes in CORE for downlink
        if net_inst.type in (
            enums.NetworkInstanceType.DOWNLINK,
            enums.NetworkInstanceType.ENDPOINT,
        ):
            adv6_route_down = route6.to
            if net_inst.type == enums.NetworkInstanceType.DOWNLINK and route6.nptv6:
                adv6_route_down = route6.nptv6_prefix
            # This will happen the first time a route is added and NPTv6 has't been
            # calculated yet
            if adv6_route_down is None:
                continue
            route.command(
                ni_core,
                "replace",
                dst=adv6_route_down,
                type="blackhole",
            )

    for route4 in connection.routes.ipv4:
        # routes in current the namespace
        route.command(
            ni_dl,
            "replace",
            dst=route4.to,
            type="blackhole",
        )
        # routes in CORE for downlink
        if net_inst.type == enums.NetworkInstanceType.ENDPOINT:
            route.command(
                ni_core,
                "replace",
                dst=route4.to,
                type="blackhole",
            )
    # IPv4
    if nat64_scope and net_inst.type == enums.NetworkInstanceType.DOWNLINK:
        route.command(
            ni_core,
            "replace",
            dst=nat64_scope,
            type="blackhole",
        )


def delete_all_routes(
    ni_dl: pyroute2.NetNS,
    ni_core: pyroute2.NetNS,
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
    ndb = pyroute2.NDB(sources=[{"netns": network_instance_id}])
    NI_ROUTE_MONITORS[network_instance_id] = (None, ndb)

    handler = create_handler(network_instance_id)
    ndb.task_manager.register_handler(ifinfmsg, handler)

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

    NI_ROUTE_MONITORS[network_instance_id][1].close()
    del NI_ROUTE_MONITORS[network_instance_id]
