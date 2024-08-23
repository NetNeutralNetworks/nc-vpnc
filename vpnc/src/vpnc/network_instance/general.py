"""Functions to make connections easier."""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from ipaddress import IPv6Address, IPv6Network
from typing import Any

from vpnc import config, helpers, models
from vpnc.network import namespace

logger = logging.getLogger("vpnc")


def add_network_instance(
    network_instance: models.NetworkInstance,
    cleanup: bool = False,  # noqa: FBT001, FBT002
) -> None:
    """Add a network instance (Linux namespace) and enable forwarding if needed."""
    logger.info("Setting up %s network instance.", network_instance.id)
    namespace.add(name=network_instance.id, cleanup=cleanup)

    # IPv6 and IPv4 routing is enabled on the network instance only for CORE
    # and DOWNLINK.
    if network_instance.type in [
        models.NetworkInstanceType.CORE,
        models.NetworkInstanceType.DOWNLINK,
    ]:
        proc = subprocess.run(  # noqa: S602
            f"""
            # enable routing
            /usr/sbin/ip netns exec {network_instance.id} sysctl -w net.ipv6.conf.all.forwarding=1
            /usr/sbin/ip netns exec {network_instance.id} sysctl -w net.ipv4.conf.all.forwarding=1
            """,  # noqa: E501
            stdout=subprocess.PIPE,
            shell=True,
            check=True,
        )
        logger.info(proc.args)
        logger.debug(proc.stdout)

    add_network_instance_connection(network_instance)


def delete_network_instance(network_instance: str) -> None:
    """Delete a network instance (Linux namespace)."""
    # run the network instance remove commands
    namespace.delete(network_instance)


def get_network_instance_connections(
    network_instance: models.NetworkInstance,
) -> list[str]:
    """Get all configured connections (interfaces)."""
    # Configured XFRM interfaces for provider connections.
    configured_interfaces: set[str] = {
        connection.intf_name() for connection in network_instance.connections.values()
    }

    return list(configured_interfaces)


def add_network_instance_connection(
    network_instance: models.NetworkInstance,
) -> list[str]:
    """Add configured connections (interfaces).

    Adds connections to the network instance (Linux namespace).
    """
    interfaces: list[str] = []
    for connection in network_instance.connections.values():
        # Add connection
        # TODO@draggeta: delete unused connections as well!!
        try:
            interface = connection.add(
                network_instance=network_instance,
            )
            interfaces.append(interface)
        except ValueError:
            logger.exception(
                "Failed to set up connection '%s' interface(s)",
                connection,
            )
            continue
        add_network_instance_connection_route(network_instance, interface, connection)

    return interfaces


def delete_network_instance_connection(
    network_instance: models.NetworkInstance,
) -> None:
    """Delete unconfigured connections (interfaces).

    Deletes the connection from the network instance (Linux namespace).
    """
    # INTERFACES
    # Get all interfaces in the network instance.
    proc = subprocess.run(  # noqa: S603
        ["/usr/sbin/ip", "-json", "-details", "-netns", network_instance.id, "link"],
        stdout=subprocess.PIPE,
        check=True,
    )
    active_interfaces_ni: list[dict[str, Any]] = json.loads(proc.stdout)

    # Active interfaces connected to the provider not of type veth or loopback.
    active_interfaces: list[dict[str, Any]] = [
        x
        for x in active_interfaces_ni
        if x["link_type"] != "loopback"
        and x.get("linkinfo", {}).get("info_kind") != "veth"
    ]
    # Configured interfaces for connections.
    configured_interfaces = get_network_instance_connections(network_instance)

    remove_cmds = ""
    for active_intf in active_interfaces:
        if active_intf.get("ifname") in configured_interfaces:
            continue
        if not active_intf.get("linkinfo"):
            # Move physical interfaces back to the DEFAULT network instance.
            remove_cmds += f"/usr/sbin/ip -netns {network_instance.id} link set dev {active_intf.get('ifname')} netns 1\n"  # noqa: E501
            continue
        remove_cmds += f"/usr/sbin/ip -netns {network_instance.id} link del dev {active_intf.get('ifname')}\n"

    if remove_cmds:
        # run the commands
        proc = subprocess.run(  # noqa: S602
            remove_cmds,
            capture_output=True,
            shell=True,
            check=False,
        )
        logger.info(proc.args)
        logger.debug(proc.stdout, proc.stderr)


def add_network_instance_connection_route(
    network_instance: models.NetworkInstance,
    interface: str,
    connection: models.Connection,
) -> None:
    """Add configured routes.

    Adds the routes to a connection (interface) in a network instance (Linux namespace).
    """
    # Remove all statically configured routes.
    proc = subprocess.run(  # noqa: S602
        f"""
        /usr/sbin/ip -netns {network_instance.id} -4 route flush dev {interface} protocol static
        /usr/sbin/ip -netns {network_instance.id} -6 route flush dev {interface} protocol static
        """,
        capture_output=True,
        shell=True,
        check=False,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout, proc.stderr)

    route_cmds = ""
    if (
        config.VPNC_SERVICE_CONFIG.mode != models.ServiceMode.HUB
        or network_instance.type != models.NetworkInstanceType.CORE
    ):
        for route6 in connection.routes.ipv6:
            if not route6.via or connection.config.type in [
                models.ConnectionType.IPSEC,
            ]:
                route_cmds += f"/usr/sbin/ip -netns {network_instance.id} -6 route add {route6.to} dev {interface}\n"
                continue
            route_cmds += f"/usr/sbin/ip -netns {network_instance.id} -6 route add {route6.to} via {route6.via} dev {interface}\n"

        for route4 in connection.routes.ipv4:
            if not route4.via or connection.config.type in [
                models.ConnectionType.IPSEC,
            ]:
                route_cmds += f"/usr/sbin/ip -netns {network_instance.id} -4 route add {route4.to} dev {interface}\n"
                continue
            route_cmds += f"/usr/sbin/ip -netns {network_instance.id} -4 route add {route4.to} via {route4.via} dev {interface}\n"

    proc = subprocess.run(  # noqa: S602
        route_cmds,
        capture_output=True,
        shell=True,
        check=False,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout, proc.stderr)


def get_network_instance_nat64_scope(
    network_instance_name: str,
) -> ipaddress.IPv6Network:
    """Return the IPv6 NPTv6 scope for a network instance.

    This scope  is always a /48.
    """
    assert isinstance(config.VPNC_SERVICE_CONFIG, models.ServiceHub)

    ni_info = helpers.parse_downlink_network_instance_name(network_instance_name)

    tenant_ext = ni_info["tenant_ext_str"]  # c, d, e, f
    tenant_id = ni_info["tenant_id"]  # remote identifier
    network_instance_id = ni_info["network_instance_id"]  # connection number

    nat64_prefix = config.VPNC_SERVICE_CONFIG.prefix_downlink_nat64
    nat64_network_address = int(nat64_prefix[0])
    offset = f"0:0:{tenant_ext}:{tenant_id}:{network_instance_id}::"
    nat64_offset = int(IPv6Address(offset))
    nat64_address = IPv6Address(nat64_network_address + nat64_offset)
    return IPv6Network(nat64_address).supernet(new_prefix=96)


def get_network_instance_nptv6_scope(
    network_instance_name: str,
) -> ipaddress.IPv6Network:
    """Return the IPv6 NPTv6 scope for a network instance. This is always a /48."""
    assert isinstance(config.VPNC_SERVICE_CONFIG, models.ServiceHub)

    ni_info = helpers.parse_downlink_network_instance_name(network_instance_name)

    tenant_ext = ni_info["tenant_ext_str"]
    tenant_id = ni_info["tenant_id"]
    network_instance_id = ni_info["network_instance_id"]

    nptv6_superscope = config.VPNC_SERVICE_CONFIG.prefix_downlink_nptv6
    nptv6_network_address = int(nptv6_superscope[0])
    offset = f"{tenant_ext}:{tenant_id}:{network_instance_id}::"
    nptv6_offset = int(IPv6Address(offset))
    nptv6_address = IPv6Address(nptv6_network_address + nptv6_offset)
    return IPv6Network(nptv6_address).supernet(new_prefix=48)


def add_network_instance_link(
    network_instance: models.NetworkInstance,
) -> None:
    """Create a link and routes between a DOWNLINK and the CORE network instance."""
    veth_c = f"{network_instance.id}_C"
    veth_d = f"{network_instance.id}_D"

    cmds_ns_link = f"""
    # add veth interfaces between CORE and DOWNLINK network instance
    /usr/sbin/ip -netns {config.CORE_NI} link add {veth_c} type veth peer name {veth_d} netns {network_instance.id}
    # bring veth interfaces up
    /usr/sbin/ip -netns {config.CORE_NI} link set dev {veth_c} up
    /usr/sbin/ip -netns {network_instance.id} link set dev {veth_d} up
    # assign IP addresses to veth interfaces
    /usr/sbin/ip -netns {config.CORE_NI} -6 address add fe80::/64 dev {veth_c}
    /usr/sbin/ip -netns {network_instance.id} -6 address add fe80::1/64 dev {veth_d}
    """  # noqa: E501

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.ENDPOINT:
        cmds_ns_link += f"""
        /usr/sbin/ip -netns {config.CORE_NI} address add 169.254.0.1/30 dev {veth_c}
        /usr/sbin/ip -netns {network_instance.id} address add 169.254.0.2/30 dev {veth_d}
        /usr/sbin/ip -netns {config.CORE_NI} -4 route add default via 169.254.0.2 dev {veth_c}
        /usr/sbin/ip -netns {config.CORE_NI} -6 route add default via fe80::1 dev {veth_c}
        """

    proc = subprocess.run(  # noqa: S602
        cmds_ns_link,
        capture_output=True,
        shell=True,
        check=False,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout, proc.stderr)

    cross_ni_routes = ""
    core_ni = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    # add route from DOWNLINK to MGMT/uplink network via CORE network instance
    for connection in core_ni.connections.values():
        for route6 in connection.routes.ipv6:
            cross_ni_routes += f"/usr/sbin/ip -netns {network_instance.id} route add {route6.to} via fe80:: dev {veth_d}\n"  # noqa: E501
        if config.VPNC_SERVICE_CONFIG.mode != models.ServiceMode.HUB:
            for route4 in connection.routes.ipv4:
                cross_ni_routes += f"/usr/sbin/ip -netns {network_instance.id} route add {route4.to} via 169.254.0.1 dev {veth_d}\n"  # noqa: E501
        if cross_ni_routes:
            proc = subprocess.run(  # noqa: S602
                cross_ni_routes,
                capture_output=True,
                shell=True,
                check=False,
            )
            logger.info(proc.args)
            logger.debug(proc.stdout, proc.stderr)


def delete_network_instance_link(network_instance_name: str) -> None:
    """Delete a link (and routes) between a DOWNLINK and the CORE network instance."""
    # run the netns remove commands
    proc = subprocess.run(  # noqa: S602
        f"""
        # remove veth interfaces
        /usr/sbin/ip --brief -netns {network_instance_name} link show type veth |
            awk -F '@' '{{print $1}}' |
            xargs -I {{}} sudo /usr/sbin/ip -netns {network_instance_name} link del {{}}
        # remove NAT64
        /usr/sbin/ip netns exec {network_instance_name} jool instance remove {network_instance_name}
        """,  # noqa: E501
        capture_output=True,
        shell=True,
        check=False,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout, proc.stderr)
