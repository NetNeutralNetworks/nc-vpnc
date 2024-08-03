"""
Functions to make connections easier.
"""

from __future__ import annotations

import json
import logging
import subprocess
from ipaddress import IPv6Address, IPv6Network
from typing import Any

from .. import config, helpers, models
from ..network import namespace

logger = logging.getLogger("vpnc")


def add_network_instance(
    network_instance: models.NetworkInstance, cleanup=False
) -> None:
    """
    Add a network instance (Linux namespace) and enable forwarding if needed.
    """
    logger.info("Setting up %s network instance.", network_instance.name)
    namespace.add(name=network_instance.name, cleanup=cleanup)

    # IPv6 and IPv4 routing is enabled on the network instance only for CORE and DOWNLINK .
    if network_instance.type in [
        models.NetworkInstanceType.CORE,
        models.NetworkInstanceType.DOWNLINK,
    ]:
        subprocess.run(
            f"""
            # enable routing
            ip netns exec {network_instance.name} sysctl -w net.ipv6.conf.all.forwarding=1
            ip netns exec {network_instance.name} sysctl -w net.ipv4.conf.all.forwarding=1
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=True,
        )

    add_network_instance_connection(network_instance)


def delete_network_instance(network_instance: str) -> None:
    """
    Delete a network instance (Linux namespace).
    """
    # run the network instance remove commands
    namespace.delete(network_instance)


def get_network_instance_connections(
    network_instance: models.NetworkInstance,
) -> list[str]:
    """
    Get all configured connections (interfaces) for a network instance (Linux) namespace.
    """

    # Configured XFRM interfaces for provider connections.
    configured_interfaces: set[str] = {
        connection.config.intf_name(connection_id)
        for connection_id, connection in enumerate(network_instance.connections)
    }

    return list(configured_interfaces)


def add_network_instance_connection(
    network_instance: models.NetworkInstance,
) -> list[str]:
    """
    Add configured connections (interfaces) to the network instance (Linux namespace).
    """
    interfaces: list[str] = []
    for idx, connection in enumerate(network_instance.connections):
        # Add connection
        # TODO: delete unused connections as well!!
        try:
            interface = connection.config.add(
                network_instance=network_instance,
                connection_id=idx,
                connection=connection,
            )
            interfaces.append(interface)
        except ValueError:
            logger.error(
                "Failed to set up connection '%s' interface(s)",
                connection,
                exc_info=True,
            )
            continue
        add_network_instance_connection_route(network_instance, interface, connection)

    return interfaces


def delete_network_instance_connection(
    network_instance: models.NetworkInstance,
) -> None:
    """
    Delete unconfigured connections (interfaces) from the network instance (Linux namespace).
    """
    # INTERFACES
    # Get all interfaces in the network instance.
    output_active_interfaces: str = subprocess.run(
        f"ip -j -d -n {network_instance.name} link",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    active_interfaces_ni: dict = json.loads(output_active_interfaces)

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
            remove_cmds += f"ip -n {network_instance.name} link set dev {active_intf.get('ifname')} netns 1\n"
            continue
        remove_cmds += (
            f"ip -n {network_instance.name} link del dev {active_intf.get('ifname')}\n"
        )

    if remove_cmds:
        # run the commands
        subprocess.run(
            remove_cmds,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )


def add_network_instance_connection_route(
    network_instance: models.NetworkInstance,
    interface: str,
    connection: models.Connection,
) -> None:
    """
    Add configured routes for a connection (interface) in a network instance (Linux namespace).
    """

    flush_output = subprocess.run(
        f"""
        ip -n {network_instance.name} -4 route flush dev {interface} protocol static
        ip -n {network_instance.name} -6 route flush dev {interface} protocol static
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(flush_output.args)
    logger.info(flush_output.stdout.decode())
    route_cmds = ""
    if network_instance.type == models.NetworkInstanceType.DOWNLINK:
        route_cmds += f"""
            ip -n {network_instance.name} -4 route add default dev {interface}
            ip -n {network_instance.name} -6 route add default dev {interface}
        """

    for route in connection.routes.ipv6:
        if not route.via or connection.config.type in [models.ConnectionType.IPSEC]:
            route_cmds += f"ip -n {network_instance.name} -6 route add {route.to} dev {interface}\n"
            continue
        route_cmds += f"ip -n {network_instance.name} -6 route add {route.to} via {route.via} dev {interface}\n"

    for route in connection.routes.ipv4:
        if not route.via or connection.config.type in [models.ConnectionType.IPSEC]:
            route_cmds += f"ip -n {network_instance.name} -4 route add {route.to} dev {interface}\n"
            continue
        route_cmds += f"ip -n {network_instance.name} -4 route add {route.to} via {route.via} dev {interface}\n"

    output = subprocess.run(
        route_cmds,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(output.args)
    logger.info(output.stdout.decode())


def add_network_instance_nat64(network_instance: models.NetworkInstance) -> None:
    """
    Add NAT64 rules to a network instance (Linux namespace).
    """
    # Configure NAT-PT and NAT64
    if config.VPNC_SERVICE_CONFIG.mode != models.ServiceMode.HUB:
        return

    ni_info = helpers.parse_downlink_network_instance_name(network_instance.name)

    pdn64 = config.VPNC_SERVICE_CONFIG.prefix_downlink_nat64
    # outputs fdcc:0:c::/48
    pdn64_3 = list(pdn64.subnets(new_prefix=48))[ni_info["tenant_ext"]]
    # outputs fdcc:0:c:1::/64
    pdn64_4 = list(pdn64_3.subnets(new_prefix=64))[ni_info["tenant_id"]]
    # outputs fdcc:0:c:1:1::/80
    pdn64_5 = list(pdn64_4.subnets(new_prefix=80))[ni_info["network_instance_id"]]
    # outputs fdcc:0:c:1:1::/96
    downlink_nat64_space = list(pdn64_5.subnets(new_prefix=96))[0]

    # configure NAT64 for the DOWNLINK network instance
    output_nat64 = subprocess.run(
        f"""
        # start NAT64
        ip netns exec {network_instance.name} jool instance flush
        ip netns exec {network_instance.name} jool instance add {network_instance.name} --netfilter --pool6 {downlink_nat64_space}
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(output_nat64.args)
    logger.info(output_nat64.stdout.decode())


def get_network_instance_natpt_networks(
    network_instance: models.NetworkInstance,
) -> tuple[bool, list[models.NatPrefixTranslation]]:
    """
    Calculates the NAT-PT translations to perform for a network instance (Linux namespace).
    """

    natpt_list: list[models.NatPrefixTranslation] = []
    updated = False
    if config.VPNC_SERVICE_CONFIG.mode != models.ServiceMode.HUB:
        return updated, natpt_list

    # Get NAT-PT prefix for this network instance
    natpt_superscope = config.VPNC_SERVICE_CONFIG.prefix_downlink_natpt
    ni_info = helpers.parse_downlink_network_instance_name(network_instance.name)

    tenant_ext = ni_info["tenant_ext_str"]
    tenant_id = ni_info["tenant_id"]
    network_instance_id = ni_info["network_instance_id"]

    natpt_network_address = int(natpt_superscope[0])
    natpt_offset = int(IPv6Address(f"{tenant_ext}:{tenant_id}:{network_instance_id}::"))
    natpt_address = IPv6Address(natpt_network_address + natpt_offset)
    natpt_scope = IPv6Network(natpt_address).supernet(new_prefix=48)

    for connection in network_instance.connections:
        natpt_list.extend(connection.natpt)

    # Calculate how to perform the NAT-PT translation.
    for configured_natpt in natpt_list:
        natpt_prefix = configured_natpt.remote.prefixlen
        # Check if the translation is possibly correct. This is a basic check
        if (
            configured_natpt.local
            and configured_natpt.remote.netmask == configured_natpt.local.netmask
        ):
            if configured_natpt.local.subnet_of(natpt_scope):
                continue

        for candidate_natpt_prefix in natpt_scope.subnets(new_prefix=natpt_prefix):
            # if the highest IP of the subnet is lower than the most recently added network
            free = True
            for npt in natpt_list:
                if not npt.local:
                    continue
                # Check to be sure that the subnet isn't a supernet. That would break it
                # otherwise.
                if not npt.local.subnet_of(natpt_scope):
                    continue
                if (
                    npt.local[0] >= candidate_natpt_prefix[-1] >= npt.local[-1]
                    or npt.local[0] <= candidate_natpt_prefix[0] <= npt.local[-1]
                ):
                    free = False
                    break

            if not free:
                continue

            configured_natpt.local = candidate_natpt_prefix
            updated = True
            break

    for connection in network_instance.connections:
        natpt_list.extend(connection.natpt)
    return updated, natpt_list


def add_network_instance_link(
    network_instance: models.NetworkInstance,
):
    """
    Creates a link and routes between a DOWNLINK network instance and the CORE network instance.
    """

    veth_c = f"{network_instance.name}_C"
    veth_d = f"{network_instance.name}_D"

    cmds_ns_link = f"""
    # add veth interfaces between CORE and DOWNLINK network instance
    ip -n {config.CORE_NI} link add {veth_c} type veth peer name {veth_d} netns {network_instance.name}
    # bring veth interfaces up
    ip -n {config.CORE_NI} link set dev {veth_c} up
    ip -n {network_instance.name} link set dev {veth_d} up
    # assign IP addresses to veth interfaces
    ip -n {config.CORE_NI} -6 address add fe80::/64 dev {veth_c}
    ip -n {network_instance.name} -6 address add fe80::1/64 dev {veth_d}
    """

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.ENDPOINT:
        cmds_ns_link += f"""
        ip -n {config.CORE_NI} address add 169.254.0.1/30 dev {veth_c}
        ip -n {network_instance.name} address add 169.254.0.2/30 dev {veth_d}
        ip -n {config.CORE_NI} -4 route add default via 169.254.0.2 dev {veth_c}
        ip -n {config.CORE_NI} -6 route add default via fe80::1 dev {veth_c}
        """

    output_ns_link = subprocess.run(
        cmds_ns_link,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(output_ns_link.args)
    logger.info(output_ns_link.stdout.decode())

    cross_ni_routes = ""
    core_ni = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    # add route from DOWNLINK to MGMT/uplink network via CORE network instance
    for connection in core_ni.connections:
        for route6 in connection.routes.ipv6:
            cross_ni_routes += f"ip -n {network_instance.name} route add {route6.to} via fe80:: dev {veth_d}\n"
        if config.VPNC_SERVICE_CONFIG.mode != models.ServiceMode.HUB:
            for route4 in connection.routes.ipv4:
                cross_ni_routes += f"ip -n {network_instance.name} route add {route4.to} via 169.254.0.1 dev {veth_d}\n"
        if cross_ni_routes:
            output_cross_ns_routes = subprocess.run(
                cross_ni_routes,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                check=False,
            )
            logger.info(output_cross_ns_routes.args)
            logger.info(output_cross_ns_routes.stdout.decode())


def delete_network_instance_link(network_instance_name: str):
    """
    Deletes a link (and routes) between a DOWNLINK network instance and the CORE network instance.
    """
    # run the netns remove commands
    output_ni_remove = subprocess.run(
        f"""
        # remove veth interfaces
        ip --brief -n {network_instance_name} link show type veth |
            awk -F '@' '{{print $1}}' |
            xargs -I {{}} sudo ip -n {network_instance_name} link del {{}}
        # remove NAT64
        ip netns exec {network_instance_name} jool instance remove {network_instance_name}
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(output_ni_remove.args)
    logger.info(output_ni_remove.stdout.decode())
