"""Functions to make connections easier."""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import time
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)

import pyroute2.netns

from vpnc import config, helpers, models
from vpnc.network import namespace, route
from vpnc.services import routes

logger = logging.getLogger("vpnc")


def set_network_instance(
    network_instance: models.NetworkInstance,
    active_network_instance: models.NetworkInstance | None,
    cleanup: bool = False,  # noqa: FBT001, FBT002
) -> None:
    """Add a network instance (Linux namespace) and enable forwarding if needed."""
    logger.info("Setting up %s network instance.", network_instance.id)
    namespace.add(name=network_instance.id, cleanup=cleanup)

    attempts = 20
    for attempt in range(attempts):
        if network_instance.id in pyroute2.netns.listnetns():
            break
        if attempt == attempts - 1:
            logger.error(
                "Network instance %s did not instantiate correctly. Not configured.",
                network_instance.id,
            )
        time.sleep(0.05)

    if network_instance.type == models.NetworkInstanceType.DOWNLINK:
        add_network_instance_link(network_instance)
    routes.start(network_instance.id)

    # IPv6 and IPv4 routing is enabled on the network instance only for CORE
    # and DOWNLINK.
    if network_instance.type in (
        models.NetworkInstanceType.CORE,
        models.NetworkInstanceType.DOWNLINK,
    ):
        proc = subprocess.run(
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

    set_network_instance_connection(network_instance, active_network_instance)


def delete_network_instance(network_instance: str) -> None:
    """Delete a network instance (Linux namespace)."""
    # run the network instance remove commands
    namespace.delete(network_instance)
    routes.stop(network_instance)


def get_network_instance_connections(
    network_instance: models.NetworkInstance,
) -> list[str]:
    """Get all configured connections (interfaces)."""
    configured_interfaces: set[str] = {
        connection.intf_name() for connection in network_instance.connections.values()
    }

    return list(configured_interfaces)


def set_network_instance_connection(
    network_instance: models.NetworkInstance,
    active_network_instance: models.NetworkInstance | None,
) -> list[str]:
    """Add configured connections (interfaces).

    Adds connections to the network instance (Linux namespace).
    """
    interfaces: list[str] = []
    if active_network_instance:
        delete_network_instance_connection(network_instance, active_network_instance)
    ni_dl = pyroute2.NetNS(network_instance.id)
    ni_core = pyroute2.NetNS(config.CORE_NI)
    with ni_dl, ni_core:
        for connection in network_instance.connections.values():
            active_connection = None
            if active_network_instance and active_network_instance.connections:
                active_connection = active_network_instance.connections.get(
                    connection.id,
                )
            # Add connection
            try:
                interface = connection.add(
                    network_instance=network_instance,
                )
                interfaces.append(interface)
                with routes.ni_locks[network_instance.id]:
                    intf = []
                    if if_idx := ni_dl.link_lookup(ifname=interface):
                        intf = ni_dl.get_links(if_idx[0])
                    connection_state: str = "down"
                    if intf:
                        connection_state = intf[0].get("state")
                    if connection_state == "up":
                        routes.set_routes_up(
                            ni_dl,
                            ni_core,
                            network_instance,
                            connection,
                            active_connection,
                        )
                    else:
                        routes.set_routes_down(
                            ni_dl,
                            ni_core,
                            network_instance,
                            connection,
                            active_connection,
                        )
            except ValueError:
                logger.exception(
                    "Failed to set up connection '%s' interface(s)",
                    connection,
                )
                continue

    return interfaces


def delete_network_instance_connection(
    network_instance: models.NetworkInstance,
    active_network_instance: models.NetworkInstance,
) -> None:
    """Delete unconfigured connections (interfaces).

    Deletes the connection from the network instance (Linux namespace).
    """
    active_connections = list(active_network_instance.connections.values())

    # Configured interfaces for connections.
    configured_connections = get_network_instance_connections(network_instance)

    for active_connection in active_connections:
        interface_name = active_connection.intf_name()
        if not interface_name:
            continue
        if interface_name in configured_connections:
            continue

        active_connection.delete(active_network_instance)


def get_network_instance_nat64_scope(
    network_instance_name: str,
) -> ipaddress.IPv6Network | None:
    """Return the IPv6 NPTv6 scope for a network instance.

    This scope  is always a /48.
    """
    if network_instance_name in (
        config.CORE_NI,
        config.DEFAULT_NI,
        config.EXTERNAL_NI,
    ):
        return None

    if not isinstance(config.VPNC_CONFIG_SERVICE, models.ServiceHub):
        return None

    ni_info = helpers.parse_downlink_network_instance_name(network_instance_name)

    tenant_ext = ni_info.tenant_ext_str  # c, d, e, f
    tenant_id = ni_info.tenant_id  # remote identifier
    network_instance_id = ni_info.network_instance_id  # connection number

    nat64_prefix = config.VPNC_CONFIG_SERVICE.prefix_downlink_nat64
    nat64_network_address = int(nat64_prefix[0])
    offset = f"0:0:{tenant_ext}:{tenant_id:x}:{network_instance_id}::"
    nat64_offset = int(IPv6Address(offset))
    nat64_address = IPv6Address(nat64_network_address + nat64_offset)
    return IPv6Network(nat64_address).supernet(new_prefix=96)


def get_network_instance_nptv6_scope(
    network_instance_name: str,
) -> ipaddress.IPv6Network | None:
    """Return the IPv6 NPTv6 scope for a network instance. This is always a /48."""
    if network_instance_name in (config.CORE_NI, config.DEFAULT_NI, config.EXTERNAL_NI):
        return None

    if not isinstance(config.VPNC_CONFIG_SERVICE, models.ServiceHub):
        return None
    assert isinstance(config.VPNC_CONFIG_SERVICE, models.ServiceHub)

    ni_info = helpers.parse_downlink_network_instance_name(network_instance_name)

    tenant_ext = ni_info.tenant_ext_str
    tenant_id = ni_info.tenant_id
    network_instance_id = ni_info.network_instance_id

    nptv6_superscope = config.VPNC_CONFIG_SERVICE.prefix_downlink_nptv6
    nptv6_network_address = int(nptv6_superscope[0])
    offset = f"{tenant_ext}:{tenant_id:x}:{network_instance_id}::"
    nptv6_offset = int(IPv6Address(offset))
    nptv6_address = IPv6Address(nptv6_network_address + nptv6_offset)
    return IPv6Network(nptv6_address).supernet(new_prefix=48)


def add_network_instance_link(
    network_instance: models.NetworkInstance,
) -> None:
    """Create a link and routes between a DOWNLINK and the CORE network instance."""
    veth_c = f"{network_instance.id}_C"
    veth_d = f"{network_instance.id}_D"

    with pyroute2.NetNS(netns=network_instance.id) as ni_dl, pyroute2.NetNS(
        netns=config.CORE_NI,
    ) as ni_core:
        # add veth interfaces between CORE and DOWNLINK network instance
        if not ni_core.link_lookup(ifname=veth_c):
            ni_core.link(
                "add",
                ifname=veth_c,
                kind="veth",
                peer={"ifname": veth_d, "net_ns_fd": network_instance.id},
            )
        # bring veth interfaces up
        ifidx_core: int = ni_core.link_lookup(ifname=veth_c)[0]
        ifidx_dl: int = ni_dl.link_lookup(ifname=veth_d)[0]

        # assign IP addresses to veth interfaces
        ni_core.link("set", index=ifidx_core, state="up")
        ni_dl.link("set", index=ifidx_dl, state="up")

        # assign IP addresses to veth interfaces
        ni_core.addr("replace", index=ifidx_core, address="fe80::", prefixlen=64)
        ni_dl.addr("replace", index=ifidx_dl, address="fe80::1", prefixlen=64)

        if config.VPNC_CONFIG_SERVICE.mode == models.ServiceMode.ENDPOINT:
            # assign IP addresses to veth interfaces
            ni_core.addr(
                "replace",
                index=ifidx_core,
                address="169.254.0.1",
                prefixlen=30,
            )
            ni_dl.addr("replace", index=ifidx_dl, address="169.254.0.2", prefixlen=30)

        core_ni = config.VPNC_CONFIG_SERVICE.network_instances[config.CORE_NI]
        # add route from DOWNLINK to MGMT/uplink network via CORE network instance
        for connection in core_ni.connections.values():
            for route6 in connection.routes.ipv6:
                route.command(
                    ni_dl,
                    "replace",
                    dst=route6.to,
                    gateway=IPv6Address("fe80::"),
                    ifname=veth_d,
                )
            if config.VPNC_CONFIG_SERVICE.mode != models.ServiceMode.HUB:
                for route4 in connection.routes.ipv4:
                    route.command(
                        ni_dl,
                        "replace",
                        dst=route4.to,
                        gateway=IPv4Address("169.254.0.1"),
                        ifname=veth_d,
                    )


def delete_network_instance_link(network_instance_name: str) -> None:
    """Delete a link (and routes) between a DOWNLINK and the CORE network instance."""
    # run the netns remove commands
    proc = subprocess.run(
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


def get_network_instance_nat64_mappings_state(
    network_instance_name: str,
) -> tuple[IPv6Network, IPv4Network] | None:
    """Retrieve the live NAT64 mapping configured in Jool."""
    proc = subprocess.run(
        (
            f"/usr/sbin/ip netns exec {network_instance_name}"
            f" jool --instance {network_instance_name} global display |"
            " grep pool6 |"
            " awk '{ print $2 }'"
        ),
        capture_output=True,
        text=True,
        shell=True,
        check=False,
    )

    if not proc.stdout.strip():
        return None
    try:
        return IPv6Network(proc.stdout.strip()), IPv4Network("0.0.0.0/0")
    except AddressValueError:
        return None


def get_network_instance_nptv6_mappings_state(
    network_instance_name: str,
) -> list[tuple[IPv6Network, IPv6Network]]:
    """Retrieve the live NPTv6 mapping configured in ip6tables."""
    proc = subprocess.run(
        (
            f"/usr/sbin/ip netns exec {network_instance_name}"
            " ip6tables -t nat -L |"
            " grep NETMAP |"
            " awk '{print $5,$6}'"
        ),
        stdout=subprocess.PIPE,
        shell=True,
        check=False,
    )

    output: list[tuple[IPv6Network, IPv6Network]] = []

    if not proc.stdout:
        return output
    try:
        for mapping_str in proc.stdout.decode().strip().split("\n"):
            mapping: list[str] = mapping_str.split()
            local = IPv6Network(mapping[0])
            remote = IPv6Network(mapping[1].split("to:", maxsplit=1)[1])

            output.append((local, remote))
    except AddressValueError:
        return output
    return output
