"""Models used by the service for network instances."""

from __future__ import annotations

import logging
import pathlib
import subprocess
import sys
import threading
import time
from abc import abstractmethod
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

import pyroute2
import pyroute2.netns
from jinja2 import Environment, FileSystemLoader
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)
from pydantic_core import PydanticCustomError

import vpnc.shared
from vpnc import config
from vpnc.models import connections, enums, ssh
from vpnc.network import namespace, route
from vpnc.services import configuration, frr, routes, strongswan

# Needed for pydantim ports and type checking
logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


class NetworkInstance(BaseModel):
    """Define a network instance data structure."""

    model_config = ConfigDict(validate_assignment=True)

    id: str
    type: Any
    metadata: dict[str, Any] = Field(default_factory=dict)

    connections: dict[int, connections.Connection]

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: dict[str, Any] | None) -> dict[str, Any]:
        if v is None:
            return {}
        return v

    @field_validator("connections")
    @classmethod
    def validate_connection_id_uniqueness(
        cls,
        v: dict[int, connections.Connection] | None,
    ) -> dict[int, connections.Connection]:
        """Validate that all connections in the list have unique identifiers."""
        if v is None:
            return {}
        seen_ids: list[int] = []
        for key, connection in v.items():
            connection_id = connection.id
            if connection_id != key:
                err_type = "unique_list_key"
                msg = "Connection is duplicated"
                raise PydanticCustomError(err_type, msg)
            seen_ids.append(connection_id)

        return v

    @abstractmethod
    def set(self, active_network_instance: NetworkInstance | None) -> bool:
        """Set a network instance."""
        raise NotImplementedError

    @abstractmethod
    def delete(self) -> None:
        """Delete a network instance."""
        raise NotImplementedError

    @abstractmethod
    def set_iptables(self) -> bool:
        """Add ip(6)table rules for the namespace."""
        raise NotImplementedError

    def set_network_instance(
        self,
        active_network_instance: NetworkInstance | None,
        *,
        cleanup: bool = False,
    ) -> bool:
        """Add a network instance (Linux namespace) and enable forwarding if needed."""
        with vpnc.shared.NI_START_LOCK:
            if self.id not in vpnc.shared.NI_LOCK:
                vpnc.shared.NI_LOCK[self.id] = threading.Lock()

        logger.info("Acquiring lock for %s", self.id)
        with vpnc.shared.NI_LOCK[self.id]:
            if self == active_network_instance:
                logger.debug(
                    "Network instance '%s' is already in the correct state.",
                    self.id,
                )
                return False

            logger.info("Setting up the %s network instance.", self.id)
            namespace.add(name=self.id, cleanup=cleanup)

            attempts = 20
            for attempt in range(attempts):
                if self.id in pyroute2.netns.listnetns():
                    break
                if attempt == attempts - 1:
                    logger.error(
                        "Network instance %s did not instantiate correctly."
                        " Not configured.",
                        self.id,
                    )
                    raise ValueError
                time.sleep(0.05)

            # IPv6 and IPv4 routing is enabled on the network instance only for CORE,
            # DOWNLINK and ENDPOINT.
            if self.type in (
                enums.NetworkInstanceType.CORE,
                enums.NetworkInstanceType.DOWNLINK,
                enums.NetworkInstanceType.ENDPOINT,
            ):
                logger.info(
                    "Enabling network instance %s IPv6 forwarding.",
                    self.id,
                )
                proc = pyroute2.NSPopen(
                    self.id,
                    ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                proc.wait()
                proc.release()

                logger.info(
                    "Enabling network instance %s IPv4 forwarding.",
                    self.id,
                )
                proc = pyroute2.NSPopen(
                    self.id,
                    ["sysctl", "-w", "net.ipv4.conf.all.forwarding=1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                proc.wait()
                proc.release()

            if self.type in (
                enums.NetworkInstanceType.DOWNLINK,
                enums.NetworkInstanceType.ENDPOINT,
            ):
                self._set_network_instance_link()

        routes.start(self.id)
        with vpnc.shared.NI_LOCK[self.id]:
            self._set_network_instance_connections(active_network_instance)

        return False

    def delete_network_instance(self) -> None:
        """Delete a network instance (Linux namespace)."""
        # run the network instance remove commands
        routes.stop(self.id)

        logger.info("Acquiring lock for %s", self.id)
        with vpnc.shared.NI_LOCK[self.id]:
            if self.type in (
                enums.NetworkInstanceType.DOWNLINK,
                enums.NetworkInstanceType.ENDPOINT,
            ):
                self._delete_network_instance_link()

            # Break connections.
            ssh_connections = [
                x
                for x in self.connections.values()
                if x.config.type == enums.ConnectionType.SSH
            ]
            other_connections = [
                x
                for x in self.connections.values()
                if x.config.type != ssh.ConnectionConfigSSH
            ]
            sorted_connections = ssh_connections + other_connections
            for conn in sorted_connections:
                logger.info(
                    "Deleting network instance %s connection %s.",
                    self.id,
                    conn.id,
                )
                conn.delete(self)

            namespace.delete(self.id)

        with vpnc.shared.NI_START_LOCK:
            del vpnc.shared.NI_LOCK[self.id]

    def _get_network_instance_connections(self) -> list[str]:
        """Get all configured connections (interfaces)."""
        configured_interfaces: set[str] = {
            connection.intf_name(self) for connection in self.connections.values()
        }

        return list(configured_interfaces)

    def _set_network_instance_connections(
        self,
        active_network_instance: NetworkInstance | None,
    ) -> None:
        """Add configured connections (interfaces).

        Adds connections to the network instance (Linux namespace).
        """
        interfaces: list[str] = []
        if active_network_instance:
            self._delete_network_instance_connections(
                active_network_instance,
            )
        ni_dl = pyroute2.NetNS(self.id)
        ni_core = pyroute2.NetNS(config.CORE_NI)
        with ni_dl, ni_core:
            for connection in self.connections.values():
                logger.info(
                    "Setting up network instance %s connection %s.",
                    self.id,
                    connection.id,
                )
                active_connection = None
                # Match the configured connection to an active, running connection,
                # if it exists).
                if active_network_instance and active_network_instance.connections:
                    active_connection = active_network_instance.connections.get(
                        connection.id,
                    )
                # Add connection
                try:
                    interface = connection.add(
                        network_instance=self,
                    )
                    interfaces.append(interface)
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
                            self,
                            connection,
                            active_connection,
                        )
                    else:
                        routes.set_routes_down(
                            ni_dl,
                            ni_core,
                            self,
                            connection,
                            active_connection,
                        )
                except (ValueError, Exception):
                    logger.exception(
                        "Failed to set up connection '%s' interface(s)",
                        connection,
                    )
                    continue
                time.sleep(0.01)

    def _delete_network_instance_connections(
        self,
        active_network_instance: NetworkInstance | None,
    ) -> None:
        """Delete unconfigured connections (interfaces).

        Deletes the connection from the network instance (Linux namespace).
        """
        if not active_network_instance:
            return
        active_connections = list(active_network_instance.connections.values())
        # Break connections in reverse order.
        active_connections.reverse()

        # Configured interfaces for connections.
        configured_connections = self._get_network_instance_connections()

        # It is important to break SSH connections first as these always depend on
        # another connection.
        ssh_connections = [
            x for x in active_connections if x.config.type == enums.ConnectionType.SSH
        ]
        other_connections = [
            x for x in active_connections if x.config.type != enums.ConnectionType.SSH
        ]

        sorted_connections = ssh_connections + other_connections

        for conn in sorted_connections:
            logger.info(
                "Deleting network instance %s connection %s.",
                active_network_instance.id,
                conn.id,
            )
            interface_name = conn.intf_name(self)
            if not interface_name:
                continue
            if interface_name in configured_connections:
                continue

            conn.delete(active_network_instance)

    def _set_network_instance_link(
        self,
    ) -> None:
        """Create a link and routes between a DOWNLINK and the CORE network instance."""
        veth_c = f"{self.id}_C"
        veth_d = f"{self.id}_D"

        logger.info(
            "Setting up the connection between %s and the %s network instance",
            self.id,
            config.CORE_NI,
        )
        with pyroute2.NetNS(netns=self.id) as ni_dl, pyroute2.NetNS(
            netns=config.CORE_NI,
        ) as ni_core:
            # add veth interfaces between CORE and DOWNLINK network instance
            logger.info("Adding veth pair %s and %s.", veth_c, veth_d)
            if not ni_core.link_lookup(ifname=veth_c):
                ni_core.link(
                    "add",
                    ifname=veth_c,
                    kind="veth",
                    peer={"ifname": veth_d, "net_ns_fd": self.id},
                )
            # bring veth interfaces up
            logger.info(
                "Setting veth pair %s and %s interface status to up.",
                veth_c,
                veth_d,
            )
            ifidx_core: int = ni_core.link_lookup(ifname=veth_c)[0]
            ifidx_dl: int = ni_dl.link_lookup(ifname=veth_d)[0]

            ni_core.link("set", index=ifidx_core, state="up")
            ni_dl.link("set", index=ifidx_dl, state="up")

            # assign IP addresses to veth interfaces
            logger.info(
                "Setting veth pair %s and %s interface IPv6 addresses.",
                veth_c,
                veth_d,
            )
            ni_core.addr("replace", index=ifidx_core, address="fe80::", prefixlen=64)
            ni_dl.addr("replace", index=ifidx_dl, address="fe80::1", prefixlen=64)

            if config.VPNC_CONFIG_SERVICE.mode == enums.ServiceMode.ENDPOINT:
                # assign IP addresses to veth interfaces
                logger.info(
                    "Setting veth pair %s and %s interface IPv4 addresses.",
                    veth_c,
                    veth_d,
                )
                ni_core.addr(
                    "replace",
                    index=ifidx_core,
                    address="169.254.0.1",
                    prefixlen=30,
                )
                ni_dl.addr(
                    "replace",
                    index=ifidx_dl,
                    address="169.254.0.2",
                    prefixlen=30,
                )

            core_ni = config.VPNC_CONFIG_SERVICE.network_instances[config.CORE_NI]
            # add route from DOWNLINK to MGMT/uplink network via CORE network instance
            for connection in core_ni.connections.values():
                for route6 in connection.routes.ipv6:
                    logger.info(
                        "Setting DOWNLINK to CORE route: %s, gateway fe80::,"
                        " ifname %s interface.",
                        route6.to,
                        veth_d,
                    )
                    route.command(
                        ni_dl,
                        "replace",
                        dst=route6.to,
                        gateway=IPv6Address("fe80::"),
                        ifname=veth_d,
                    )
                if config.VPNC_CONFIG_SERVICE.mode != enums.ServiceMode.HUB:
                    for route4 in connection.routes.ipv4:
                        logger.info(
                            "Setting DOWNLINK to CORE route: %s, gateway 169.254.0.1,"
                            " ifname %s interface.",
                            route4.to,
                            veth_d,
                        )
                        route.command(
                            ni_dl,
                            "replace",
                            dst=route4.to,
                            gateway=IPv4Address("169.254.0.1"),
                            ifname=veth_d,
                        )

    def _delete_network_instance_link(
        self,
    ) -> None:
        """Delete a link between a DOWNLINK and the CORE network instance."""
        # run the netns remove commands
        proc = subprocess.run(  # noqa: S602
            f"""
            # remove veth interfaces
            /usr/sbin/ip --brief -netns {self.id} link show type veth |
                awk -F '@' '{{print $1}}' |
                xargs -I {{}} sudo /usr/sbin/ip -netns {self.id} link del {{}}
            # remove NAT64
            /usr/sbin/ip netns exec {self.id} jool instance remove {self.id}
            """,
            capture_output=True,
            shell=True,
            check=False,
        )
        logger.info(proc.args)
        logger.debug(proc.stdout, proc.stderr)


class NetworkInstanceExternal(NetworkInstance):
    """Define an EXTERNAL network instance data structure."""

    type: Literal[enums.NetworkInstanceType.EXTERNAL] = (
        enums.NetworkInstanceType.EXTERNAL
    )

    def set(
        self,
        active_network_instance: NetworkInstance | None,
    ) -> bool:
        """Set an EXTERNAL network instance."""
        try:
            super().set_network_instance(active_network_instance, cleanup=False)
        except ValueError:
            logger.critical(
                "Setting up the %s network instance failed.",
                config.EXTERNAL_NI,
            )
            sys.exit(1)

        _ = self.set_iptables()

        return False

    def delete(self) -> None:
        """Delete an EXTERNAL network instance."""
        self.delete_network_instance()

    def set_iptables(self) -> bool:
        """Add ip(6)table rules for the EXTERNAL namespace.

        The EXTERNAL network instance blocks all traffic except for IKE, ESP and IPsec.
        """
        iptables_template = TEMPLATES_ENV.get_template("iptables-external.conf.j2")
        iptables_configs = {
            "network_instance_name": self.id,
        }
        iptables_render = iptables_template.render(**iptables_configs)
        logger.info(
            "Configuring network instance %s iptables rules.",
            self.id,
        )
        logger.debug(iptables_render)
        proc = subprocess.run(  # noqa: S602
            iptables_render,
            stdout=subprocess.PIPE,
            shell=True,
            check=True,
        )
        logger.debug(proc.stdout)

        return False


class NetworkInstanceCore(NetworkInstance):
    """Define a CORE network instance data structure."""

    type: Literal[enums.NetworkInstanceType.CORE] = enums.NetworkInstanceType.CORE

    def set(
        self,
        active_network_instance: NetworkInstance | None,
    ) -> bool:
        """Configure the CORE network instance (Linux namespace)."""
        # Set the network instance
        super().set_network_instance(
            active_network_instance,
            cleanup=False,
        )

        # IP(6)TABLES RULES
        _ = self.set_iptables()

        # VPN
        logger.info("Setting up VPN tunnels.")
        strongswan.generate_config(self)

        if config.VPNC_CONFIG_SERVICE.mode == enums.ServiceMode.HUB:
            # FRR
            frr.generate_config()

        return False

    def delete(self) -> None:
        """Delete a CORE network instance."""
        self.delete_network_instance()

    def set_iptables(
        self,
    ) -> bool:
        """Add ip(6)table rules for the CORE network instance.

        The CORE network instance blocks all traffic originating from the DOWNLINK
        network instance (Linux namespace), but does accept traffic originating from
        its uplink.
        """
        interfaces = self._get_network_instance_connections()

        iptables_template = TEMPLATES_ENV.get_template("iptables-core.conf.j2")
        iptables_configs: dict[str, Any] = {
            "mode": config.VPNC_CONFIG_SERVICE.mode,
            "network_instance_name": self.id,
            "interfaces": sorted(interfaces),
        }
        iptables_render = iptables_template.render(**iptables_configs)
        logger.info(
            "Configuring network instance %s iptables rules.",
            self.id,
        )
        logger.debug(iptables_render)
        proc = subprocess.run(  # noqa: S602
            iptables_render,
            stdout=subprocess.PIPE,
            shell=True,
            check=True,
        )
        logger.debug(proc.stdout)

        return False


class NetworkInstanceDownlink(NetworkInstance):
    """Define a DOWNLINK network instance data structure."""

    type: Literal[enums.NetworkInstanceType.DOWNLINK] = (
        enums.NetworkInstanceType.DOWNLINK
    )

    def set(
        self,
        active_network_instance: NetworkInstance | None,
    ) -> bool:
        """Configure the DOWNLINKnetwork instance (Linux namespace)."""
        # Set the network instance
        super().set_network_instance(
            active_network_instance,
            cleanup=True,
        )

        # IP(6)TABLES RULES including NPTv6
        updated = self.set_iptables()

        # Configure NAT64
        self._set_downlink_nat64()

        # VPN
        logger.info("Setting up VPN tunnels.")
        strongswan.generate_config(self)

        return updated

    def delete(self) -> None:
        """Delete a DOWNLINK network instance."""
        self._delete_network_instance_link()
        self.delete_network_instance()

    def set_iptables(self) -> bool:
        """Configure ip(6)table rules for a downlink.

        The DOWNLINK network instance blocks all traffic except for traffic from the
        CORE network instance and ICMPv6.
        """
        mode = config.VPNC_CONFIG_SERVICE.mode
        core_interfaces = [f"{self.id}_D"]
        downlink_interfaces = self._get_network_instance_connections()

        iptables_template = TEMPLATES_ENV.get_template("iptables-downlink.conf.j2")
        updated, nptv6_networks = self._calculate_nptv6_mappings()
        iptables_configs = {
            "mode": mode,
            "network_instance_name": self.id,
            "core_interfaces": sorted(core_interfaces),
            "downlink_interfaces": sorted(downlink_interfaces),
            "nptv6_networks": nptv6_networks,
        }
        iptables_render = iptables_template.render(**iptables_configs)
        logger.info(
            "Configuring network instance %s iptables rules.",
            self.id,
        )
        logger.debug(iptables_render)
        proc = subprocess.run(  # noqa: S602
            iptables_render,
            stdout=subprocess.PIPE,
            shell=True,
            check=True,
        )
        logger.debug(proc.stdout)

        return updated

    def _calculate_nptv6_mappings(
        self,
    ) -> tuple[bool, list[connections.RouteIPv6]]:
        """Calculate the NPTv6 translations for a network instance (Linux namespace)."""
        updated = False
        nptv6_list: list[connections.RouteIPv6] = []
        if config.VPNC_CONFIG_SERVICE.mode != enums.ServiceMode.HUB:
            return updated, nptv6_list

        # Get NPTv6 prefix for this network instance
        if not (
            nptv6_scope := configuration.get_network_instance_nptv6_scope(
                self.id,
            )
        ):
            return updated, []

        # Get only routes that should have NPTv6 performed.
        for connection in self.connections.values():
            nptv6_list.extend(
                [route for route in connection.routes.ipv6 if route.nptv6 is True],
            )

        # Calculate how to perform the NPTv6 translation.
        for configured_nptv6 in nptv6_list:
            nptv6_prefix = configured_nptv6.to.prefixlen
            # Check if the translation is possibly correct. This is a basic check
            if (
                configured_nptv6.nptv6_prefix
                and configured_nptv6.to.prefixlen
                == configured_nptv6.nptv6_prefix.prefixlen
            ):
                if configured_nptv6.nptv6_prefix.subnet_of(nptv6_scope):
                    logger.debug(
                        "Route '%s' already has NPTv6 prefix '%s'",
                        configured_nptv6.to,
                        configured_nptv6.nptv6_prefix,
                    )
                    continue
                logger.warning(
                    (
                        "Route '%s' has invalid NPTv6 prefix '%s' applied."
                        " Not part of assigned scope '%s'. Recalculating"
                    ),
                    configured_nptv6.to,
                    configured_nptv6.nptv6_prefix,
                    nptv6_scope,
                )
                configured_nptv6.nptv6_prefix = None
            if (
                configured_nptv6.nptv6_prefix
                and configured_nptv6.to.prefixlen < nptv6_scope.prefixlen
            ):
                logger.warning(
                    "Route '%s' is too big for NPTv6 scope '%s'. Ignoring",
                    configured_nptv6.to,
                    nptv6_scope,
                )
                continue

            # Calculate the NPTv6 translations if not already calculated.
            for candidate_nptv6_prefix in nptv6_scope.subnets(new_prefix=nptv6_prefix):
                # if the highest IP of the subnet is lower than the most recently
                # added network
                free = True
                for npt in nptv6_list:
                    if not npt.nptv6_prefix:
                        continue
                    # Check to be sure that the subnet isn't a supernet. That would
                    # break it otherwise.
                    if not npt.nptv6_prefix.subnet_of(nptv6_scope):
                        continue
                    # If the addresses overlap, it isn't free and cannot be used.
                    if (
                        npt.nptv6_prefix[0]
                        >= candidate_nptv6_prefix[-1]
                        >= npt.nptv6_prefix[-1]
                        or npt.nptv6_prefix[0]
                        <= candidate_nptv6_prefix[0]
                        <= npt.nptv6_prefix[-1]
                    ):
                        free = False
                        break

                if not free:
                    continue

                configured_nptv6.nptv6_prefix = candidate_nptv6_prefix
                updated = True
                break

        return updated, [x for x in nptv6_list if x.nptv6_prefix]

    def _set_downlink_nat64(self) -> None:
        """Add NAT64 rules to a network instance (Linux namespace)."""
        if config.VPNC_CONFIG_SERVICE.mode != enums.ServiceMode.HUB:
            logger.debug("Not running in hub mode. Not configuring NAT64.")
            return

        if not (nat64_scope := configuration.get_network_instance_nat64_scope(self)):
            logger.warning(
                "No NAT64 scope found for network instance %s",
                self.id,
            )
            return
        # configure NAT64 for the DOWNLINK network instance
        try:
            proc = pyroute2.NSPopen(
                self.id,
                # Stop Strongswan in the EXTERNAL network instance.
                ["jool", "instance", "flush"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info(
                "Executing in network instance %s: %s",
                self.id,
                proc.args,
            )
        finally:
            proc.wait()
            proc.release()
        try:
            logger.info(
                "Configuring network instance %s NAT64 scope %s",
                self.id,
                nat64_scope,
            )
            proc = pyroute2.NSPopen(
                self.id,
                # Stop Strongswan in the EXTERNAL network instance.
                [
                    "jool",
                    "instance",
                    "add",
                    self.id,
                    "--netfilter",
                    "--pool6",
                    str(nat64_scope),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info(
                "Executing in network instance %s: %s",
                self.id,
                proc.args,
            )
        finally:
            proc.wait()
            proc.release()


class NetworkInstanceEndpoint(NetworkInstance):
    """Define am Endpoint network instance data structure."""

    type: Literal[enums.NetworkInstanceType.ENDPOINT] = (
        enums.NetworkInstanceType.ENDPOINT
    )

    def set(
        self,
        active_network_instance: NetworkInstance | None,
    ) -> bool:
        """Configure the DOWNLINKnetwork instance (Linux namespace)."""
        # Set the network instance
        super().set_network_instance(
            active_network_instance,
            cleanup=False,
        )

        # IP(6)TABLES RULES including NPTv6
        self.set_iptables()

        return False

    def delete(self) -> None:
        """Delete a DOWNLINK network instance."""
        self.delete_network_instance()

    def set_iptables(self) -> bool:
        """Configure ip(6)table rules for a downlink.

        The ENDPOINT network instance blocks all traffic except for traffic from the
        CORE network instance and ICMPv6.
        """
        mode = config.VPNC_CONFIG_SERVICE.mode
        core_interfaces = [f"{self.id}_D"]
        downlink_interfaces = self._get_network_instance_connections()

        iptables_template = TEMPLATES_ENV.get_template("iptables-endpoint.conf.j2")
        iptables_configs: dict[str, Any] = {
            "mode": mode,
            "network_instance_name": self.id,
            "core_interfaces": sorted(core_interfaces),
            "downlink_interfaces": sorted(downlink_interfaces),
            "nptv6_networks": [],
        }
        iptables_render = iptables_template.render(**iptables_configs)
        logger.info(
            "Configuring network instance %s iptables rules.",
            self.id,
        )
        logger.debug(iptables_render)
        proc = subprocess.run(  # noqa: S602
            iptables_render,
            stdout=subprocess.PIPE,
            shell=True,
            check=True,
        )
        logger.debug(proc.stdout)

        return False
