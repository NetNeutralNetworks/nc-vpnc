"""Models used by the service for network instances."""

from __future__ import annotations

import logging
import pathlib
import re
import subprocess
from abc import abstractmethod
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)
from pydantic_core import PydanticCustomError

from vpnc import config
from vpnc.models import connections, enums, tenant
from vpnc.network import namespace, state
from vpnc.services import configuration, frr, strongswan

# Needed for pydantim ports and type checking
logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)

# Sysctls for network instances that route traffic (CORE, DOWNLINK, ENDPOINT).
#
# keep_addr_on_down: the strongSwan monitor sets XFRM interfaces administratively
# down when their IPsec SA goes away and up again when it returns. By default the
# kernel flushes all global IPv6 addresses from an interface when it goes down and
# doesn't restore them on up (IPv4 addresses are kept). That leaves e.g. the
# uplink XFRM interface without its BGP peering address after an outage, so BGP
# never re-establishes. With keep_addr_on_down=1 the addresses, and their prefix
# routes, survive a down/up. "all" is honoured for every interface in the
# namespace; "default" is set too so newly created interfaces inherit it.
ROUTED_NETWORK_INSTANCE_SYSCTLS = {
    "net.ipv6.conf.all.forwarding": "1",
    "net.ipv4.conf.all.forwarding": "1",
    "net.ipv6.conf.all.keep_addr_on_down": "1",
    "net.ipv6.conf.default.keep_addr_on_down": "1",
}


# Per network instance the last iptables script and the rules it resulted in.
IPTABLES_APPLIED: dict[str, tuple[str, str]] = {}
COUNTERS_RE = re.compile(r"\[\d+:\d+\]")


def _iptables_rules(name: str) -> str:
    """Return the IPv4 and IPv6 rules of a namespace, without comments and counters."""

    def save() -> str:
        return "".join(
            subprocess.run(  # noqa: S603
                [command],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            ).stdout
            for command in ("/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save")
        )

    # Both from one thread in the namespace.
    output = namespace.call(name, save)
    return COUNTERS_RE.sub(
        "",
        "\n".join(line for line in output.splitlines() if not line.startswith("#")),
    )


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
    def delete(self) -> None:
        """Delete a network instance."""
        raise NotImplementedError

    @abstractmethod
    def set_iptables(self) -> bool:
        """Add ip(6)table rules for the namespace."""
        raise NotImplementedError

    def reconcile(self, previous: NetworkInstance | None = None) -> bool:
        """Make the network instance match its configuration; only fixes differences.

        previous is the configuration applied before, to remove what's gone.
        Returns whether the configuration was updated (new NPTv6 prefixes).
        """
        # DOWNLINK namespaces are removed when vpnc stops.
        self._ensure_namespace(cleanup=self.type == enums.NetworkInstanceType.DOWNLINK)
        updated = self.set_iptables()
        self._set_network_instance_connections(previous)
        self._delete_unconfigured_interfaces()
        self._reconcile_services()
        return updated

    def desired_routes(
        self,
        links: dict[str, state.Link],
    ) -> tuple[list[state.Route], list[state.Route]]:
        """Return the routes of the network instance and its routes in CORE.

        A connection's routes go via its interface when it passes traffic, and are
        blackholed otherwise. The advertisements in CORE (IPv6 prefixes and the NAT64
        scope) are only active when all connections of the network instance are up.
        """
        core_link = f"{self.id}_C"
        ni_routes: list[state.Route] = []
        core_routes: list[state.Route] = []

        def route_or_blackhole(dst, gateway, dev, *, up):  # noqa: ANN001, ANN202
            return (
                state.Route(dst, gateway=gateway, dev=dev)
                if up
                else state.Route.blackhole(dst)
            )

        connections_up = {
            conn_id: (link := links.get(conn.intf_name(self))) is not None
            and link.passes_traffic
            for conn_id, conn in self.connections.items()
        }
        all_up = bool(connections_up) and all(connections_up.values())

        for conn_id, conn in self.connections.items():
            up = connections_up[conn_id]
            dev = conn.intf_name(self)
            for route6 in conn.routes.ipv6:
                ni_routes.append(route_or_blackhole(route6.to, route6.via, dev, up=up))
                if (adv6 := self._core_ipv6_advertisement(route6)) is not None:
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
                if self.type == enums.NetworkInstanceType.ENDPOINT:
                    core_routes.append(
                        route_or_blackhole(
                            route4.to,
                            IPv4Address("169.254.0.2"),
                            core_link,
                            up=up,
                        ),
                    )

        nat64_scope = configuration.get_network_instance_nat64_scope(self)
        if nat64_scope and self.type == enums.NetworkInstanceType.DOWNLINK:
            core_routes.append(
                route_or_blackhole(
                    nat64_scope,
                    IPv6Address("fe80::1"),
                    core_link,
                    up=all_up,
                ),
            )

        ni_routes.extend(self._uplink_routes())
        return ni_routes, core_routes

    def _core_ipv6_advertisement(
        self,
        route6: connections.RouteIPv6,
    ) -> IPv6Network | None:
        """Return the prefix advertised in CORE for a connection's IPv6 route."""
        if self.type == enums.NetworkInstanceType.DOWNLINK and route6.nptv6:
            # None until the NPTv6 prefix has been calculated.
            return route6.nptv6_prefix
        if self.type in (
            enums.NetworkInstanceType.DOWNLINK,
            enums.NetworkInstanceType.ENDPOINT,
        ):
            return route6.to
        return None

    def _uplink_routes(self) -> list[state.Route]:
        """Return the routes of a DOWNLINK/ENDPOINT network instance to the uplinks."""
        if self.type not in (
            enums.NetworkInstanceType.DOWNLINK,
            enums.NetworkInstanceType.ENDPOINT,
        ):
            return []
        default_tenant = tenant.get_default_tenant()
        veth = f"{self.id}_D"
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

    def _apply_iptables(self, script: str) -> bool:
        """Run a rendered iptables script, unless it's already in effect.

        The script flushes and rebuilds the rules, so it only runs when the script
        or the rules (e.g. changed by hand) differ from the last run.
        """
        current = _iptables_rules(self.id)
        if IPTABLES_APPLIED.get(self.id) == (script, current):
            return False
        logger.info("Configuring network instance %s iptables rules.", self.id)
        logger.debug(script)
        result = namespace.run(self.id, ["/bin/sh", "-c", script])
        if result.returncode:
            msg = f"Configuring iptables failed: {result.stderr.strip()}"
            raise RuntimeError(msg)
        IPTABLES_APPLIED[self.id] = (script, _iptables_rules(self.id))
        return True

    def _reconcile_services(self) -> None:
        """Reconcile the services of the network instance type (NAT64, VPN, ...)."""

    def _ensure_namespace(self, *, cleanup: bool) -> None:
        """Ensure the namespace, its sysctls and its link to CORE."""
        namespace.add(name=self.id, cleanup=cleanup)
        if not namespace.exists(self.id):
            logger.error(
                "Network instance %s did not instantiate correctly. Not configured.",
                self.id,
            )
            raise ValueError

        # IPv6 and IPv4 routing is enabled on the network instance only for CORE,
        # DOWNLINK and ENDPOINT.
        if self.type in (
            enums.NetworkInstanceType.CORE,
            enums.NetworkInstanceType.DOWNLINK,
            enums.NetworkInstanceType.ENDPOINT,
        ):
            namespace.ensure_sysctls(self.id, ROUTED_NETWORK_INSTANCE_SYSCTLS)

        if self.type in (
            enums.NetworkInstanceType.DOWNLINK,
            enums.NetworkInstanceType.ENDPOINT,
        ):
            self._set_network_instance_link()

    def _delete_unconfigured_interfaces(self) -> None:
        """Delete connection interfaces (XFRM, tun, WireGuard) no longer configured."""
        configured = set(self._get_network_instance_connections())
        with state.netns(self.id) as dl:
            for name, link in list(dl.state.links.items()):
                if link.kind in ("xfrm", "tun", "wireguard") and name not in configured:
                    state.delete_link(dl.ipr, dl.state, name)

    def delete_network_instance(self) -> None:
        """Delete a network instance (Linux namespace)."""
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
            if x.config.type != enums.ConnectionType.SSH
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
        for connection in self.connections.values():
            logger.debug(
                "Setting up network instance %s connection %s.",
                self.id,
                connection.id,
            )
            # Add connection
            try:
                interface = connection.add(
                    network_instance=self,
                )
                interfaces.append(interface)
            except (ValueError, Exception):
                logger.exception(
                    "Failed to set up connection '%s' interface(s)",
                    connection,
                )
                continue

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
            interface_name = conn.intf_name(self)
            if not interface_name or interface_name in configured_connections:
                continue
            logger.info(
                "Deleting network instance %s connection %s.",
                active_network_instance.id,
                conn.id,
            )

            conn.delete(active_network_instance)

    def _set_network_instance_link(
        self,
    ) -> None:
        """Create a link and routes between a DOWNLINK and the CORE network instance."""
        default_tenant = tenant.get_default_tenant()
        veth_c = f"{self.id}_C"
        veth_d = f"{self.id}_D"

        logger.debug(
            "Setting up the connection between %s and the %s network instance",
            self.id,
            config.CORE_NI,
        )
        with (
            state.netns(self.id) as dl,
            state.netns(config.CORE_NI) as core,
        ):
            ni_dl, dl_state = dl.ipr, dl.state
            ni_core, core_state = core.ipr, core.state
            state.ensure_veth(ni_core, core_state, veth_c, veth_d, self.id)
            state.refresh_link(ni_dl, dl_state, veth_d)
            state.ensure_link_state(ni_core, core_state, veth_c, up=True)
            state.ensure_link_state(ni_dl, dl_state, veth_d, up=True)

            # Link-local addresses for routing, and IPv4 in ENDPOINT mode.
            endpoint = default_tenant.mode == enums.ServiceMode.ENDPOINT
            state.ensure_addresses(
                ni_core,
                core_state,
                veth_c,
                [IPv4Interface("169.254.0.1/30")] if endpoint else [],
                [IPv6Interface("fe80::/64")],
            )
            state.ensure_addresses(
                ni_dl,
                dl_state,
                veth_d,
                [IPv4Interface("169.254.0.2/30")] if endpoint else [],
                [IPv6Interface("fe80::1/64")],
            )

    def _delete_network_instance_link(
        self,
    ) -> None:
        """Delete a link between a DOWNLINK and the CORE network instance."""
        with state.netns(self.id) as dl:
            state.delete_link(dl.ipr, dl.state, f"{self.id}_D")
        namespace.run(self.id, ["/usr/bin/jool", "instance", "remove", self.id])


class NetworkInstanceExternal(NetworkInstance):
    """Define an EXTERNAL network instance data structure."""

    type: Literal[enums.NetworkInstanceType.EXTERNAL] = (
        enums.NetworkInstanceType.EXTERNAL
    )

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
        self._apply_iptables(iptables_render)

        return False


class NetworkInstanceCore(NetworkInstance):
    """Define a CORE network instance data structure."""

    type: Literal[enums.NetworkInstanceType.CORE] = enums.NetworkInstanceType.CORE

    def _reconcile_services(self) -> None:
        strongswan.apply(self)
        if tenant.get_default_tenant().mode == enums.ServiceMode.HUB:
            frr.generate_config()

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
        default_tenant = tenant.get_default_tenant()

        interfaces = self._get_network_instance_connections()

        iptables_template = TEMPLATES_ENV.get_template("iptables-core.conf.j2")
        iptables_configs: dict[str, Any] = {
            "mode": default_tenant.mode,
            "network_instance_name": self.id,
            "interfaces": sorted(interfaces),
        }
        iptables_render = iptables_template.render(**iptables_configs)
        self._apply_iptables(iptables_render)

        return False


class NetworkInstanceDownlink(NetworkInstance):
    """Define a DOWNLINK network instance data structure."""

    type: Literal[enums.NetworkInstanceType.DOWNLINK] = (
        enums.NetworkInstanceType.DOWNLINK
    )

    def _reconcile_services(self) -> None:
        self._set_downlink_nat64()
        strongswan.apply(self)

    def delete(self) -> None:
        """Delete a DOWNLINK network instance."""
        self._delete_network_instance_link()
        self.delete_network_instance()

    def set_iptables(self) -> bool:
        """Configure ip(6)table rules for a downlink.

        The DOWNLINK network instance blocks all traffic except for traffic from the
        CORE network instance and ICMPv6.
        """
        default_tenant = tenant.get_default_tenant()

        mode = default_tenant.mode
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
        self._apply_iptables(iptables_render)

        return updated

    def _calculate_nptv6_mappings(
        self,
    ) -> tuple[bool, list[connections.RouteIPv6]]:
        """Calculate the NPTv6 translations for a network instance (Linux namespace)."""
        default_tenant = tenant.get_default_tenant()

        updated = False
        nptv6_list: list[connections.RouteIPv6] = []
        if default_tenant.mode != enums.ServiceMode.HUB:
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
        default_tenant = tenant.get_default_tenant()

        if default_tenant.mode != enums.ServiceMode.HUB:
            logger.debug("Not running in hub mode. Not configuring NAT64.")
            return

        if not (nat64_scope := configuration.get_network_instance_nat64_scope(self)):
            logger.warning(
                "No NAT64 scope found for network instance %s",
                self.id,
            )
            return
        # Configure NAT64 (Jool) only if the instance differs.
        current = namespace.run(
            self.id,
            ["/usr/bin/jool", "-i", self.id, "global", "display", "--csv"],
        )
        if current.returncode == 0:
            if f"pool6,{nat64_scope}" in current.stdout.splitlines():
                return
            namespace.run(self.id, ["/usr/bin/jool", "instance", "remove", self.id])
        logger.info(
            "Configuring network instance %s NAT64 scope %s",
            self.id,
            nat64_scope,
        )
        result = namespace.run(
            self.id,
            [
                "/usr/bin/jool",
                "instance",
                "add",
                self.id,
                "--netfilter",
                "--pool6",
                str(nat64_scope),
            ],
        )
        if result.returncode:
            logger.error(
                "Configuring NAT64 in %s failed: %s",
                self.id,
                result.stderr.strip(),
            )


class NetworkInstanceEndpoint(NetworkInstance):
    """Define am Endpoint network instance data structure."""

    type: Literal[enums.NetworkInstanceType.ENDPOINT] = (
        enums.NetworkInstanceType.ENDPOINT
    )

    def delete(self) -> None:
        """Delete an ENDPOINT network instance."""
        self.delete_network_instance()

    def set_iptables(self) -> bool:
        """Configure ip(6)table rules for a downlink.

        The ENDPOINT network instance blocks all traffic except for traffic from the
        CORE network instance and ICMPv6.
        """
        default_tenant = tenant.get_default_tenant()

        mode = default_tenant.mode
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
        self._apply_iptables(iptables_render)

        return False
