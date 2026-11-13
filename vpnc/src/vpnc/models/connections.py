"""Models used by the services."""

from __future__ import annotations

import ipaddress
import logging
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator

from vpnc import helpers
from vpnc.models import enums, tenant
from vpnc.models.ipsec import ConnectionConfigIPsec  # noqa: TCH001
from vpnc.models.physical import ConnectionConfigPhysical  # noqa: TCH001
from vpnc.models.ssh import ConnectionConfigSSH
from vpnc.models.wireguard import ConnectionConfigWireGuard  # noqa: TCH001
from vpnc.network import state

if TYPE_CHECKING:
    from vpnc.models import network_instance

logger = logging.getLogger("vpnc")

class Interface(BaseModel):
    """Define interface configuration such as IP addresses."""

    ipv6: list[IPv6Interface] = Field(default_factory=list)
    ipv4: list[IPv4Interface] = Field(default_factory=list)

    _none_as_default = helpers.none_as_default("ipv6", "ipv4")


class RouteIPv4(BaseModel):
    """Define IPv4 routes."""

    to: IPv4Network
    via: IPv4Address | None = None

    @field_validator("to", mode="before")
    @classmethod
    def _coerce_next_hop(cls, v: str) -> str:
        if v == "default":
            return "0.0.0.0/0"
        return v


class RouteIPv6(BaseModel):
    """Define IPv6 routes. Include the option to enable/disable NPTv6 for the route."""

    to: IPv6Network
    via: IPv6Address | None = None
    nptv6: bool = True
    nptv6_prefix: IPv6Network | None = None

    @field_validator("to", mode="before")
    @classmethod
    def _coerce_next_hop(cls, v: str) -> str:
        if v == "default":
            return "::/0"
        return v


class Routes(BaseModel):
    """Define route (IPv4 and IPv6) configuration for a connection."""

    ipv6: list[RouteIPv6] = Field(default_factory=list)
    ipv4: list[RouteIPv4] = Field(default_factory=list)

    _none_as_default = helpers.none_as_default("ipv6", "ipv4")

    @property
    def all(self) -> list[RouteIPv4 | RouteIPv6]:
        """Return the IPv4 and IPv6 routes."""
        return [*self.ipv4, *self.ipv6]


class Connection(BaseModel):
    """Define a connection data structure used in a network instance."""

    model_config = ConfigDict(validate_assignment=True)

    metadata: dict[str, Any] = Field(default_factory=dict)
    # False: admin down. The interface is down; a VPN isn't set up.
    enabled: bool = True
    # None: the interface's default. IPv6 needs 1280.
    mtu: int | None = Field(default=None, ge=1280, le=65535)
    interface: Interface = Field(default_factory=Interface)
    routes: Routes = Field(default_factory=Routes)
    config: (
        ConnectionConfigIPsec
        | ConnectionConfigPhysical
        | ConnectionConfigSSH
        | ConnectionConfigWireGuard
    )

    # Not configured: the network instance sets it from the key.
    _id: int = PrivateAttr()

    def set_id(self, key: int) -> None:
        """Set the number of the connection in its network instance."""
        self._id = key

    @property
    def id(self) -> int:
        """Return the number of the connection in its network instance."""
        return self._id

    _none_as_default = helpers.none_as_default("metadata", "interface", "routes")

    def calc_interface_ip_addresses(
        self,
        network_instance: network_instance.NetworkInstance,
    ) -> tuple[list[IPv4Interface], list[IPv6Interface]]:
        """Calculate Interface IP addresses for a DOWNLINK if not configured."""
        default_tenant = tenant.get_default_tenant()
        interface_ipv4_address = self.interface.ipv4  # pylint: disable=no-member
        interface_ipv6_address = self.interface.ipv6  # pylint: disable=no-member
        if (
            network_instance.type != enums.NetworkInstanceType.DOWNLINK
            or default_tenant.mode != enums.ServiceMode.HUB
        ):
            return interface_ipv4_address, interface_ipv6_address

        if not interface_ipv4_address:
            pdi4 = default_tenant.prefix_downlink_interface_v4
            ipv4_ni_network = helpers.nth_subnet(pdi4, 24, network_instance.number)
            ipv4_con_network = helpers.nth_subnet(ipv4_ni_network, 28, self.id)
            interface_ipv4_address = [
                ipaddress.IPv4Interface(f"{ipv4_con_network[1]}/28"),
            ]

        if not interface_ipv6_address:
            pdi6 = default_tenant.prefix_downlink_interface_v6
            ipv6_ni_network = helpers.nth_subnet(pdi6, 48, network_instance.number)
            ipv6_con_network = helpers.nth_subnet(ipv6_ni_network, 64, self.id)
            interface_ipv6_address = [ipaddress.IPv6Interface(ipv6_con_network)]

        return interface_ipv4_address, interface_ipv6_address

    def ensure_mtu_and_addresses(
        self,
        network_instance: network_instance.NetworkInstance,
        netns: state.Netns,
    ) -> None:
        """Give the connection's interface its MTU and addresses, in its namespace."""
        state.ensure_mtu(
            netns.ipr,
            netns.state,
            self.intf_name(network_instance),
            self.mtu,
        )
        if_ipv4, if_ipv6 = self.calc_interface_ip_addresses(network_instance)
        state.ensure_addresses(
            netns.ipr,
            netns.state,
            self.intf_name(network_instance),
            [*if_ipv4, *if_ipv6],
        )

    def delete_interface(
        self,
        network_instance: network_instance.NetworkInstance,
    ) -> None:
        """Delete the connection's interface."""
        with state.netns(network_instance.id) as netns:
            state.delete_link(netns.ipr, netns.state, self.intf_name(network_instance))

    def add(
        self,
        network_instance: network_instance.NetworkInstance,
    ) -> str:
        """Create a connection."""
        return self.config.add(network_instance, self)

    def delete(
        self,
        network_instance: network_instance.NetworkInstance,
    ) -> None:
        """Delete a connection."""
        return self.config.delete(network_instance, self)

    def name(self, network_instance: network_instance.NetworkInstance) -> str:
        """Return the name of the connection, e.g. C0001-00-0."""
        return f"{network_instance.id}-{self.id}"

    def intf_name(self, network_instance: network_instance.NetworkInstance) -> str:
        """Return the name of the connection's interface."""
        return self.config.intf_name(network_instance, self)


class ConnectionConfig(Protocol):
    """Defines the structure for connection configrations."""

    type: enums.ConnectionType

    def add(
        self,
        network_instance: network_instance.NetworkInstance,
        connection: Connection,
    ) -> str:
        """Create a connection."""
        ...

    def delete(
        self,
        network_instance: network_instance.NetworkInstance,
        connection: Connection,
    ) -> None:
        """Delete a connection."""
        ...

    def intf_name(
        self,
        network_instance: network_instance.NetworkInstance,
        connection: Connection,
    ) -> str:
        """Return the name of the connection interface."""
        ...
