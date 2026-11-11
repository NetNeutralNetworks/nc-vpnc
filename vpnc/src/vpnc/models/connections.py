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
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vpnc.models import enums, info, tenant
from vpnc.models.ipsec import ConnectionConfigIPsec  # noqa: TCH001
from vpnc.models.physical import ConnectionConfigPhysical  # noqa: TCH001
from vpnc.models.ssh import ConnectionConfigSSH
from vpnc.models.wireguard import ConnectionConfigWireGuard  # noqa: TCH001

if TYPE_CHECKING:
    from vpnc.models import network_instance
    from vpnc.models.info import TenantInformation

logger = logging.getLogger("vpnc")

Net = TypeVar("Net", IPv4Network, IPv6Network)


def nth_subnet(network: Net, new_prefix: int, n: int) -> Net:
    """Return subnet n of a network, like list(network.subnets(new_prefix))[n]."""
    if not 0 <= n < 1 << (new_prefix - network.prefixlen):
        msg = f"{network} has no subnet {n} of length /{new_prefix}"
        raise IndexError(msg)
    size = 1 << (network.max_prefixlen - new_prefix)
    return type(network)((int(network.network_address) + n * size, new_prefix))


class Interface(BaseModel):
    """Define interface configuration such as IP addresses."""

    ipv6: list[IPv6Interface] = Field(default_factory=list)
    ipv4: list[IPv4Interface] = Field(default_factory=list)

    @field_validator("ipv6", "ipv4", mode="before")
    @classmethod
    def _coerce_addresses(
        cls,
        v: list[IPv4Interface | IPv6Interface] | None,
    ) -> list[IPv4Interface | IPv6Interface]:
        if v is None:
            return []
        return v


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

    @field_validator("ipv6", "ipv4", mode="before")
    @classmethod
    def _coerce_addresses(
        cls,
        v: list[RouteIPv4 | RouteIPv6] | None,
    ) -> list[RouteIPv4 | RouteIPv6]:
        if v is None:
            return []
        return v


class Connection(BaseModel):
    """Define a connection data structure used in a network instance."""

    model_config = ConfigDict(validate_assignment=True)

    id: int = Field(ge=0, le=9)
    metadata: dict[str, Any] = Field(default_factory=dict)
    interface: Interface = Field(default_factory=Interface)
    routes: Routes = Field(default_factory=Routes)
    config: (
        ConnectionConfigIPsec
        | ConnectionConfigPhysical
        | ConnectionConfigSSH
        | ConnectionConfigWireGuard
    )

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: dict[str, Any] | None) -> dict[str, Any]:
        if v is None:
            return {}
        return v

    @field_validator("interface", mode="before")
    @classmethod
    def _coerce_interface(cls, v: Interface | None) -> Interface:
        if v is None:
            return Interface(ipv6=[], ipv4=[])
        return v

    @field_validator("routes", mode="before")
    @classmethod
    def _coerce_routes(cls, v: Routes | None) -> Routes:
        if v is None:
            return Routes(ipv6=[], ipv4=[])
        return v

    def calc_interface_ip_addresses(
        self,
        network_instance: network_instance.NetworkInstance,
    ) -> tuple[list[IPv4Interface], list[IPv6Interface]]:
        """Calculate Interface IP addresses for a DOWNLINK if not configured."""
        default_tenant = tenant.get_default_tenant()
        is_downlink: bool = network_instance.type == enums.NetworkInstanceType.DOWNLINK
        ni_info: TenantInformation | None = None
        if is_downlink:
            ni_info = info.parse_downlink_network_instance_name(
                network_instance.id,
            )

        if (
            not self.interface.ipv4  # pylint: disable=no-member
            and is_downlink
            and ni_info
            and default_tenant.mode == enums.ServiceMode.HUB
        ):
            pdi4 = default_tenant.prefix_downlink_interface_v4
            network_instance_id = ni_info.network_instance_id
            if network_instance_id is None:
                logger.critical(
                    "Network instance ID should never be None here. "
                    "Something has gone horribly wrong.",
                )
                raise ValueError

            ipv4_ni_network = nth_subnet(pdi4, 24, network_instance_id)
            ipv4_con_network = nth_subnet(ipv4_ni_network, 28, self.id)
            interface_ipv4_address = [
                ipaddress.IPv4Interface(f"{ipv4_con_network[1]}/28"),
            ]
        else:
            interface_ipv4_address = self.interface.ipv4  # pylint: disable=no-member

        if (
            not self.interface.ipv6  # pylint: disable=no-member
            and is_downlink
            and ni_info
            and default_tenant.mode == enums.ServiceMode.HUB
        ):
            network_instance_id = ni_info.network_instance_id
            if network_instance_id is None:
                logger.critical(
                    "Network instance ID should never be None here. "
                    "Something has gone horribly wrong.",
                )
                raise ValueError
            pdi6 = default_tenant.prefix_downlink_interface_v6
            ipv6_ni_network = nth_subnet(pdi6, 48, network_instance_id)
            interface_ipv6_address = [
                ipaddress.IPv6Interface(nth_subnet(ipv6_ni_network, 64, self.id)),
            ]
        else:
            interface_ipv6_address = self.interface.ipv6  # pylint: disable=no-member

        return interface_ipv4_address, interface_ipv6_address

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
