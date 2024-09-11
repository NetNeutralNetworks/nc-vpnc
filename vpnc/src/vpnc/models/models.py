"""Models used by the services."""

from __future__ import annotations

import ipaddress
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    NetmaskValueError,
)
from typing import Any, Literal, Protocol

from packaging.version import Version
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_serializer,
    field_validator,
)
from pydantic_core import PydanticCustomError

from vpnc import config, helpers
from vpnc.models import enums
from vpnc.models.enums import NetworkInstanceType, ServiceMode

# Needed for pydantim ports and type checking
from vpnc.models.ipsec import ConnectionConfigIPsec  # noqa: TCH001
from vpnc.models.physical import ConnectionConfigPhysical  # noqa: TCH001
from vpnc.models.ssh import ConnectionConfigSSH  # noqa: TCH001


class TenantInformation(BaseModel):
    """Contains the parsed tenant/network/connection information."""

    tenant: str
    tenant_ext: int
    tenant_ext_str: str
    tenant_id: int
    tenant_id_str: str
    network_instance: str | None
    network_instance_id: int | None
    connection: str | None
    connection_id: int | None


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


class ConnectionConfig(Protocol):
    """Defines the structure for connection configrations."""

    type: enums.ConnectionType

    def add(self, network_instance: NetworkInstance, connection: Connection) -> str:
        """Create a connection."""
        ...

    def delete(
        self,
        network_instance: NetworkInstance,
        connection: Connection,
    ) -> None:
        """Delete a connection."""
        ...

    def intf_name(self, connection_id: int) -> str:
        """Return the name of the connection interface."""
        ...

    def status_summary(
        self,
        network_instance: NetworkInstance,
        connection_id: int,
    ) -> dict[str, Any]:
        """Get the connection status."""
        ...


class Connection(BaseModel):
    """Define a connection data structure used in a network instance."""

    model_config = ConfigDict(validate_assignment=True)

    id: int = Field(ge=0, le=9)
    metadata: dict[str, Any] = Field(default_factory=dict)
    interface: Interface = Field(default_factory=Interface)
    routes: Routes = Field(default_factory=Routes)
    config: ConnectionConfigIPsec | ConnectionConfigPhysical | ConnectionConfigSSH

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
        network_instance: NetworkInstance,
        connection_id: int,
    ) -> tuple[list[IPv4Interface], list[IPv6Interface]]:
        """Calculate Interface IP addresses for a DOWNLINK if not configured."""
        is_downlink: bool = network_instance.type == NetworkInstanceType.DOWNLINK
        ni_info: TenantInformation | None = None
        if is_downlink:
            ni_info = helpers.parse_downlink_network_instance_name(
                network_instance.id,
            )
        if (
            not self.interface.ipv4  # pylint: disable=no-member
            and is_downlink
            and ni_info
            and isinstance(config.VPNC_CONFIG_SERVICE, ServiceHub)
        ):
            pdi4 = config.VPNC_CONFIG_SERVICE.prefix_downlink_interface_v4

            assert isinstance(ni_info.network_instance_id, int)

            ipv4_ni_network: IPv4Network = list(pdi4.subnets(new_prefix=24))[
                ni_info.network_instance_id
            ]
            ipv4_con_network = list(ipv4_ni_network.subnets(new_prefix=28))[
                connection_id
            ]
            interface_ipv4_address = [
                ipaddress.IPv4Interface(f"{ipv4_con_network[1]}/28"),
            ]
        else:
            interface_ipv4_address = self.interface.ipv4  # pylint: disable=no-member

        if (
            not self.interface.ipv6  # pylint: disable=no-member
            and is_downlink
            and ni_info
            and isinstance(config.VPNC_CONFIG_SERVICE, ServiceHub)
        ):
            pdi6 = config.VPNC_CONFIG_SERVICE.prefix_downlink_interface_v6
            ipv6_ni_network: IPv6Network = list(pdi6.subnets(new_prefix=48))[
                ni_info.network_instance_id
            ]
            interface_ipv6_address = [
                ipaddress.IPv6Interface(
                    list(ipv6_ni_network.subnets(new_prefix=64))[connection_id],
                ),
            ]
        else:
            interface_ipv6_address = self.interface.ipv6  # pylint: disable=no-member

        return interface_ipv4_address, interface_ipv6_address

    def add(
        self,
        network_instance: NetworkInstance,
    ) -> str:
        """Create a connection."""
        return self.config.add(network_instance, self)

    def delete(
        self,
        network_instance: NetworkInstance,
    ) -> None:
        """Delete a connection."""
        return self.config.delete(network_instance, self)

    def intf_name(self) -> str:
        """Return the name of the connection's interface."""
        return self.config.intf_name(self.id)

    def status_summary(
        self,
        network_instance: NetworkInstance,
    ) -> dict[str, Any]:
        """Get the connection status."""
        return self.config.status_summary(network_instance, self.id)


class NetworkInstance(BaseModel):
    """Define a network instance data structure."""

    model_config = ConfigDict(validate_assignment=True)

    id: str
    type: NetworkInstanceType
    metadata: dict[str, Any] = Field(default_factory=dict)

    connections: dict[int, Connection]

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
        v: dict[int, Connection] | None,
    ) -> dict[int, Connection]:
        """Validate that all connections in the list have unique identifiers."""
        if v is None:
            return {}
        seen_ids: list[int] = []
        for key, connection in v.items():
            connection_id = connection.id
            if connection_id in seen_ids:
                err_type = "unique_list_key"
                msg = "Duplicate connection identifier found."
                raise PydanticCustomError(err_type, msg)
            if connection_id != key:
                err_type = "unique_list_key"
                msg = "Connection identifier doesn't match list key"
                raise PydanticCustomError(err_type, msg)
            seen_ids.append(connection_id)

        return v


class Tenant(BaseModel):
    """Define a tenant data structure."""

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    version: Version

    id: str = Field(pattern=r"^[2-9a-fA-F]\d{4}$")
    name: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    network_instances: dict[str, NetworkInstance] = Field(default_factory=dict)

    @field_validator("version", mode="before")
    @classmethod
    def _coerce_version(cls, v: str) -> Version:
        return Version(v)

    @field_serializer("version")
    def _version_to_str(self, v: Version) -> str:
        return str(v)


class BGPGlobal(BaseModel):
    """Define BGP global data structure."""

    asn: int = 4200000000
    router_id: IPv4Address


class BGPNeighbor(BaseModel):
    """Define a BGP neighbor data structure."""

    neighbor_asn: int
    neighbor_address: IPv4Address | IPv6Address
    # Optional, lower is more preferred CORE uplink for receiving traffic,
    # defaults to 0, max is 9
    priority: int = Field(0, ge=0, le=9)


class BGP(BaseModel):
    """Define a BGP data structure."""

    neighbors: list[BGPNeighbor]
    globals: BGPGlobal


class ServiceEndpoint(Tenant):
    """Define a service data structure."""

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    id: str = "DEFAULT"
    name: str = "DEFAULT"
    mode: Literal[ServiceMode.ENDPOINT] = ServiceMode.ENDPOINT

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = r"%any"

    @field_validator("mode", mode="before")
    @classmethod
    def _coerce_type(cls, v: str) -> ServiceMode:
        return ServiceMode(v)

    @field_validator("id", "name")
    @classmethod
    def _validate_is_default(cls, v: str) -> str:
        if v != "DEFAULT":
            msg = "default_tenant_error"
            raise PydanticCustomError(
                msg,
                "The default tenant id and name should be 'DEFAULT'",
            )
        return v


class ServiceHub(Tenant):
    """Define a service data structure."""

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    id: str = "DEFAULT"
    name: str = "DEFAULT"
    mode: Literal[ServiceMode.HUB] = ServiceMode.HUB

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = r"%any"

    # OVERLAY CONFIG
    # IPv4 prefix for downlink interfaces. Must be a /16, will get subnetted into /24s
    # per downlink interface per tunnel.
    prefix_downlink_interface_v4: IPv4Network = IPv4Network("100.64.0.0/10")
    # IPv6 prefix for downlink interfaces. Must be a /48 or larger, will get subnetted
    # into /64s per downlink interface per tunnel.
    prefix_downlink_interface_v6: IPv6Network = IPv6Network("fdcc:cbe::/32")
    # The below are used on the provider side to uniquely adress tenant environments
    # IPv6 prefix for NAT64. Must be a /32 or larger. Will be subnetted into /96s per
    # downlink per tunnel.
    prefix_downlink_nat64: IPv6Network = IPv6Network("64:ff9b::/32")
    # IPv6 prefix for NPTv6. Must be a /12 or larger. Will be subnetted into /48s per
    # downlink per tunnel.
    prefix_downlink_nptv6: IPv6Network = IPv6Network("660::/12")

    ## BGP config
    bgp: BGP

    @field_validator("mode", mode="before")
    @classmethod
    def _coerce_type(cls, v: str) -> ServiceMode:
        return ServiceMode(v)

    @field_validator("id", "name")
    @classmethod
    def _validate_is_default(cls, v: str) -> str:
        if v != "DEFAULT":
            msg = "default_tenant_error"
            raise PydanticCustomError(
                msg,
                "The default tenant id and name should be 'DEFAULT'",
            )
        return v

    @field_validator("prefix_downlink_interface_v4")
    @classmethod
    def set_default_prefix_downlink_interface_v4(
        cls,
        v: IPv4Network,
        _: ValidationInfo,
    ) -> IPv4Network:
        """Check if the value adheres to the limits."""
        if v.prefixlen > 16:  # noqa: PLR2004
            msg = "'prefix_downlink_interface_v4' prefix length must be '16' or lower."
            raise NetmaskValueError(
                msg,
            )

        return v

    @field_validator("prefix_downlink_interface_v6")
    @classmethod
    def set_default_prefix_downlink_interface_v6(
        cls,
        v: IPv6Network,
        _: ValidationInfo,
    ) -> IPv6Network:
        """Check if the value adheres to the limits."""
        if v.prefixlen > 32:  # noqa: PLR2004
            msg = "'prefix_downlink_interface_v6' prefix length must be '32' or lower."
            raise NetmaskValueError(
                msg,
            )

        return v

    @field_validator("prefix_downlink_nat64")
    @classmethod
    def set_default_prefix_downlink_nat64(
        cls,
        v: IPv6Network,
        _: ValidationInfo,
    ) -> IPv6Network:
        """Check if the value adheres to the limits."""
        if v.prefixlen > 32:  # noqa: PLR2004
            msg = "'prefix_downlink_nat64' prefix length must be '32' or lower."
            raise NetmaskValueError(
                msg,
            )

        return v

    @field_validator("prefix_downlink_nptv6")
    @classmethod
    def set_default_prefix_downlink_nptv6(
        cls,
        v: IPv6Network,
        _: ValidationInfo,
    ) -> IPv6Network:
        """Check if the value adheres to the limits."""
        if v.prefixlen > 12:  # noqa: PLR2004
            msg = "'prefix_downlink_nptv6' prefix length must be '12' or lower."
            raise NetmaskValueError(
                msg,
            )

        return v


class Service(BaseModel):
    """Union type to help with loading config."""

    config: ServiceHub | ServiceEndpoint


class Tenants(BaseModel):
    """Union type to help with loading config."""

    config: dict[str, Tenant]
