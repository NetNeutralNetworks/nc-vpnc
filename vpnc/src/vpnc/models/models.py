"""
Models used by the services.
"""

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
from typing import Any, Literal

from packaging.version import Version
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_serializer,
    field_validator,
)

from .. import config, helpers
from .enums import NetworkInstanceType, ServiceMode
from .ipsec import ConnectionConfigIPsec
from .physical import ConnectionConfigLocal


class RouteIPv6(BaseModel):
    """
    IPv6 routes
    """

    to: IPv6Network
    via: IPv6Address | None = None
    nptv6: bool = True
    nptv6_prefix: IPv6Network | None = None

    @field_validator("to", mode="before")
    @classmethod
    def _coerce_next_hop(cls, v: Any):
        if v == "default":
            return "::/0"
        return v


class RouteIPv4(BaseModel):
    """
    IPv4 routes
    """

    to: IPv4Network
    via: IPv4Address | None = None

    @field_validator("to", mode="before")
    @classmethod
    def _coerce_next_hop(cls, v: Any):
        if v == "default":
            return "0.0.0.0/0"
        return v


class Routes(BaseModel):
    """
    Routes
    """

    ipv6: list[RouteIPv6] = Field(default_factory=list)
    ipv4: list[RouteIPv4] = Field(default_factory=list)

    @field_validator("ipv6", "ipv4", mode="before")
    @classmethod
    def _coerce_addresses(cls, v: Any):
        if v is None:
            return []
        return v


class Interface(BaseModel):
    """
    Interface configuration such as IP addresses
    """

    ipv6: list[IPv6Interface] = Field(default_factory=list)
    ipv4: list[IPv4Interface] = Field(default_factory=list)

    @field_validator("ipv6", "ipv4", mode="before")
    @classmethod
    def _coerce_addresses(cls, v: Any):
        if v is None:
            return []
        return v


class Connection(BaseModel):
    """
    Defines a connection data structure
    """

    model_config = ConfigDict(validate_assignment=True)

    metadata: dict = Field(default_factory=dict)
    interface: Interface = Field(default_factory=Interface)
    routes: Routes = Field(default_factory=Routes)
    config: ConnectionConfigIPsec | ConnectionConfigLocal

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: Any):
        if v is None:
            return {}
        return v

    @field_validator("interface", mode="before")
    @classmethod
    def _coerce_interface(cls, v: Any):
        if v is None:
            return Interface(ipv6=[], ipv4=[])
        return v

    @field_validator("routes", mode="before")
    @classmethod
    def _coerce_routes(cls, v: Any):
        if v is None:
            return Routes(ipv6=[], ipv4=[])
        return v

    def calculate_ip_addresses(
        self,
        network_instance: "NetworkInstance",
        connection_id: int,
    ) -> tuple[list[IPv4Interface], list[IPv6Interface]]:
        """
        Calculates Interface IP addresses for a DOWNLINK network instance if not configured
        """

        is_downlink: bool = network_instance.type == NetworkInstanceType.DOWNLINK
        if is_downlink:
            parsed_ni = helpers.parse_downlink_network_instance_name(
                network_instance.name
            )
        if (
            not self.interface.ipv4  # pylint: disable=no-member
            and is_downlink
            and isinstance(config.VPNC_SERVICE_CONFIG, ServiceHub)
        ):
            pdi4 = config.VPNC_SERVICE_CONFIG.prefix_downlink_interface_v4
            ipv4_ni_network = list(pdi4.subnets(new_prefix=24))[
                parsed_ni["network_instance_id"]
            ]
            ipv4_con_network = list(ipv4_ni_network.subnets(new_prefix=28))[
                connection_id
            ]
            interface_ipv4_address = [
                ipaddress.IPv4Interface(f"{ipv4_con_network[1]}/28")
            ]

        elif self.interface.ipv4 is None:  # pylint: disable=no-member
            interface_ipv4_address = []
        else:
            interface_ipv4_address = self.interface.ipv4  # pylint: disable=no-member

        if (
            not self.interface.ipv6  # pylint: disable=no-member
            and is_downlink
            and isinstance(config.VPNC_SERVICE_CONFIG, ServiceHub)
        ):
            pdi6 = config.VPNC_SERVICE_CONFIG.prefix_downlink_interface_v6
            ipv6_ni_network = list(pdi6.subnets(new_prefix=48))[
                parsed_ni["network_instance_id"]
            ]
            interface_ipv6_address = [
                ipaddress.IPv6Interface(
                    list(ipv6_ni_network.subnets(new_prefix=64))[connection_id]
                )
            ]
        elif self.interface.ipv6 is None:  # pylint: disable=no-member
            interface_ipv6_address = []
        else:
            interface_ipv6_address = self.interface.ipv6  # pylint: disable=no-member

        return interface_ipv4_address, interface_ipv6_address


class NetworkInstance(BaseModel):
    """
    Defines a network instance data structure
    """

    model_config = ConfigDict(validate_assignment=True)

    name: str
    type: NetworkInstanceType
    metadata: dict = Field(default_factory=dict)

    connections: list[Connection]

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: Any):
        if v is None:
            return {}
        return v


class Tenant(BaseModel):
    """
    Defines a tenant data structure
    """

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    version: Version

    id: str
    name: str
    metadata: dict = Field(default_factory=dict)
    network_instances: dict[str, NetworkInstance] = Field(default_factory=dict)

    @field_validator("version", mode="before")
    @classmethod
    def _coerce_version(cls, v: Any):
        return Version(v)

    @field_serializer("version")
    def _version_to_str(self, v: Version) -> str:
        return str(v)


class BGPGlobal(BaseModel):
    """
    Defines global BGP data structure
    """

    asn: int = 4200000000
    router_id: IPv4Address


class BGPNeighbor(BaseModel):
    """
    Defines a BGP neighbor data structure
    """

    neighbor_asn: int
    neighbor_address: IPv4Address | IPv6Address
    # Optional, lower is more preferred CORE uplink for receiving traffic, defaults to 0, max is 9
    priority: int = Field(0, ge=0, le=9)


class BGP(BaseModel):
    """
    Defines a BGP data structure
    """

    neighbors: list[BGPNeighbor]
    globals: BGPGlobal


class ServiceEndpoint(Tenant):
    """
    Defines a service data structure
    """

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    id: str = "service"
    name: str = "Service"
    mode: Literal[ServiceMode.ENDPOINT] = ServiceMode.ENDPOINT

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = r"%any"

    @field_validator("mode", mode="before")
    @classmethod
    def _coerce_type(cls, v: Any):
        return ServiceMode(v)


class ServiceHub(Tenant):
    """
    Defines a service data structure
    """

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    id: str = "service"
    name: str = "Service"
    mode: Literal[ServiceMode.HUB] = ServiceMode.HUB

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = r"%any"

    # OVERLAY CONFIG
    # IPv4 prefix for downlink interfaces. Must be a /16, will get subnetted into /24s per downlink
    # interface per tunnel.
    prefix_downlink_interface_v4: IPv4Network = IPv4Network("100.64.0.0/10")
    # IPv6 prefix for downlink interfaces. Must be a /48 or larger, will get subnetted into /64s per
    # downlink interface per tunnel.
    prefix_downlink_interface_v6: IPv6Network = IPv6Network("fdcc:cbe::/32")
    # The below are used on the provider side to uniquely adress tenant environments
    # IPv6 prefix for NAT64. Must be a /32 or larger. Will be subnetted into /96s per downlink per
    # tunnel.
    prefix_downlink_nat64: IPv6Network = IPv6Network("64:ff9b::/32")
    # IPv6 prefix for NPTv6. Must be a /12 or larger. Will be subnetted into /48s per downlink per
    # tunnel.
    prefix_downlink_nptv6: IPv6Network = IPv6Network("660::/12")

    ## BGP config
    bgp: BGP

    @field_validator("mode", mode="before")
    @classmethod
    def _coerce_type(cls, v: Any):
        return ServiceMode(v)

    @field_validator("prefix_downlink_interface_v4")
    @classmethod
    def set_default_prefix_downlink_interface_v4(
        cls, v: IPv4Network, _: ValidationInfo
    ) -> IPv4Network:
        """
        Check if the value adheres to the limits.
        """
        if isinstance(v, IPv4Network) and v.prefixlen > 16:
            raise NetmaskValueError(
                "'prefix_downlink_interface_v4' prefix length must be '16' or lower."
            )

        return v

    @field_validator("prefix_downlink_interface_v6")
    @classmethod
    def set_default_prefix_downlink_interface_v6(
        cls, v: IPv6Network, _: ValidationInfo
    ) -> IPv6Network:
        """
        Check if the value adheres to the limits.
        """
        if isinstance(v, IPv6Network) and v.prefixlen > 32:
            raise NetmaskValueError(
                "'prefix_downlink_interface_v6' prefix length must be '32' or lower."
            )

        return v

    @field_validator("prefix_downlink_nat64")
    @classmethod
    def set_default_prefix_downlink_nat64(
        cls, v: IPv6Network, _: ValidationInfo
    ) -> IPv6Network:
        """
        Check if the value adheres to the limits.
        """
        if isinstance(v, IPv6Network) and v.prefixlen > 32:
            raise NetmaskValueError(
                "'prefix_downlink_nat64' prefix length must be '32' or lower."
            )

        return v

    @field_validator("prefix_downlink_nptv6")
    @classmethod
    def set_default_prefix_downlink_nptv6(
        cls, v: IPv6Network, _: ValidationInfo
    ) -> IPv6Network:
        """
        Check if the value adheres to the limits.
        """
        if isinstance(v, IPv6Network) and v.prefixlen > 12:
            raise NetmaskValueError(
                "'prefix_downlink_nptv6' prefix length must be '12' or lower."
            )

        return v


class Service(BaseModel):
    """
    Union type to help with loading config
    """

    service: ServiceHub | ServiceEndpoint
