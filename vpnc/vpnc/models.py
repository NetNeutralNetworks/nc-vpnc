#!/usr/bin/env python3
"""
Models used by the services.
"""

from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError


def _represent_ipv4_address(dumper: yaml.SafeDumper, node: IPv4Address):
    value = dumper.represent_scalar("tag:yaml.org,2002:str", str(node))
    return value


yaml.SafeDumper.add_representer(
    IPv4Address,
    _represent_ipv4_address,
)


# def _construct_ipv4_address(loader, node):
#     value = loader.construct_scalar(node)
#     return IPv4Address(value)


# yaml.SafeLoader.add_constructor(
#     "tag:yaml.org,2002:python/object/apply:ipaddress.IPv4Address",
#     _construct_ipv4_address,
# )


def _represent_ipv4_network(dumper: yaml.SafeDumper, node: IPv4Network):
    value = dumper.represent_scalar("tag:yaml.org,2002:str", str(node))
    return value


yaml.SafeDumper.add_representer(
    IPv4Network,
    _represent_ipv4_network,
)


# def _construct_ipv4_network(loader: yaml.SafeLoader, node):
#     value = loader.construct_scalar(node)
#     return IPv4Network(value)


# yaml.SafeLoader.add_constructor(
#     "tag:yaml.org,2002:python/object/apply:ipaddress.IPv4Network",
#     _construct_ipv4_network,
# )


def _represent_ipv4_interface(dumper: yaml.SafeDumper, node: IPv4Interface):
    value = dumper.represent_scalar("tag:yaml.org,2002:str", str(node))
    return value


yaml.SafeDumper.add_representer(
    IPv4Interface,
    _represent_ipv4_interface,
)


# def _construct_ipv4_interface(loader: yaml.SafeLoader, node):
#     value = loader.construct_scalar(node)
#     return IPv4Interface(value)


# yaml.SafeLoader.add_constructor(
#     "tag:yaml.org,2002:python/object/apply:ipaddress.IPv4Interface",
#     _construct_ipv4_interface,
# )


def _represent_ipv6_address(dumper: yaml.SafeDumper, node: IPv6Address):
    value = dumper.represent_scalar("tag:yaml.org,2002:str", str(node))
    return value


yaml.SafeDumper.add_representer(
    IPv6Address,
    _represent_ipv6_address,
)


# def _construct_ipv6_address(loader: yaml.SafeLoader, node):
#     value = loader.construct_scalar(node)
#     return IPv6Address(value)


# yaml.SafeLoader.add_constructor(
#     "tag:yaml.org,2002:python/object/apply:ipaddress.IPv6Address",
#     _construct_ipv6_address,
# )


def _represent_ipv6_network(dumper: yaml.SafeDumper, node: IPv6Network):
    value = dumper.represent_scalar("tag:yaml.org,2002:str", str(node))
    return value


yaml.SafeDumper.add_representer(
    IPv6Network,
    _represent_ipv6_network,
)


# def _construct_ipv6_network(loader: yaml.SafeLoader, node):
#     value = loader.construct_scalar(node)
#     return IPv6Network(value)


# yaml.SafeLoader.add_constructor(
#     "tag:yaml.org,2002:python/object/apply:ipaddress.IPv6Network",
#     _construct_ipv6_network,
# )


def _represent_ipv6_interface(dumper: yaml.SafeDumper, node: IPv6Interface):
    value = dumper.represent_scalar("tag:yaml.org,2002:str", str(node))
    return value


yaml.SafeDumper.add_representer(
    IPv6Interface,
    _represent_ipv6_interface,
)


# def _construct_ipv6_interface(loader: yaml.SafeLoader, node):
#     value = loader.construct_scalar(node)
#     return IPv6Interface(value)


# yaml.SafeLoader.add_constructor(
#     "tag:yaml.org,2002:python/object/apply:ipaddress.IPv6Interface",
#     _construct_ipv6_interface,
# )


class Initiation(Enum):
    """
    Defines the modes in which the service can run
    """

    INITIATOR = "start"
    RESPONDER = "none"


class ServiceMode(Enum):
    """
    Defines the modes in which the service can run
    """

    HUB = "hub"
    ENDPOINT = "endpoint"


class TrafficSelectors(BaseModel):
    """
    Defines a traffic selector data structure
    """

    local: set[IPv4Network | IPv6Network] = Field(default_factory=set)
    remote: set[IPv4Network | IPv6Network] = Field(default_factory=set)

    @field_validator("local", "remote", mode="before")
    @classmethod
    def _coerce_traffic_selectors(cls, v: Any):
        if v is None:
            return set()
        return v


class Tunnel(BaseModel):
    """
    Defines a tunnel data structure
    """

    model_config = ConfigDict(validate_assignment=True)

    description: str | None = None
    metadata: dict = Field(default_factory=dict)
    remote_peer_ip: IPv4Address | IPv6Address
    remote_id: str | None = None
    ike_version: Literal[1, 2] = 2
    ike_proposal: str
    ike_lifetime: int = 86400
    ipsec_proposal: str
    ipsec_lifetime: int = 3600
    psk: str
    initiation: Initiation = Initiation.INITIATOR
    tunnel_ip: IPv4Interface | IPv6Interface | None = None
    # Mutually exclusive with traffic selectors
    routes: set[IPv4Network | IPv6Network]
    # Mutually exclusive with routes
    traffic_selectors: TrafficSelectors

    @field_validator("ike_version", mode="before")
    @classmethod
    def coerce_ike_version(cls, v: Any):
        """
        Coerces strings to integers
        """
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return v

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: Any):
        if v is None:
            return {}
        return v

    @field_validator("routes", mode="before")
    @classmethod
    def _coerce_routes(cls, v: Any):
        if not isinstance(v, set):
            return set()
        return v

    @field_validator("traffic_selectors", mode="before")
    @classmethod
    def _coerce_traffic_selectors(cls, v: Any):
        if v is None:
            return TrafficSelectors(local=set(), remote=set())
        return v

    @model_validator(mode="after")
    def mutual_exclusive(self) -> "Tunnel":
        if self.routes and (
            self.traffic_selectors.local or self.traffic_selectors.remote
        ):
            raise ValueError("Cannot specify routes and traffic selectors.")
        return self


class Remote(BaseModel):
    """
    Defines a remote side data structure
    """

    model_config = ConfigDict(validate_assignment=True)

    id: str
    name: str
    metadata: dict = Field(default_factory=dict)
    tunnels: dict[int, Tunnel] = Field(default_factory=dict)

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: Any):
        if v is None:
            return {}
        return v


class BGP(BaseModel):
    """
    Defines an BGP data structure
    """

    asn: int = 4200000000
    router_id: IPv4Address = IPv4Address("1.0.0.1")


class Uplink(BaseModel):
    """
    Defines an uplink data structure
    """

    # VPN CONFIG
    # Uplink VPNs
    description: str | None = None
    metadata: dict | None = Field(default_factory=dict)
    remote_peer_ip: IPv4Address | IPv6Address
    remote_id: str | None = None
    psk: str
    prefix_uplink_tunnel: IPv6Interface | None = None
    asn: int | None = None
    priority: int = Field(0, ge=0, le=9)


class Service(BaseModel):
    """
    Defines a service data structure
    """

    mode: ServiceMode = Field(frozen=True)

    # UNTRUSTED INTERFACE CONFIG
    # Untrusted/outside interface
    untrusted_if_name: str
    # IP address of untrusted/outside interface
    untrusted_if_ip: IPv4Interface | IPv6Interface | None = None
    # Default gateway of untrusted/outside interface
    untrusted_if_gw: IPv4Address | IPv6Address | None = None

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str
    # Uplink VPNs
    uplinks: dict[int, Uplink] | None = None

    # OVERLAY CONFIG
    # IPv6 prefix for client initiating administration traffic.
    prefix_uplink: IPv6Network | None = Field(default=None, validate_default=True)
    # IP prefix for downlinks. Must be a /16, will get subnetted into /24s per downlink tunnel.
    prefix_downlink_v4: IPv4Network | None = Field(default=None, validate_default=True)
    # IPv6 prefix for downlinks. Must be a /32. Will be subnetted into /96s per downlink per tunnel.
    prefix_downlink_v6: IPv6Network | None = Field(default=None, validate_default=True)

    ## BGP config
    # bgp_asn private range is between 4.200.000.000 and 4.294.967.294 inclusive.
    bgp: BGP | None = Field(default=None, validate_default=True)

    @field_validator(
        "uplinks", "prefix_uplink", "prefix_downlink_v4", "prefix_downlink_v6", "bgp"
    )
    @classmethod
    def check_endpoint_mode(cls, v: Any, info: ValidationInfo) -> Any:
        """
        Performs checks for specific items if running in endpoint mode.
        """
        mode: ServiceMode = info.data["mode"]
        if mode.name == "ENDPOINT" and v is not None:
            raise PydanticCustomError(
                "service mode error",
                "value for {prop} must be None or unset",
                {"prop": v},
            )

        return v

    @field_validator("prefix_uplink")
    @classmethod
    def set_default_prefix_uplink(
        cls, v: IPv6Network | None, info: ValidationInfo
    ) -> IPv6Network | None:
        """
        Set the default value based on mode.
        """
        mode: ServiceMode = info.data["mode"]
        if mode.name == "HUB" and v is None:
            # IPv6 prefix for client initiating administration traffic.
            return IPv6Network("fd33::/16")
        if mode.name == "ENDPOINT":
            return None

        return v

    @field_validator("prefix_downlink_v4")
    @classmethod
    def set_default_prefix_downlink_v4(
        cls, v: IPv4Network | None, info: ValidationInfo
    ) -> IPv4Network | None:
        """
        Set the default value based on mode.
        """
        mode: ServiceMode = info.data["mode"]
        if mode.name == "HUB" and v is None:
            # IP prefix for downlinks. Must be a /16, will get subnetted into /24s per downlink tunnel.
            return IPv4Network("100.99.0.0/16")
        if mode.name == "ENDPOINT":
            return None

        return v

    @field_validator("prefix_downlink_v6")
    @classmethod
    def set_default_prefix_downlink_v6(
        cls, v: IPv6Network | None, info: ValidationInfo
    ) -> IPv6Network | None:
        """
        Set the default value based on mode.
        """
        mode: ServiceMode = info.data["mode"]
        if mode.name == "HUB" and v is None:
            # IPv6 prefix for downlinks. Must be a /32. Will be subnetted into /96s per downlink per tunnel.
            return IPv6Network("fdcc::/32")
        if mode.name == "ENDPOINT":
            return None

        return v

    @field_validator("bgp")
    @classmethod
    def set_default_bgp(cls, v: BGP | None, info: ValidationInfo) -> BGP | None:
        """
        Set the default value based on mode.
        """
        mode: ServiceMode = info.data["mode"]
        if mode.name == "HUB" and v is None:
            # IPv6 prefix for downlinks. Must be a /32. Will be subnetted into /96s per downlink per tunnel.
            return BGP()
        if mode.name == "ENDPOINT":
            return None

        return v
