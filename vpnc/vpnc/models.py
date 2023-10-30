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
from pydantic import BaseModel, Field, ValidationInfo, field_validator
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

    # def __post_init__(self):
    #     self.local = [ip_network(x) for x in self.local]
    #     self.remote = [ip_network(x) for x in self.remote]


class Tunnel(BaseModel):
    """
    Defines a tunnel data structure
    """

    description: str | None = None
    metadata: dict | None = Field(default_factory=dict)
    remote_peer_ip: IPv4Address | IPv6Address
    remote_id: str | None = None
    ike_version: Literal[1, 2] = 2
    ike_proposal: str
    ipsec_proposal: str
    psk: str
    tunnel_ip: IPv4Interface | IPv6Interface | None = None
    # Mutually exclusive with traffic selectors
    routes: set[IPv4Network | IPv6Network] | None = Field(default_factory=set)
    # Mutually exclusive with routes
    traffic_selectors: TrafficSelectors | None = Field(default_factory=TrafficSelectors)

    # def __post_init__(self):
    #     self.description = str(self.description)
    #     self.remote_peer_ip = ip_address(self.remote_peer_ip)
    #     if not self.remote_id:
    #         self.remote_id = str(self.remote_peer_ip)
    #     self.ike_version = int(self.ike_version)
    #     assert self.ike_version in [1, 2]
    #     if self.tunnel_ip:
    #         self.tunnel_ip = ip_interface(self.tunnel_ip)
    #     if isinstance(self.routes, list):
    #         self.routes = [ip_network(x) for x in self.routes]
    #     if isinstance(self.traffic_selectors, dict):
    #         self.traffic_selectors = TrafficSelectors(**self.traffic_selectors)
    #     if self.routes and (
    #         self.traffic_selectors.remote or self.traffic_selectors.local
    #     ):
    #         raise ValueError("Cannot specify both routes and traffic selectors.")


class Remote(BaseModel):
    """
    Defines a remote side data structure
    """

    id: str
    name: str
    metadata: dict = Field(default_factory=dict)
    tunnels: dict[int, Tunnel] = Field(default_factory=dict)

    # def __post_init__(self):
    #     self.id = str(self.id)
    #     self.name = str(self.name)
    #     self.tunnels = {k: Tunnel(**v) for (k, v) in self.tunnels.items()}


class BGP(BaseModel):
    """
    Defines an BGP data structure
    """

    asn: int = 4200000000
    router_id: IPv4Address = IPv4Address("1.0.0.1")

    # def __post_init__(self):
    #     self.asn = int(self.asn)
    #     self.router_id = IPv4Address(self.router_id)


class Uplink(BaseModel):
    """
    Defines an uplink data structure
    """

    # VPN CONFIG
    # Uplink VPNs
    remote_peer_ip: IPv4Address | IPv6Address
    remote_id: str | None = None
    psk: str
    prefix_uplink_tunnel: IPv6Interface | None = None
    asn: int | None = None

    # def __post_init__(self):
    #     self.remote_peer_ip = ip_address(self.remote_peer_ip)
    #     if not self.remote_id:
    #         self.remote_id = str(self.remote_peer_ip)
    #     if self.prefix_uplink_tunnel:
    #         self.prefix_uplink_tunnel = IPv6Interface(self.prefix_uplink_tunnel)
    #     if self.asn:
    #         self.asn = int(self.asn)
    #     if self.asn and not self.prefix_uplink_tunnel:
    #         raise ValueError(
    #             "Prefix for the uplink tunnel must be specified if ASN is specified."
    #         )
    #     if self.prefix_uplink_tunnel and not self.asn:
    #         raise ValueError("ASN must be specified if tunnel prefix is specified.")


class Service(BaseModel):
    """
    Defines a service data structure
    """

    mode: ServiceMode

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
    prefix_uplink: IPv6Network = IPv6Network("fd33::/16")
    # IP prefix for downlinks. Must be a /16, will get subnetted into /24s per downlink tunnel.
    prefix_downlink_v4: IPv4Network = IPv4Network("100.99.0.0/16")
    # IPv6 prefix for downlinks. Must be a /32. Will be subnetted into /96s per downlink per tunnel.
    prefix_downlink_v6: IPv6Network = IPv6Network("fdcc::/32")

    ## BGP config
    # bgp_asn private range is between 4.200.000.000 and 4.294.967.294 inclusive.
    bgp: BGP | None = None

    @field_validator(
        "uplinks", "prefix_uplink", "prefix_downlink_v4", "prefix_downlink_v6", "bgp"
    )
    @classmethod
    def check_endpoint_mode(cls, v: Any, info: ValidationInfo) -> Any:
        mode: ServiceMode = info.data["mode"]
        if mode.name == "ENDPOINT" and v is not None:
            raise PydanticCustomError(
                "service mode error",
                "value for {prop} must be None or unset",
                {"prop": v},
            )

        return v

    # def __post_init__(self):
    #     if self.untrusted_if_ip:
    #         self.untrusted_if_ip = ip_interface(self.untrusted_if_ip)
    #     if self.untrusted_if_gw:
    #         self.untrusted_if_gw = ip_address(self.untrusted_if_gw)


class ServiceHub(Service):
    """
    Defines a hub data structure
    """

    # VPN CONFIG
    # Uplink VPNs
    uplinks: dict[int, Uplink]

    # OVERLAY CONFIG
    # IPv6 prefix for client initiating administration traffic.
    prefix_uplink: IPv6Network = IPv6Network("fd33::/16")
    # IP prefix for downlinks. Must be a /16, will get subnetted into /24s per downlink tunnel.
    prefix_downlink_v4: IPv4Network = IPv4Network("100.99.0.0/16")
    # IPv6 prefix for downlinks. Must be a /32. Will be subnetted into /96s per downlink per tunnel.
    prefix_downlink_v6: IPv6Network = IPv6Network("fdcc::/32")

    ## BGP config
    # bgp_asn private range is between 4.200.000.000 and 4.294.967.294 inclusive.
    bgp: BGP

    # def __post_init__(self):
    #     if self.untrusted_if_ip:
    #         self.untrusted_if_ip = ip_interface(self.untrusted_if_ip)
    #     if self.untrusted_if_gw:
    #         self.untrusted_if_gw = ip_address(self.untrusted_if_gw)
    #     if self.prefix_uplink:
    #         self.prefix_uplink = IPv6Network(self.prefix_uplink)
    #     if self.prefix_downlink_v4:
    #         self.prefix_downlink_v4 = IPv4Network(self.prefix_downlink_v4)
    #     if self.prefix_downlink_v6:
    #         self.prefix_downlink_v6 = IPv6Network(self.prefix_downlink_v6)
    #     if self.uplinks:
    #         for k, v in self.uplinks.items():
    #             if isinstance(v, Uplink):
    #                 self.uplinks[k] = v
    #             elif isinstance(v, dict):
    #                 self.uplinks[k] = Uplink(**v)
    #     if self.bgp and not isinstance(self.bgp, BGP):
    #         self.bgp = BGP(**self.bgp)
