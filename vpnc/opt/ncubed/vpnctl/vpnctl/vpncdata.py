#!/usr/bin/env python3

from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)


@dataclass(kw_only=True)
class TrafficSelectors:
    """
    Defines a traffic selector data structure
    """

    local: list[IPv4Network | IPv6Network]
    remote: list[IPv4Network | IPv6Network]

    def __post_init__(self):
        self.local = [str(ip_network(x)) for x in self.local]
        self.remote = [str(ip_network(x)) for x in self.remote]


@dataclass(kw_only=True)
class Tunnel:
    """
    Defines a tunnel data structure
    """

    description: str | None = None
    metadata: dict | None = None
    remote_peer_ip: IPv4Address | IPv6Address
    remote_id: str | None = None
    ike_version: int = 2
    ike_proposal: str
    ipsec_proposal: str
    psk: str
    tunnel_ip: IPv4Interface | IPv6Interface | None = None
    # Mutually exclusive with traffic selectors
    routes: list[IPv4Network | IPv6Network] | None = None
    # Mutually exclusive with routes
    traffic_selectors: TrafficSelectors | None = None

    def __post_init__(self):
        if not self.remote_id:
            self.remote_id = str(self.remote_peer_ip)
        if isinstance(self.traffic_selectors, dict):
            self.traffic_selectors = TrafficSelectors(**self.traffic_selectors)
        else:
            self.traffic_selectors = TrafficSelectors(local=[], remote=[])
        if self.routes:
            self.routes = [str(ip_network(x)) for x in self.routes]
        else:
            self.routes = []
        if self.routes and (
            self.traffic_selectors.remote or self.traffic_selectors.local
        ):
            raise ValueError("Cannot specify both routes and traffic selectors.")
        self.remote_peer_ip = str(ip_address(self.remote_peer_ip))
        if self.tunnel_ip:
            self.tunnel_ip = str(ip_interface(self.tunnel_ip))


@dataclass(kw_only=True)
class Remote:
    """
    Defines a remote side data structure
    """

    id: str = ""
    name: str = ""
    metadata: dict = field(default_factory=dict)
    tunnels: dict[int, Tunnel] | None = None

    def __post_init__(self):
        if self.tunnels:
            self.tunnels = {k: Tunnel(**v) for (k, v) in self.tunnels.items()}
        else:
            self.tunnels = {}


@dataclass(kw_only=True)
class BGP:
    """
    Defines an BGP data structure
    """

    asn: int = 4200000000
    router_id: IPv4Address = "0.0.0.1"


@dataclass(kw_only=True)
class Uplink:
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

    def __post_init__(self):
        if not self.remote_id:
            self.remote_id = str(self.remote_peer_ip)
        if self.asn and not self.prefix_uplink_tunnel:
            raise ValueError("Prefix for the uplink tunnel must be specified if ASN is specified.")
        if self.prefix_uplink_tunnel and not self.asn:
            raise ValueError("ASN must be specified if tunnel prefix is specified.")


@dataclass(kw_only=True)
class Service:
    """
    Defines a service data structure
    """

    # UNTRUSTED INTERFACE CONFIG
    # Untrusted/outside interface
    untrusted_if_name: str = ""
    # IP address of untrusted/outside interface
    untrusted_if_ip: IPv4Interface | IPv6Interface | None = None
    # Default gateway of untrusted/outside interface
    untrusted_if_gw: IPv4Address | IPv6Address | None = None

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = ""


@dataclass(kw_only=True)
class ServiceHub(Service):
    """
    Defines a hub data structure
    """

    # VPN CONFIG
    # Uplink VPNs
    uplinks: dict[int, Uplink] | None = None

    # OVERLAY CONFIG
    # IPv6 prefix for client initiating administration traffic.
    prefix_uplink: IPv6Network = IPv6Network("fd33::/16")
    ## VPN2MGMT
    ## Tunnel transit prefix for link between trusted namespace and root namespace, must be a /127.
    #prefix_root_tunnel: IPv6Network = IPv6Network("fd33:2:f::/127")
    # IP prefix for downlinks. Must be a /16, will get subnetted into /24s per downlink tunnel.
    prefix_downlink_v4: IPv4Network = IPv4Network("100.99.0.0/16")
    # IPv6 prefix for downlinks. Must be a /32. Will be subnetted into /96s per downlink per tunnel.
    prefix_downlink_v6: IPv6Network = IPv6Network("fdcc::/32")


    ## BGP config
    # bgp_asn private range is between 4.200.000.000 and 4.294.967.294 inclusive.
    bgp: BGP = BGP(asn=0, router_id="0.0.0.0")

    def __post_init__(self):
        if self.uplinks:
            for k, v in self.uplinks.items():
                if isinstance(v, Uplink):
                    self.uplinks[k] = v
                elif isinstance(v, dict):
                    self.uplinks[k] = Uplink(**v)
