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

from packaging.version import Version
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError


class Initiation(Enum):
    """
    Defines if the VPN connection automatically starts
    """

    INITIATOR = "start"
    RESPONDER = "none"


class ConnectionType(Enum):
    """
    Defines the modes in which the connections can run
    """

    IPSEC = "ipsec"
    LOCAL = "local"


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


class ConnectionIPsec(BaseModel):
    """
    Defines an IPsec data structure
    """

    remote_peer_ip: IPv4Address | IPv6Address
    remote_id: str | None = None
    ike_version: Literal[1, 2] = 2
    ike_proposal: str = "aes256gcm16-prfsha384-ecp384"
    ike_lifetime: int = 86400
    ipsec_proposal: str = "aes256gcm16-prfsha384-ecp384"
    ipsec_lifetime: int = 3600
    initiation: Initiation = Initiation.INITIATOR
    psk: str
    # Mutually exclusive with traffic selectors
    routes: set[IPv4Network | IPv6Network] = Field(default_factory=set)
    # Mutually exclusive with routes
    traffic_selectors: TrafficSelectors = Field(default_factory=TrafficSelectors)

    @field_validator("ike_version", mode="before")
    @classmethod
    def coerce_ike_version(cls, v: Any):
        """
        Coerces strings to integers
        """
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return v

    @field_validator("routes", mode="before")
    @classmethod
    def _coerce_routes(cls, v: Any):
        if not isinstance(v, (set, list)):
            return set()
        return v

    @field_validator("traffic_selectors", mode="before")
    @classmethod
    def _coerce_traffic_selectors(cls, v: Any):
        if v is None:
            return TrafficSelectors(local=set(), remote=set())
        return v

    @model_validator(mode="after")
    def _mutual_exclusive(self) -> "ConnectionIPsec":
        if self.routes and (
            self.traffic_selectors.local or self.traffic_selectors.remote
        ):
            raise ValueError("Cannot specify routes and traffic selectors.")
        return self


class Connection(BaseModel):
    """
    Defines a connection data structure
    """

    model_config = ConfigDict(validate_assignment=True)

    type: ConnectionType = ConnectionType.IPSEC
    description: str | None = None
    metadata: dict = Field(default_factory=dict)
    interface_ip: IPv4Interface | IPv6Interface | None = None
    connection: ConnectionIPsec

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: Any):
        if v is None:
            return {}
        return v


class Remote(BaseModel):
    """
    Defines a remote side data structure
    """

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    version: Version

    id: str
    name: str
    metadata: dict = Field(default_factory=dict)
    connections: dict[int, Connection] = Field(default_factory=dict)

    @field_validator("version", mode="before")
    @classmethod
    def _coerce_version(cls, v: Any):
        return Version(v)

    @field_serializer("version")
    def _version_to_str(self, v: Version) -> str:
        return str(v)

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


class ConnectionUplink(Connection):
    """
    Defines an uplink data structure
    """

    asn: int | None = None
    priority: int = Field(0, ge=0, le=9)


class Routes(BaseModel):
    """
    Routes for a namespace
    """

    to: IPv4Network | IPv6Network | Literal["default"]
    via: IPv4Address | IPv6Address | None = None


class NamespaceConfig(BaseModel):
    """
    Network configuration for a specific namespace
    """

    interface: str
    addresses: list[IPv4Interface | IPv6Interface]
    routes: list[Routes] = Field(default_factory=list)


class Network(BaseModel):
    """
    Defines network configurations
    """

    untrust: NamespaceConfig
    root: NamespaceConfig | None = None


class Service(BaseModel):
    """
    Defines a service data structure
    """

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    mode: ServiceMode = Field(frozen=True)

    version: Version

    network: Network

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = r"%any"
    # Uplink VPNs
    connections: dict[int, ConnectionUplink] | None = None

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

    @field_validator("version", mode="before")
    @classmethod
    def _coerce_version(cls, v: Any):
        return Version(v)

    @field_serializer("version")
    def _version_to_str(self, v: Version) -> str:
        return str(v)

    @field_validator(
        "connections",
        "prefix_uplink",
        "prefix_downlink_v4",
        "prefix_downlink_v6",
        "bgp",
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
