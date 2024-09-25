"""Models used by the services."""

from __future__ import annotations

import logging
import sys
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    NetmaskValueError,
)
from typing import TYPE_CHECKING, Any, Literal

import pydantic_core
import yaml
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

from vpnc import config
from vpnc.models.enums import ServiceMode

# Needed for pydantim ports and type checking
from vpnc.models.network_instance import (
    NetworkInstanceCore,  # noqa: TCH001
    NetworkInstanceDownlink,  # noqa: TCH001
    NetworkInstanceEndpoint,  # noqa: TCH001
    NetworkInstanceExternal,  # noqa: TCH001
)

if TYPE_CHECKING:
    import pathlib

logger = logging.getLogger("vpnc")


class Tenant(BaseModel):
    """Define a tenant data structure."""

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    version: Version

    id: str = Field(pattern=r"^[2-9a-fA-F]\d{4}$")
    name: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    network_instances: dict[
        str,
        NetworkInstanceDownlink | NetworkInstanceCore | NetworkInstanceExternal,
    ] = Field(default_factory=dict)

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
    network_instances: dict[
        str,
        NetworkInstanceCore | NetworkInstanceExternal | NetworkInstanceEndpoint,
    ] = Field(default_factory=dict)

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
    network_instances: dict[
        str,
        NetworkInstanceDownlink | NetworkInstanceCore | NetworkInstanceExternal,
    ] = Field(default_factory=dict)

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

    config: Tenant | ServiceHub | ServiceEndpoint


def load_tenant_config(
    path: pathlib.Path,
) -> tuple[
    ServiceHub | ServiceEndpoint | Tenant | None,
    ServiceHub | ServiceEndpoint | Tenant | None,
]:
    """Load the global configuration."""
    logger.info("Loading configuration file from %s.", path)
    if not config.TENANT_RE.match(path.stem):
        logger.exception("Invalid filename found in %s. Skipping.", path)
        return None, None
    try:
        with path.open(encoding="utf-8") as f:
            try:
                config_yaml = yaml.safe_load(f)
            except (yaml.YAMLError, TypeError):
                logger.critical(
                    "Configuration is not valid '%s'.",
                    path,
                    exc_info=True,
                )
                sys.exit(1)
    except FileNotFoundError:
        logger.critical(
            "Configuration file could not be found at '%s'.",
            path,
            exc_info=True,
        )
        return None, None

    try:
        tenant = Tenants(config=config_yaml).config
    except pydantic_core.ValidationError:
        logger.critical(
            "Configuration file '%s' doesn't adhere to the schema",
            path,
            exc_info=True,
        )
        return None, None

    active_tenant = config.VPNC_CONFIG_TENANT.get(tenant.id)
    # config.VPNC_CONFIG_TENANT[tenant.id] = tenant

    return tenant, active_tenant


def get_default_tenant() -> ServiceHub | ServiceEndpoint:
    """Return the default tenant configuration."""
    if not (default_tenant := config.VPNC_CONFIG_TENANT.get(config.DEFAULT_TENANT)):
        default_tenant, _ = load_tenant_config(
            config.VPNC_A_CONFIG_PATH_SERVICE,
        )
    if not isinstance(
        default_tenant,
        (ServiceHub, ServiceEndpoint),
    ):
        logger.critical(
            "Service isn't configured correctly. Data class is not of a service type.",
        )
        sys.exit(1)
    return default_tenant


def get_tenant(tenant_id: str) -> Tenant | ServiceHub | ServiceEndpoint:
    """Return the default tenant configuration."""
    if not (tenant := config.VPNC_CONFIG_TENANT.get(tenant_id)):
        tenant, _ = load_tenant_config(
            config.VPNC_A_CONFIG_PATH_SERVICE,
        )

    return tenant
