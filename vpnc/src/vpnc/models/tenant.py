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

    config: dict[str, Tenant]


def load_service_config(
    config_path: pathlib.Path,
) -> tuple[
    ServiceHub | ServiceEndpoint,
    ServiceEndpoint | ServiceHub | None,
]:
    """Load the global configuration."""
    logger.info("Loading configuration file from %s.", config_path)
    try:
        with config_path.open(encoding="utf-8") as f:
            try:
                new_cfg_dict = yaml.safe_load(f)
            except (yaml.YAMLError, TypeError):
                logger.critical(
                    "Configuration is not valid '%s'.",
                    config_path,
                    exc_info=True,
                )
                sys.exit(1)
    except FileNotFoundError:
        logger.critical(
            "Configuration file could not be found at '%s'.",
            config_path,
            exc_info=True,
        )
        sys.exit(1)

    try:
        if hasattr(config, "VPNC_CONFIG_SERVICE"):
            active_tenant = config.VPNC_CONFIG_SERVICE.model_copy(deep=True)
            config.VPNC_CONFIG_SERVICE = Service(config=new_cfg_dict).config
        else:
            config.VPNC_CONFIG_SERVICE = Service(config=new_cfg_dict).config
            active_tenant = None
    except pydantic_core.ValidationError:
        logger.critical(
            "Configuration file '%s' doesn't adhere to the schema",
            config_path,
            exc_info=True,
        )
        sys.exit(1)

    return config.VPNC_CONFIG_SERVICE, active_tenant


def load_tenant_config(
    path: pathlib.Path,
) -> tuple[Tenant | None, Tenant | None]:
    """Load tenant configuration."""
    if not config.DOWNLINK_TEN_RE.match(path.stem):
        logger.exception("Invalid filename found in %s. Skipping.", path)
        return None, None

    # Open the configuration file and check if it's valid YAML.
    try:
        with path.open(encoding="utf-8") as f:
            try:
                config_yaml = yaml.safe_load(f)
            except yaml.YAMLError:
                logger.exception("Invalid YAML found in %s. Skipping.", path)
                return None, None
    except FileNotFoundError:
        logger.exception(
            "Configuration file could not be found at '%s'. Skipping",
            path,
        )
        return None, None

    # Parse the YAML file to a DOWNLINK object and validate the input.
    try:
        tenant = Tenant(**config_yaml)
    except (TypeError, ValueError):
        logger.exception(
            "Invalid configuration found in '%s'. Skipping.",
            path,
        )
        return None, None

    if tenant.id != path.stem:
        logger.error(
            (
                "VPN identifier '%s' and configuration file name"
                " '%s' do not match. Skipping."
            ),
            tenant.id,
            path.stem,
        )
        return None, None

    active_tenant = config.VPNC_CONFIG_TENANT.get(tenant.id)
    config.VPNC_CONFIG_TENANT[tenant.id] = tenant

    return tenant, active_tenant
