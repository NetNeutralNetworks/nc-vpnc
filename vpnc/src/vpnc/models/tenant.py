"""Models used by the services."""

from __future__ import annotations

import logging
import re
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
    model_validator,
)
from pydantic_core import PydanticCustomError

from vpnc import config, migration
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


# The network instances of the service (DEFAULT) per mode.
SERVICE_NETWORK_INSTANCES = {
    ServiceMode.HUB: (config.CORE_NI, config.EXTERNAL_NI),
    ServiceMode.ENDPOINT: (config.CORE_NI, config.EXTERNAL_NI, config.ENDPOINT_NI),
}


class Tenant(BaseModel):
    """Define a tenant data structure."""

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    version: Version

    id: str = Field(pattern=config.TENANT_ID_PATTERN)
    name: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    network_instances: dict[
        str,
        NetworkInstanceDownlink | NetworkInstanceCore | NetworkInstanceExternal,
    ] = Field(default_factory=dict)

    @field_validator("version", mode="before")
    @classmethod
    def _coerce_version(cls, v: str) -> Version:
        version = Version(str(v))
        if version != Version(migration.CURRENT):
            raise ValueError(migration.unsupported(v))
        return version

    @field_serializer("version")
    def _version_to_str(self, v: Version) -> str:
        return str(v)

    @field_validator("network_instances", mode="before")
    @classmethod
    def _coerce_keys(cls, v: Any) -> Any:  # noqa: ANN401
        if not isinstance(v, dict):
            return v
        return {network_instance_key(key): value for key, value in v.items()}

    @model_validator(mode="after")
    def _name_network_instances(self) -> Tenant:
        """Name the network instances after the tenant and their key."""
        for key, network_instance in self.network_instances.items():
            self._check_key(key)
            network_instance.set_name(self.id, key)
        return self

    def _check_key(self, key: str) -> None:
        """Refuse keys that aren't a network instance number, e.g. 00."""
        if not re.fullmatch(r"\d{2}", key):
            msg = f"network instance '{key}' should be two digits, e.g. 00"
            raise ValueError(msg)


def network_instance_key(key: Any) -> Any:  # noqa: ANN401
    """Return a network instance key as in the model: YAML reads 00 as 0."""
    return f"{key:02d}" if isinstance(key, int) else key


class BGPGlobal(BaseModel):
    """Define BGP global data structure."""

    asn: int = 4200000000
    router_id: IPv4Address
    bfd: bool = False


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


# The highest prefix length per downlink prefix of a hub.
MAX_PREFIX_LENGTHS = {
    "prefix_downlink_interface_v4": 16,
    "prefix_downlink_interface_v6": 32,
    "prefix_downlink_nat64": 32,
    "prefix_downlink_nptv6": 12,
}


class ServiceTenant(Tenant):
    """What the service (DEFAULT) has in both modes."""

    id: str = config.DEFAULT_TENANT
    name: str = config.DEFAULT_TENANT
    mode: ServiceMode

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = r"%any"

    def _check_key(self, key: str) -> None:
        if key not in SERVICE_NETWORK_INSTANCES[self.mode]:
            msg = f"network instance '{key}' can't be part of {self.id}"
            raise ValueError(msg)

    @field_validator("id", "name")
    @classmethod
    def _validate_is_default(cls, v: str) -> str:
        if v != config.DEFAULT_TENANT:
            msg = "default_tenant_error"
            raise PydanticCustomError(
                msg,
                "The default tenant id and name should be 'DEFAULT'",
            )
        return v


class ServiceEndpoint(ServiceTenant):
    """Define a service data structure."""

    mode: Literal[ServiceMode.ENDPOINT] = ServiceMode.ENDPOINT
    network_instances: dict[
        str,
        NetworkInstanceCore | NetworkInstanceExternal | NetworkInstanceEndpoint,
    ] = Field(default_factory=dict)


class ServiceHub(ServiceTenant):
    """Define a service data structure."""

    mode: Literal[ServiceMode.HUB] = ServiceMode.HUB
    network_instances: dict[
        str,
        NetworkInstanceDownlink | NetworkInstanceCore | NetworkInstanceExternal,
    ] = Field(default_factory=dict)

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

    @field_validator(*MAX_PREFIX_LENGTHS)
    @classmethod
    def _check_prefix_length(
        cls,
        v: IPv4Network | IPv6Network,
        info: ValidationInfo,
    ) -> IPv4Network | IPv6Network:
        maximum = MAX_PREFIX_LENGTHS[str(info.field_name)]
        if v.prefixlen > maximum:
            msg = f"'{info.field_name}' prefix length must be '{maximum}' or lower."
            raise NetmaskValueError(msg)
        return v


class Service(BaseModel):
    """Union type to help with loading config."""

    config: ServiceHub | ServiceEndpoint


class Tenants(BaseModel):
    """Union type to help with loading config."""

    config: Tenant | ServiceHub | ServiceEndpoint


class ConfigurationError(RuntimeError):
    """The service (DEFAULT) configuration is missing or invalid."""


def load_tenant_config(
    path: pathlib.Path,
) -> tuple[
    ServiceHub | ServiceEndpoint | Tenant | None,
    ServiceHub | ServiceEndpoint | Tenant | None,
]:
    """Load the global configuration."""
    logger.info("Loading configuration file from %s.", path)
    if not config.TENANT_RE.match(path.stem):
        logger.error("Invalid filename found in %s. Skipping.", path)
        return None, None
    # Errors are logged without the file's content: it holds secrets.
    try:
        with path.open(encoding="utf-8") as f:
            config_yaml = yaml.safe_load(f)
    except FileNotFoundError:
        logger.critical("Configuration file could not be found at '%s'.", path)
        return None, None
    except (yaml.YAMLError, TypeError) as err:
        mark = getattr(err, "problem_mark", None)
        logger.critical(
            "Configuration is not valid '%s': %s%s.",
            path,
            getattr(err, "problem", None) or type(err).__name__,
            f" at line {mark.line + 1}, column {mark.column + 1}" if mark else "",
        )
        return None, None

    if isinstance(config_yaml, dict):
        config_yaml = migration.upgrade(config_yaml)
    try:
        tenant = Tenants(config=config_yaml).config
    except pydantic_core.ValidationError as err:
        logger.critical(
            "Configuration file '%s' doesn't adhere to the schema:\n%s",
            path,
            "\n".join(
                f"  {'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in err.errors(include_input=False, include_context=False)
            ),
        )
        return None, None

    if tenant.id != path.stem:
        logger.critical(
            "Configuration file '%s' holds the configuration of '%s'. Skipping.",
            path,
            tenant.id,
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
        msg = "Service isn't configured correctly. Data class is not of a service type."
        logger.critical(msg)
        # Exiting here would only end the calling thread, silently.
        raise ConfigurationError(msg)
    return default_tenant
