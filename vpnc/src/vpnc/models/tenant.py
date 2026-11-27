"""Models used by the services."""

from __future__ import annotations

import logging
import re
from ipaddress import (
    IPv4Network,
    IPv6Network,
    NetmaskValueError,
)
from typing import TYPE_CHECKING, Annotated, Any, Literal

import pydantic_core
import yaml
from packaging.version import Version
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    WithJsonSchema,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from vpnc import config, helpers, migration
from vpnc.models import enums
from vpnc.models.enums import ServiceMode

# Needed for pydantim ports and type checking
from vpnc.models.network_instance import (
    NetworkInstanceCore,
    NetworkInstanceDownlink,
    NetworkInstanceEndpoint,
    NetworkInstanceExternal,
)
from vpnc.models.scalars import (
    Address,
    Address4,
    Int,
    Network4,
    Network6,
    OptionalInt,
)
from vpnc.models.secret import Secret

if TYPE_CHECKING:
    import pathlib
    from collections.abc import Iterable

logger = logging.getLogger("vpnc")


# The network instances of the service (DEFAULT) per mode.
SERVICE_NETWORK_INSTANCES = {
    ServiceMode.HUB: (config.CORE_NI, config.EXTERNAL_NI),
    ServiceMode.ENDPOINT: (config.CORE_NI, config.EXTERNAL_NI, config.ENDPOINT_NI),
}


class Tenant(BaseModel):
    """Define a tenant data structure."""

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    version: Annotated[Version, WithJsonSchema({"type": "string"})]

    id: str = Field(pattern=config.TENANT_ID_PATTERN)
    name: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    # DOWNLINK only: another type would be set up as the service's, e.g. with
    # CORE's XFRM interface ids.
    network_instances: dict[str, NetworkInstanceDownlink] = Field(default_factory=dict)

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
        if not re.fullmatch(r"[0-9]{2}", key):
            msg = f"network instance '{key}' should be two digits, e.g. 00"
            raise ValueError(msg)


def network_instance_key(key: Any) -> Any:  # noqa: ANN401
    """Return a network instance key as in the model: YAML reads 00 as 0."""
    return f"{key:02d}" if isinstance(key, int) else key


class BGPGlobal(BaseModel):
    """Define BGP global data structure."""

    asn: Int = 4200000000
    router_id: Address4
    bfd: bool = False


class BGPNeighbor(BaseModel):
    """Define a BGP neighbor data structure."""

    neighbor_asn: Int
    neighbor_address: Address
    # Of the routes received: higher is preferred for traffic from vpnc.
    local_pref: Int = Field(100, ge=0, le=4294967295)
    # Of the routes advertised: lower is preferred for traffic to vpnc. A
    # blackholed route gets 10 more prepends (max 9: worse than any other hub's
    # path) and the max MED.
    as_path_prepend: Int = Field(0, ge=0, le=9)
    # None: the kernel route's metric, 1024.
    med: OptionalInt = Field(None, ge=0, le=4294967294)
    # Optional: the session's TCP MD5 password, the same on the neighbor. Next to
    # the uplink's tunnel: its key alone then doesn't give a BGP session.
    password: Secret | None = None

    @field_validator("password")
    @classmethod
    def _one_word(cls, v: Secret | None) -> Secret | None:
        """It's a line of FRR's configuration, and a TCP MD5 key."""
        if v is not None and not re.fullmatch(r"\S{1,80}", v.get_secret_value()):
            msg = "1 to 80 characters without spaces"
            raise ValueError(msg)
        return v


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

    _upper = helpers.upper("mode")

    # VPN CONFIG
    # IKE local identifier for VPNs
    local_id: str = r"%any"

    def _check_key(self, key: str) -> None:
        if key not in SERVICE_NETWORK_INSTANCES[self.mode]:
            msg = f"network instance '{key}' can't be part of {self.id}"
            raise ValueError(msg)
        if self.network_instances[key].type.value != key:
            msg = f"network instance '{key}' should be of type {key}"
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


class DNS(BaseModel):
    """Limits on a network instance's DNS responses, which vpncmangle translates.

    One thread translates every network instance's: these keep one of them from
    taking it. The defaults are vpncmangle's.
    """

    # kbytes of responses per second; more are dropped.
    rate_limit: Int = Field(default=50, ge=1)
    # Bytes of a response (its IPv6 packet); a larger one is dropped.
    max_size: Int = Field(default=4096, ge=512, le=65535)
    # Records in a response; one with more is dropped.
    max_records: Int = Field(default=100, ge=1, le=65535)


class ServiceHub(ServiceTenant):
    """Define a service data structure."""

    mode: Literal[ServiceMode.HUB] = ServiceMode.HUB
    network_instances: dict[
        str,
        NetworkInstanceCore | NetworkInstanceExternal,
    ] = Field(default_factory=dict)

    # OVERLAY CONFIG
    # IPv4 prefix for downlink interfaces. Must be a /16, will get subnetted into /24s
    # per downlink interface per tunnel.
    prefix_downlink_interface_v4: Network4 = IPv4Network("100.64.0.0/10")
    # IPv6 prefix for downlink interfaces. Must be a /48 or larger, will get subnetted
    # into /64s per downlink interface per tunnel.
    prefix_downlink_interface_v6: Network6 = IPv6Network("fdcc:cbe::/32")
    # The below are used on the provider side to uniquely adress tenant environments
    # IPv6 prefix for NAT64. Must be a /32 or larger. Will be subnetted into /96s per
    # downlink per tunnel.
    prefix_downlink_nat64: Network6 = IPv6Network("64:ff9b::/32")
    # IPv6 prefix for NPTv6. Must be a /12 or larger. Will be subnetted into /48s per
    # downlink per tunnel.
    prefix_downlink_nptv6: Network6 = IPv6Network("660::/12")

    ## BGP config
    bgp: BGP

    dns: DNS = Field(default_factory=DNS)

    _none_as_default = helpers.none_as_default("dns")

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


def load(
    path: pathlib.Path,
) -> tuple[ServiceHub | ServiceEndpoint | Tenant | None, str | None]:
    """Load a configuration file; return it, or None and why it can't be loaded."""
    logger.info("Loading configuration file from %s.", path)
    model, error = _read(path)
    if error:
        # Without the file's content: it holds secrets.
        logger.critical("Configuration file %s isn't loaded: %s.", path, error)
    return model, error


def _read(  # noqa: PLR0911 (a return per reason)
    path: pathlib.Path,
) -> tuple[ServiceHub | ServiceEndpoint | Tenant | None, str | None]:
    if not config.TENANT_RE.match(path.stem):
        return None, "the file name isn't a tenant id"
    try:
        with path.open(encoding="utf-8") as f:
            config_yaml = yaml.safe_load(f)
    except FileNotFoundError:
        return None, "it doesn't exist"
    except UnicodeDecodeError:
        return None, "it isn't UTF-8 text"
    except (yaml.YAMLError, TypeError) as err:
        mark = getattr(err, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(err, "problem", None) or type(err).__name__
        return None, f"it isn't valid YAML: {problem}{where}"

    if isinstance(config_yaml, dict):
        config_yaml = migration.upgrade(config_yaml)
    try:
        tenant = Tenants(config=config_yaml).config
    except pydantic_core.ValidationError as err:
        errors = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in err.errors(include_input=False, include_context=False)
        )
        return None, f"it doesn't adhere to the schema: {errors}"

    if tenant.id != path.stem:
        return None, f"it holds the configuration of {tenant.id}"
    return tenant, None


def load_default() -> ServiceHub | ServiceEndpoint:
    """Load the service (DEFAULT) configuration; vpnc can't run without it."""
    default_tenant, _ = load(config.VPNC_A_CONFIG_PATH_SERVICE)
    if not isinstance(default_tenant, (ServiceHub, ServiceEndpoint)):
        msg = "Service isn't configured correctly. Data class is not of a service type."
        logger.critical(msg)
        raise config.ConfigurationError(msg)
    config.VPNC_CONFIG_TENANT[default_tenant.id] = default_tenant
    return default_tenant


def core_route_overlaps(
    tenants: Iterable[Tenant],
) -> list[tuple[str, str, str, str]]:
    """Return a hub's IPv6 routes in CORE that overlap: (route, of, route, of).

    A tenant's route without NPTv6 is a route in CORE as it is, so it mustn't
    take traffic of the uplinks' routes, the NAT64 and NPTv6 prefixes or another
    network instance's routes. "Of" is a connection, or the prefix's setting.
    """
    # Route, of what, and its network instance (the service's count as one).
    routes: list[tuple[IPv6Network, str, str]] = []
    for tenant_config in tenants:
        if isinstance(tenant_config, ServiceEndpoint):
            return []
        if isinstance(tenant_config, ServiceHub):
            routes += [
                (getattr(tenant_config, name), name, config.DEFAULT_TENANT)
                for name in ("prefix_downlink_nat64", "prefix_downlink_nptv6")
            ]
        for ni in tenant_config.network_instances.values():
            for connection in ni.connections.values():
                for route in connection.routes.ipv6:
                    name = connection.name(ni)
                    # A default route to the uplinks is less specific than any.
                    if ni.type == enums.NetworkInstanceType.CORE and route.to.prefixlen:
                        routes.append((route.to, name, config.DEFAULT_TENANT))
                    elif (
                        ni.type == enums.NetworkInstanceType.DOWNLINK
                        and not route.nptv6
                    ):
                        routes.append((route.to, name, ni.id))
    return [
        (str(route), of, str(other), other_of)
        for index, (route, of, ni_id) in enumerate(routes)
        for other, other_of, other_ni_id in routes[index + 1 :]
        if ni_id != other_ni_id and route.overlaps(other)
    ]
