"""Functions used throughout the service."""

from __future__ import annotations

import time
from ipaddress import IPv4Network, IPv6Network
from typing import TYPE_CHECKING, Any, TypeVar, cast

from pydantic import BaseModel, ValidationInfo, field_validator

from vpnc import config, shared
from vpnc.models import enums

if TYPE_CHECKING:
    from pathlib import Path

    from vpnc.models import tenant
    from vpnc.models.network_instance import NetworkInstance

Net = TypeVar("Net", IPv4Network, IPv6Network)


def network_instances() -> dict[str, NetworkInstance]:
    """Return the configured network instances by id."""
    return {
        ni.id: ni
        for tenant_config in list(config.VPNC_CONFIG_TENANT.values())
        for ni in tenant_config.network_instances.values()
    }


def get_default_tenant() -> tenant.ServiceHub | tenant.ServiceEndpoint:
    """Return the service (DEFAULT) configuration; it's loaded at startup."""
    try:
        default_tenant = config.VPNC_CONFIG_TENANT[config.DEFAULT_TENANT]
    except KeyError:
        msg = "The service configuration isn't loaded."
        raise config.ConfigurationError(msg) from None
    return cast("tenant.ServiceHub | tenant.ServiceEndpoint", default_tenant)


def is_hub() -> bool:
    """Return whether the service runs in hub mode."""
    return get_default_tenant().mode == enums.ServiceMode.HUB


def split_connection_name(name: str) -> tuple[str, str]:
    """Return the network instance and number of a connection's name."""
    network_instance_id, _, number = name.rpartition("-")
    return network_instance_id, number


def downlink_tenant(connection_name: str) -> str | None:
    """Return the tenant of a downlink connection (C0001 of C0001-00-1), else None."""
    match = config.DOWNLINK_CON_RE.match(connection_name)
    return match.group(2) if match else None


def tenant_file(tenant_id: str) -> Path:
    """Return the active configuration file of a tenant."""
    return config.VPNC_A_CONFIG_DIR.joinpath(f"{tenant_id}.yaml")


def endpoint(address: object, port: object) -> str:
    """Return address:port, with an IPv6 address in brackets."""
    address = str(address)
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def xfrm_interface_name(number: int | str) -> str:
    """Return the name of the XFRM interface of a connection's number."""
    return f"xfrm{number}"


def wireguard_interface_name(connection_name: str) -> str:
    """Return the name of the WireGuard interface of a connection's name."""
    return f"wg-{connection_name}"


def nth_subnet(network: Net, new_prefix: int, n: int) -> Net:
    """Return subnet n of a network, like list(network.subnets(new_prefix))[n]."""
    if not 0 <= n < 1 << (new_prefix - network.prefixlen):
        msg = f"{network} has no subnet {n} of length /{new_prefix}"
        raise IndexError(msg)
    size = 1 << (network.max_prefixlen - new_prefix)
    return type(network)((int(network.network_address) + n * size, new_prefix))


def printable(text: str) -> str:
    """Return text with its non-printable characters replaced by '?'."""
    return "".join(c if c.isprintable() else "?" for c in text)


def upper(*fields: str) -> Any:  # noqa: ANN401
    """Return a validator that upper-cases fields, whose values were lower case."""

    def validate(_: type[BaseModel], v: Any) -> Any:  # noqa: ANN401
        return v.upper() if isinstance(v, str) else v

    return field_validator(*fields, mode="before")(classmethod(validate))


def none_as_default(*fields: str) -> Any:  # noqa: ANN401
    """Return a validator that gives fields their default when they're None.

    A key without a value in YAML is None.
    """

    def validate(cls: type[BaseModel], v: Any, info: ValidationInfo) -> Any:  # noqa: ANN401
        if v is None and info.field_name is not None:
            return cls.model_fields[info.field_name].get_default(
                call_default_factory=True,
            )
        return v

    return field_validator(*fields, mode="before")(classmethod(validate))


def auto_resets(name: str) -> int:
    """Return how often the watchdog reset a connection in the last 24 hours."""
    since = time.time() - shared.AUTO_RESET_HISTORY
    return sum(t >= since for t in shared.AUTO_RESETS.get(name, []))
