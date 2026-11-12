"""Functions used throughout the service."""

from __future__ import annotations

import time
from ipaddress import IPv4Network, IPv6Network
from typing import TYPE_CHECKING, TypeVar

from vpnc import config, shared

if TYPE_CHECKING:
    from vpnc.models.network_instance import NetworkInstance

Net = TypeVar("Net", IPv4Network, IPv6Network)


def network_instances() -> dict[str, NetworkInstance]:
    """Return the configured network instances by id."""
    return {
        ni.id: ni
        for tenant_config in list(config.VPNC_CONFIG_TENANT.values())
        for ni in tenant_config.network_instances.values()
    }


def split_connection_name(name: str) -> tuple[str, str]:
    """Return the network instance and number of a connection's name."""
    network_instance_id, _, number = name.rpartition("-")
    return network_instance_id, number


def xfrm_interface_name(number: int | str) -> str:
    """Return the name of the XFRM interface of a connection's number."""
    return f"xfrm{number}"


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


def auto_resets(name: str) -> int:
    """Return how often the watchdog reset a connection in the last 24 hours."""
    since = time.time() - shared.AUTO_RESET_HISTORY
    return sum(t >= since for t in shared.AUTO_RESETS.get(name, []))
