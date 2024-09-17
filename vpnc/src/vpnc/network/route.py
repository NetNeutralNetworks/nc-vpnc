"""Manage network routes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal

logger = logging.getLogger("vpnc")

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

    import pyroute2


def command(
    netns: pyroute2.NetNS,
    command: Literal["replace", "change", "add", "del", "dump"],
    dst: IPv4Network | IPv6Network,
    type: Literal["blackhole"] | None = None,
    gateway: IPv4Address | IPv6Address | None = None,
    ifname: str | None = None,
) -> None:
    """Perform route actions."""
    route_params: dict[str, Any] = {
        k: str(v) for k, v in locals().items() if v is not None
    }
    route_params.pop("ifname", None)
    if ifname:
        if not netns.link_lookup(ifname=ifname):
            return
        route_params["oif"] = netns.link_lookup(ifname=ifname)[0]
    try:
        netns.route(**route_params)
        logger.info(
            "Operation '%s' succeeded for network instance: %s, route: %s via '%s/%s/%s'",
            command,
            netns.netns,
            dst,
            type,
            gateway,
            ifname,
        )
    except Exception as e:
        logger.warning(
            "Operation '%s' failed for network instance: %s, route: %s via '%s/%s/%s': %s",
            command,
            netns.netns,
            dst,
            type,
            gateway,
            ifname,
            e,
        )
