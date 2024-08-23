"""Manage network routes."""

from __future__ import annotations

import atexit
from typing import TYPE_CHECKING, Literal

from pyroute2 import NDB

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

    from pyroute2.ndb.objects import route as rte


def set_(
    route: IPv4Network | IPv6Network | Literal["default"],
    next_hop: IPv4Address | IPv6Address | None = None,
    inf_index: int | None = None,
    ns_name: str | None = None,
    cleanup: bool = False,  # noqa: FBT001, FBT002
) -> rte.Route:
    """Update a route attribute."""
    with NDB() as ndb:
        if ns_name:
            ndb.sources.add(netns=ns_name)
        else:
            ns_name = "localhost"
        data = {"dst": str(route), "target": ns_name}
        if next_hop:
            data["gateway"] = str(next_hop)
        if inf_index:
            data["oif"] = inf_index
        if rt := ndb.routes.get({"dst": str(route), "target": ns_name}):
            with rt:
                rt.set(**data).commit()
        else:
            with ndb.routes as nrt:
                rt: rte.Route = nrt.create(**data).commit()

    if cleanup:
        atexit.register(delete, route=rt)

    return rt


def delete(route: rte.Route) -> None:
    """Delete a network route."""
    with NDB() as ndb:
        ndb.sources.add(netns=route["target"])
        rt: rte.Route = ndb.routes.get({"dst": route["dst"], "target": route["target"]})
        if rt:
            rt.remove().commit()
