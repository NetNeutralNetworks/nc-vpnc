"""Read and change the links, addresses and routes of a namespace idempotently.

Each ensure function compares the desired state with a snapshot (NetnsState),
changes only what differs, keeps the snapshot up to date and returns whether it
changed something. Within a session() a namespace is read once and its socket
and snapshot are shared, which keeps a full check cheap.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

import pyroute2
from pyroute2.netlink.exceptions import NetlinkError
from pyroute2.netlink.rtnl.rtmsg import rtmsg

from vpnc.network import namespace

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

logger = logging.getLogger("vpnc")

IPInterface = ipaddress.IPv4Interface | ipaddress.IPv6Interface
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Interface flags (linux/if.h).
IFF_UP = 0x1
IFF_LOWER_UP = 0x10000

# Route protocol of the routes vpnc manages, unused by the kernel and routing
# daemons ("vpnc" in /etc/iproute2/rt_protos.d/vpnc.conf). Routes with
# RTPROT_STATIC are vpnc's too: vpnc used it before.
RTPROT_STATIC = 4
RTPROT_VPNC = 77
OWNED_PROTOCOLS = (RTPROT_STATIC, RTPROT_VPNC)
RT_TABLE_MAIN = 254
RTN_UNICAST = 1
RTN_BLACKHOLE = 6
RT_SCOPE_UNIVERSE = 0
RT_SCOPE_LINK = 253

# For route dumps the kernel filters (pyroute2 filters after receiving all).
SOL_NETLINK = 270
NETLINK_GET_STRICT_CHK = 12
RTM_GETROUTE = 26
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 0x1
NLM_F_DUMP = 0x300


@dataclass(frozen=True)
class Link:
    """An interface."""

    index: int
    kind: str | None
    flags: int
    xfrm_if_id: int | None = None

    @property
    def up(self) -> bool:
        """Return whether the interface is administratively up."""
        return bool(self.flags & IFF_UP)

    @property
    def passes_traffic(self) -> bool:
        """Return whether the interface is up and has carrier."""
        return self.up and bool(self.flags & IFF_LOWER_UP)


@dataclass(frozen=True)
class Route:
    """A route in the main table. Blackhole routes have no gateway or device."""

    dst: IPNetwork
    type: Literal["unicast", "blackhole"] = "unicast"
    gateway: IPAddress | None = None
    dev: str | None = None

    @classmethod
    def blackhole(cls, dst: IPNetwork) -> Route:
        """Return a blackhole route."""
        return cls(dst=dst, type="blackhole")


@dataclass
class NetnsState:
    """Snapshot of the links, global addresses and owned routes of a namespace."""

    name: str
    links: dict[str, Link] = field(default_factory=dict)
    addresses: dict[str, set[IPInterface]] = field(default_factory=dict)
    link_local: dict[str, set[IPInterface]] = field(default_factory=dict)
    routes: dict[IPNetwork, Route] = field(default_factory=dict)

    @classmethod
    def read(cls, ipr: namespace.IPRoute) -> NetnsState:
        """Read the state of the namespace of ipr."""
        state = cls(name=ipr.netns)
        names: dict[int, str] = {}
        for msg in ipr.get_links():
            name = msg.get("ifname")
            names[msg["index"]] = name
            info = msg.get(("IFLA_LINKINFO", "IFLA_INFO_KIND"))
            if_id = msg.get(("IFLA_LINKINFO", "IFLA_INFO_DATA", "IFLA_XFRM_IF_ID"))
            state.links[name] = Link(msg["index"], info, msg["flags"], if_id)
            state.addresses[name] = set()
            state.link_local[name] = set()
        for msg in ipr.get_addr():
            name = names.get(msg["index"])
            if name is None:
                continue
            address = ipaddress.ip_interface(
                f"{msg.get('address')}/{msg['prefixlen']}",
            )
            if msg["scope"] == RT_SCOPE_UNIVERSE:
                state.addresses[name].add(address)
            elif msg["scope"] == RT_SCOPE_LINK:
                state.link_local[name].add(address)
        for msg in owned_route_messages(ipr.netns):
            route = _route_from_msg(msg, names)
            state.routes[route.dst] = route
        return state


def owned_route_messages(netns: str) -> list[rtmsg]:
    """Return the owned routes of the main table of a namespace.

    The kernel only sends these (strict check), instead of every route (e.g. a
    full BGP table) for pyroute2 to parse and filter.
    """
    messages: list[rtmsg] = []
    with socket.socket(
        socket.AF_NETLINK,
        socket.SOCK_RAW,
        socket.NETLINK_ROUTE,
        fileno=namespace.netlink_socket(netns),
    ) as sock:
        sock.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
        for seq, proto in enumerate(OWNED_PROTOCOLS, start=1):
            # struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
            # type, flags.
            body = struct.pack("4B4BI", 0, 0, 0, 0, RT_TABLE_MAIN, proto, 0, 0, 0)
            header = struct.pack(
                "IHHII",
                16 + len(body),
                RTM_GETROUTE,
                NLM_F_REQUEST | NLM_F_DUMP,
                seq,
                0,
            )
            sock.send(header + body)
            messages.extend(_receive_dump(sock))
    return messages


def _receive_dump(sock: socket.socket) -> Iterator[rtmsg]:
    while True:
        data = sock.recv(1 << 20)
        offset = 0
        while offset < len(data):
            length, msg_type = struct.unpack_from("IH", data, offset)
            if msg_type == NLMSG_DONE:
                return
            if msg_type == NLMSG_ERROR:
                raise NetlinkError(-struct.unpack_from("i", data, offset + 16)[0])
            msg = rtmsg(data[offset : offset + length])
            msg.decode()
            yield msg
            offset += (length + 3) & ~3


# Per namespace, bumped by changed(): shared snapshots are read again.
_GENERATIONS: dict[str, int] = {}


def changed(name: str) -> None:
    """Note a change in a namespace not made by the ensure functions (an event)."""
    _GENERATIONS[name] = _GENERATIONS.get(name, 0) + 1


class Netns:
    """A socket in a namespace and its snapshot, read on first use."""

    def __init__(self, name: str) -> None:
        """Open a socket in the namespace."""
        self.name = name
        self.ipr = namespace.IPRoute(name)
        self._state: NetnsState | None = None
        self._generation = 0

    @property
    def state(self) -> NetnsState:
        """Return the snapshot of the namespace, read again after changed()."""
        generation = _GENERATIONS.get(self.name, 0)
        if self._state is None or self._generation != generation:
            self._generation = generation
            self._state = NetnsState.read(self.ipr)
        return self._state

    def invalidate(self) -> None:
        """Read the namespace again on the next use."""
        self._state = None


_SESSION = threading.local()


@contextlib.contextmanager
def session() -> Iterator[None]:
    """Share one socket and snapshot per namespace in this thread until the end.

    A nested session closes the namespaces it opened; the ones opened before stay
    shared (e.g. CORE during a full check). Changes not made through the ensure
    functions are only seen after changed().
    """
    outermost = getattr(_SESSION, "open", None) is None
    if outermost:
        _SESSION.open = {}
    opened: dict[str, Netns] = _SESSION.open
    before = set(opened)
    try:
        yield
    finally:
        for name in set(opened) - before:
            opened.pop(name).ipr.close()
        if outermost:
            _SESSION.open = None


@contextlib.contextmanager
def netns(name: str) -> Iterator[Netns]:
    """Open a namespace; within a session() the shared one."""
    opened: dict[str, Netns] | None = getattr(_SESSION, "open", None)
    if opened is None:
        ns = Netns(name)
        with ns.ipr:
            yield ns
        return
    if name not in opened:
        opened[name] = Netns(name)
    try:
        yield opened[name]
    except BaseException:
        # A failed change may have left the snapshot behind.
        opened[name].invalidate()
        raise


def _route_from_msg(msg: dict, names: dict[int, str]) -> Route:  # type: ignore[type-arg]
    dst = msg.get("dst") or ("::" if msg["family"] == 10 else "0.0.0.0")  # noqa: PLR2004, S104
    network = ipaddress.ip_network(f"{dst}/{msg['dst_len']}")
    if msg["type"] == RTN_BLACKHOLE:
        return Route.blackhole(network)
    gateway = msg.get("gateway")
    oif = msg.get("oif")
    return Route(
        dst=network,
        gateway=ipaddress.ip_address(gateway) if gateway else None,
        dev=names.get(oif) if oif else None,
    )


def refresh_link(ipr: namespace.IPRoute, state: NetnsState, name: str) -> Link | None:
    """Reread one interface into the snapshot and return it."""
    state.links.pop(name, None)
    if not (indexes := ipr.link_lookup(ifname=name)):
        return None
    msg = ipr.get_links(indexes[0])[0]
    link = Link(
        msg["index"],
        msg.get(("IFLA_LINKINFO", "IFLA_INFO_KIND")),
        msg["flags"],
        msg.get(("IFLA_LINKINFO", "IFLA_INFO_DATA", "IFLA_XFRM_IF_ID")),
    )
    state.links[name] = link
    state.addresses.setdefault(name, set())
    state.link_local.setdefault(name, set())
    return link


def refresh_routes(ipr: namespace.IPRoute, state: NetnsState) -> None:
    """Reread the owned routes into the snapshot."""
    names = {link.index: name for name, link in state.links.items()}
    state.routes = {}
    for msg in owned_route_messages(ipr.netns):
        route = _route_from_msg(msg, names)
        state.routes[route.dst] = route


def delete_link(ipr: namespace.IPRoute, state: NetnsState, name: str) -> bool:
    """Delete an interface if it exists."""
    if (link := state.links.get(name)) is None:
        return False
    logger.info("Deleting interface %s in %s.", name, state.name)
    try:
        ipr.link("del", index=link.index)
    except NetlinkError as err:
        if err.code != 19:  # noqa: PLR2004  ENODEV: already gone
            raise
    state.links.pop(name, None)
    state.addresses.pop(name, None)
    state.link_local.pop(name, None)
    # The kernel deleted the routes via the interface.
    refresh_routes(ipr, state)
    return True


def _move_from(
    ipr_src: pyroute2.IPRoute,
    ipr: namespace.IPRoute,
    state: NetnsState,
    name: str,
    **kwargs: object,
) -> None:
    """Create an interface in another namespace and move it into state's."""
    ipr_src.link("add", ifname=name, **kwargs)
    index = ipr_src.link_lookup(ifname=name)[0]
    ipr_src.link("set", index=index, net_ns_fd=state.name)
    refresh_link(ipr, state, name)


def ensure_xfrm(
    ipr: namespace.IPRoute,
    ipr_external: pyroute2.IPRoute,
    state: NetnsState,
    name: str,
    if_id: int,
) -> bool:
    """Ensure an XFRM interface with if_id. It's created in EXTERNAL and moved."""
    link = state.links.get(name)
    if link and link.kind == "xfrm" and link.xfrm_if_id == if_id:
        return False
    delete_link(ipr, state, name)
    logger.info(
        "Creating XFRM interface %s (if_id %#x) in %s.",
        name,
        if_id,
        state.name,
    )
    _move_from(ipr_external, ipr, state, name, kind="xfrm", xfrm_if_id=if_id)
    return True


def ensure_wireguard(
    ipr: namespace.IPRoute,
    ipr_external: pyroute2.IPRoute,
    state: NetnsState,
    name: str,
) -> bool:
    """Ensure a WireGuard interface, created in EXTERNAL (its socket stays there)."""
    link = state.links.get(name)
    if link and link.kind == "wireguard":
        return False
    delete_link(ipr, state, name)
    logger.info("Creating WireGuard interface %s in %s.", name, state.name)
    _move_from(ipr_external, ipr, state, name, kind="wireguard")
    return True


def ensure_tun(ipr: namespace.IPRoute, state: NetnsState, name: str) -> bool:
    """Ensure a tun interface."""
    link = state.links.get(name)
    if link and link.kind == "tun":
        return False
    delete_link(ipr, state, name)
    logger.info("Creating tun interface %s in %s.", name, state.name)

    # pyroute2 creates tun interfaces via /dev/net/tun in the calling thread's
    # namespace, not via netlink.
    def create() -> None:
        with pyroute2.IPRoute() as ipr_ns:
            ipr_ns.link("add", ifname=name, kind="tuntap", mode="tun")

    namespace.call(state.name, create)
    refresh_link(ipr, state, name)
    return True


def ensure_veth(
    ipr: namespace.IPRoute,
    state: NetnsState,
    name: str,
    peer_name: str,
    peer_netns: str,
) -> bool:
    """Ensure a veth pair with the peer in another namespace."""
    link = state.links.get(name)
    if link and link.kind == "veth":
        return False
    delete_link(ipr, state, name)
    logger.info(
        "Creating veth pair %s (%s) and %s (%s).",
        name,
        state.name,
        peer_name,
        peer_netns,
    )
    ipr.link(
        "add",
        ifname=name,
        kind="veth",
        peer={"ifname": peer_name, "net_ns_fd": peer_netns},
    )
    refresh_link(ipr, state, name)
    return True


def ensure_moved(
    ipr: namespace.IPRoute,
    ipr_src: pyroute2.IPRoute,
    state: NetnsState,
    name: str,
) -> bool:
    """Ensure an existing (physical) interface is moved into state's namespace."""
    if name in state.links:
        return False
    if not (indexes := ipr_src.link_lookup(ifname=name)):
        logger.warning("Interface %s not found; can't move it to %s.", name, state.name)
        return False
    logger.info("Moving interface %s to %s.", name, state.name)
    ipr_src.link("set", index=indexes[0], net_ns_fd=state.name)
    refresh_link(ipr, state, name)
    return True


def ensure_link_state(
    ipr: namespace.IPRoute,
    state: NetnsState,
    name: str,
    *,
    up: bool,
) -> bool:
    """Ensure an interface is administratively up or down."""
    if (link := state.links.get(name)) is None or link.up == up:
        return False
    logger.info(
        "Setting interface %s in %s %s.",
        name,
        state.name,
        "up" if up else "down",
    )
    ipr.link("set", index=link.index, state="up" if up else "down")
    refresh_link(ipr, state, name)
    return True


def ensure_addresses(
    ipr: namespace.IPRoute,
    state: NetnsState,
    name: str,
    desired: Iterable[IPInterface],
    link_local: Iterable[IPInterface] = (),
) -> bool:
    """Ensure an interface has exactly the desired global addresses.

    Link-local addresses are only added; the kernel adds its own.
    """
    if (link := state.links.get(name)) is None:
        return False
    wanted = set(desired)
    current = state.addresses.setdefault(name, set())
    current_ll = state.link_local.setdefault(name, set())
    changed = False
    # Add before removing: removing an interface's last IPv4 address makes the
    # kernel delete its routes.
    for address in sorted((wanted - current) | (set(link_local) - current_ll), key=str):
        logger.info("Adding address %s to %s in %s.", address, name, state.name)
        ipr.addr(
            "replace",
            index=link.index,
            address=str(address.ip),
            prefixlen=address.network.prefixlen,
        )
        (current if address in wanted else current_ll).add(address)
        changed = True
    removed = sorted(current - wanted, key=str)
    for address in removed:
        logger.info("Removing address %s from %s in %s.", address, name, state.name)
        ipr.addr(
            "del",
            index=link.index,
            address=str(address.ip),
            prefixlen=address.network.prefixlen,
        )
        current.discard(address)
    if removed:
        # The kernel may have deleted routes along with the addresses.
        refresh_routes(ipr, state)
    return changed or bool(removed)


def ensure_routes(
    ipr: namespace.IPRoute,
    state: NetnsState,
    desired: Iterable[Route],
    *,
    managed: Iterable[IPNetwork] | None = None,
) -> bool:
    """Ensure the owned routes equal the desired routes.

    Owned routes that aren't desired are deleted. If managed is given, only
    routes to those destinations are deleted (e.g. one network instance's routes
    in CORE).
    """
    wanted = {route.dst: route for route in desired}
    scope = None if managed is None else set(managed) | set(wanted)
    changed = False
    for dst, route in wanted.items():
        if state.routes.get(dst) == route:
            continue
        if route.dev is not None and route.dev not in state.links:
            logger.debug("Skipping route %s: %s not in %s.", dst, route.dev, state.name)
            continue
        logger.info("Setting route %s in %s.", route, state.name)
        ipr.route("replace", **_route_args(state, route))
        state.routes[dst] = route
        changed = True
    for dst, route in list(state.routes.items()):
        if dst in wanted or (scope is not None and dst not in scope):
            continue
        logger.info("Deleting route %s in %s.", route, state.name)
        try:
            ipr.route("del", dst=str(dst), table=RT_TABLE_MAIN)
        except NetlinkError as err:
            if err.code != 3:  # noqa: PLR2004  ESRCH: already gone
                raise
        del state.routes[dst]
        changed = True
    return changed


def _route_args(state: NetnsState, route: Route) -> dict[str, object]:
    args: dict[str, object] = {
        "dst": str(route.dst),
        "table": RT_TABLE_MAIN,
        "proto": RTPROT_VPNC,
    }
    if route.type == "blackhole":
        args["type"] = "blackhole"
        return args
    if route.gateway is not None:
        args["gateway"] = str(route.gateway)
    if route.dev is not None:
        args["oif"] = state.links[route.dev].index
    return args
