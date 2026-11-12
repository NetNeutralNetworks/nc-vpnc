"""Read and change the links, addresses and routes of a namespace idempotently.

Each ensure function compares the desired state with a snapshot (NetnsState),
changes only what differs, keeps the snapshot up to date and returns whether it
changed something. Within a session() a namespace is read once and its socket
and snapshot are shared, which keeps a full check cheap. Sessions keep their
sockets open for the next session.
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
RTM_GETLINK = 18
RTM_GETADDR = 22
RTM_GETROUTE = 26
# Attributes of links (linux/if_link.h) and addresses (linux/if_addr.h).
IFLA_IFNAME = 3
IFLA_LINKINFO = 18
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2
IFLA_XFRM_IF_ID = 2
IFA_ADDRESS = 1
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
    def read(cls, name: str, *, routes: bool = True) -> NetnsState:
        """Read the state of a namespace; without routes, if not needed.

        Only the attributes vpnc uses are parsed: pyroute2 decodes all of them
        (statistics, per-family settings), which takes most of a full check.
        """
        state = cls(name=name)
        names: dict[int, str] = {}
        with _dump_socket(name) as sock:
            # struct ifinfomsg: family, type, index, flags, change.
            for msg in _dump(sock, RTM_GETLINK, bytes(16)):
                _, _, index, flags, _ = struct.unpack_from("BxHiII", msg, 16)
                attributes = _attributes(msg[32:])
                ifname = _string(attributes[IFLA_IFNAME])
                info = _attributes(attributes.get(IFLA_LINKINFO, b""))
                kind = _string(info[IFLA_INFO_KIND]) if IFLA_INFO_KIND in info else None
                if_id = None
                if kind == "xfrm":
                    data = _attributes(info.get(IFLA_INFO_DATA, b""))
                    if IFLA_XFRM_IF_ID in data:
                        (if_id,) = struct.unpack("I", data[IFLA_XFRM_IF_ID])
                names[index] = ifname
                state.links[ifname] = Link(index, kind, flags, if_id)
                state.addresses[ifname] = set()
                state.link_local[ifname] = set()
            # struct ifaddrmsg: family, prefixlen, flags, scope, index.
            for msg in _dump(sock, RTM_GETADDR, bytes(8)):
                _, prefixlen, _, scope, index = struct.unpack_from("4BI", msg, 16)
                raw = _attributes(msg[24:]).get(IFA_ADDRESS)
                if (owner := names.get(index)) is None or raw is None:
                    continue
                address = ipaddress.ip_interface((raw, prefixlen))
                if scope == RT_SCOPE_UNIVERSE:
                    state.addresses[owner].add(address)
                elif scope == RT_SCOPE_LINK:
                    state.link_local[owner].add(address)
            if routes:
                state.routes = _routes(_owned_route_messages(sock), names)
        return state


def _string(value: bytes) -> str:
    return value.rstrip(b"\0").decode()


def _attributes(data: bytes) -> dict[int, bytes]:
    """Return the values of netlink attributes by type (nested ones as bytes)."""
    attributes: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        length, kind = struct.unpack_from("HH", data, offset)
        if length < 4:  # noqa: PLR2004
            break
        # Without the nested and byte order flags.
        attributes[kind & 0x3FFF] = data[offset + 4 : offset + length]
        offset += (length + 3) & ~3
    return attributes


@contextlib.contextmanager
def _dump_socket(netns: str) -> Iterator[socket.socket]:
    """Open a netlink socket in a namespace (FileNotFoundError if missing)."""
    with socket.socket(
        socket.AF_NETLINK,
        socket.SOCK_RAW,
        socket.NETLINK_ROUTE,
        fileno=namespace.netlink_socket(netns),
    ) as sock:
        sock.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
        yield sock


def _dump(sock: socket.socket, msg_type: int, body: bytes) -> Iterator[bytes]:
    """Request a dump and return its messages, with their headers."""
    header = struct.pack(
        "IHHII",
        16 + len(body),
        msg_type,
        NLM_F_REQUEST | NLM_F_DUMP,
        1,
        0,
    )
    sock.send(header + body)
    while True:
        data = sock.recv(1 << 20)
        offset = 0
        while offset < len(data):
            length, received = struct.unpack_from("IH", data, offset)
            if received == NLMSG_DONE:
                return
            if received == NLMSG_ERROR:
                raise NetlinkError(-struct.unpack_from("i", data, offset + 16)[0])
            yield data[offset : offset + length]
            offset += (length + 3) & ~3


def owned_route_messages(netns: str) -> list[rtmsg]:
    """Return the owned routes of the main table of a namespace."""
    with _dump_socket(netns) as sock:
        return _owned_route_messages(sock)


def _owned_route_messages(sock: socket.socket) -> list[rtmsg]:
    """Return the owned routes of the main table.

    The kernel only sends these (strict check), instead of every route (e.g. a
    full BGP table) for pyroute2 to parse and filter.
    """
    messages: list[rtmsg] = []
    for proto in OWNED_PROTOCOLS:
        # struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
        # type, flags.
        body = struct.pack("4B4BI", 0, 0, 0, 0, RT_TABLE_MAIN, proto, 0, 0, 0)
        for data in _dump(sock, RTM_GETROUTE, body):
            msg = rtmsg(data)
            msg.decode()
            messages.append(msg)
    return messages


# Per namespace, bumped by changed(): shared snapshots are read again.
_GENERATIONS: dict[str, int] = {}


def changed(name: str) -> None:
    """Note a change in a namespace not made by the ensure functions (an event)."""
    _GENERATIONS[name] = _GENERATIONS.get(name, 0) + 1


# Sockets kept open between sessions of one thread (the reconciler), per namespace
# with the identity of the namespace they're in. pyroute2 closes a socket used in
# another thread than the one that opened it, so other threads don't keep them.
_SOCKETS: dict[str, tuple[tuple[int, int], namespace.IPRoute]] = {}
_KEEPER: int | None = None


def keep_sockets() -> None:
    """Keep the sockets of this thread's sessions open for its next sessions."""
    global _KEEPER  # noqa: PLW0603
    _KEEPER = threading.get_ident()


def _keeps() -> bool:
    return threading.get_ident() == _KEEPER


def netns_identity(name: str) -> tuple[int, int]:
    """Return the identity of a namespace (FileNotFoundError if missing)."""
    stat = (namespace.NETNS_DIR / name).stat()
    return stat.st_dev, stat.st_ino


def _socket(name: str) -> namespace.IPRoute:
    """Return the kept socket of a namespace, opening one if it was replaced."""
    identity = netns_identity(name)
    if (kept := _SOCKETS.get(name)) is not None:
        if kept[0] == identity:
            return kept[1]
        forget(name)
    ipr = namespace.IPRoute(name)
    _SOCKETS[name] = (identity, ipr)
    return ipr


def forget(name: str) -> None:
    """Close the kept socket of a namespace, e.g. before deleting it.

    A socket keeps its namespace, and the interfaces in it, alive. Other threads
    leave it to the keeping thread's forget_stale().
    """
    if not _keeps():
        return
    if (kept := _SOCKETS.pop(name, None)) is not None:
        kept[1].close()


def forget_stale() -> None:
    """Close the kept sockets of namespaces that were deleted or replaced."""
    if not _keeps():
        return
    for name, (identity, _) in list(_SOCKETS.items()):
        try:
            current = netns_identity(name)
        except FileNotFoundError:
            current = None
        if current != identity:
            forget(name)


class Netns:
    """A socket in a namespace, its snapshot (read on first use) and a thread in it.

    Calls for the namespace (programs, sysctls, nftables) run in that thread.
    """

    def __init__(self, name: str, *, keep: bool = False) -> None:
        """Open a socket in the namespace (FileNotFoundError if missing).

        With keep, the socket stays open for the next session.
        """
        self.name = name
        self.keep = keep
        self.ipr = _socket(name) if keep else namespace.IPRoute(name)
        self._worker = contextlib.ExitStack()
        self._worker.enter_context(namespace.worker(name))
        self._state: NetnsState | None = None
        self._generation = 0

    def close(self) -> None:
        """Stop the thread and close the socket, unless it's kept."""
        if not self.keep:
            self.ipr.close()
        self._worker.close()

    @property
    def state(self) -> NetnsState:
        """Return the snapshot of the namespace, read again after changed()."""
        generation = _GENERATIONS.get(self.name, 0)
        if self._state is None or self._generation != generation:
            self._generation = generation
            self._state = NetnsState.read(self.name)
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
            opened.pop(name).close()
        if outermost:
            _SESSION.open = None


@contextlib.contextmanager
def netns(name: str) -> Iterator[Netns]:
    """Open a namespace; within a session() the shared one."""
    opened: dict[str, Netns] | None = getattr(_SESSION, "open", None)
    if opened is None:
        ns = Netns(name)
        try:
            yield ns
        finally:
            ns.close()
        return
    if name not in opened:
        opened[name] = Netns(name, keep=_keeps())
    try:
        yield opened[name]
    except BaseException as e:
        # A failed change may have left the snapshot behind.
        opened[name].invalidate()
        if isinstance(e, OSError) and name in opened and opened[name].keep:
            # The socket may be broken: open a new one on the next use.
            forget(name)
            opened.pop(name).close()
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


def _routes(messages: list[rtmsg], names: dict[int, str]) -> dict[IPNetwork, Route]:
    """Return the routes of route messages by destination."""
    routes = (_route_from_msg(msg, names) for msg in messages)
    return {route.dst: route for route in routes}


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
    state.routes = _routes(owned_route_messages(ipr.netns), names)


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
