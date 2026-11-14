"""Publish the connections and routes over SNMP, as a subagent of snmpd (AgentX).

Standard MIBs only, and only added to what snmpd serves:
- IF-MIB (ifTable, ifXTable): a row per connection. Each object is registered
  on its own, so snmpd keeps answering for its own interfaces.
- MPLS-L3VPN-STD-MIB (mplsL3VpnVrfRteTable): the routes of the main table of
  every network instance, by its name.

Requests are answered from a snapshot, which a second thread refreshes every
REFRESH seconds while connected to snmpd.
"""

from __future__ import annotations

import bisect
import contextlib
import dataclasses
import datetime
import itertools
import logging
import threading
import time
from typing import TYPE_CHECKING, Any

from vpnc import config, helpers, shared
from vpnc.api import status
from vpnc.models import enums
from vpnc.network import state
from vpnc.services import agentx

if TYPE_CHECKING:
    from collections.abc import Callable

    from vpnc.services.agentx import Oid, Value

logger = logging.getLogger("vpnc")

# As in config/snmp/vpnc.conf.
SOCKET = "/var/agentx/master"

IF_ENTRY = (1, 3, 6, 1, 2, 1, 2, 2, 1)
IFX_ENTRY = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1)
ROUTE_ENTRY = (1, 3, 6, 1, 2, 1, 10, 166, 11, 1, 4, 1, 1)
# FRR's bgpd registers the columns of the route table too, for L3VPN VRFs
# (vpnc has none): the lower priority wins.
ROUTE_PRIORITY = 100

# The ifIndex of connections starts here, far above what the kernel hands out.
IF_INDEX_BASE = 1_000_000_000
DEFAULT_NI_NUMBERS = {config.EXTERNAL_NI: 0, config.CORE_NI: 1, config.ENDPOINT_NI: 2}

# Seconds between refreshes of the tables.
REFRESH = 30
# Seconds between connection attempts and between pings.
RETRY = 15

# IF-MIB: ifType, ifAdminStatus and ifOperStatus.
IF_TYPE_ETHERNET = 6
IF_TYPE_TUNNEL = 131
UP = 1
DOWN = 2
DORMANT = 5
# IP-FORWARD-MIB: inetCidrRouteType and IANAipRouteProtocol.
ROUTE_REJECT = 2
ROUTE_LOCAL = 3
ROUTE_REMOTE = 4
ROUTE_BLACKHOLE = 5
ROUTE_TYPES = {6: ROUTE_BLACKHOLE, 7: ROUTE_REJECT, 8: ROUTE_REJECT}
PROTOCOL_OTHER = 1
PROTOCOL_NETMGMT = 3
# By RTPROT_*: redirect, kernel, boot, static, dhcp, vpnc, bgp, isis, ospf, rip
# and eigrp.
PROTOCOLS = {
    1: 4,
    2: 2,
    3: PROTOCOL_NETMGMT,
    4: PROTOCOL_NETMGMT,
    16: 19,
    state.RTPROT_VPNC: PROTOCOL_NETMGMT,
    186: 14,
    187: 9,
    188: 13,
    189: 8,
    192: 16,
}
ROW_ACTIVE = 1


def if_index(name: str) -> int:
    """Return the ifIndex of a connection: derived from its name, so it's stable."""
    ni_id, number = helpers.split_connection_name(name)
    if ni_id in DEFAULT_NI_NUMBERS:
        return IF_INDEX_BASE + DEFAULT_NI_NUMBERS[ni_id] * 10 + int(number)
    # C0001-00-0: tenant C0001 (the C as hex), network instance 00, connection 0.
    tenant = int(ni_id[0], 16) * 10000 + int(ni_id[1:5])
    return IF_INDEX_BASE + tenant * 1000 + int(ni_id[6:8]) * 10 + int(number)


@dataclasses.dataclass(frozen=True)
class Tunnel:
    """A connection as a row of the interface tables."""

    index: int
    state: status.ConnectionState
    # When its oper_status last changed (Unix time).
    changed: float


@dataclasses.dataclass(frozen=True)
class Route:
    """A route as a row of the route table."""

    if_index: int
    type: int
    protocol: int
    metric: int


class Table:
    """A table: its columns by number, and its rows by index."""

    def __init__(
        self,
        entry: Oid,
        columns: dict[int, Callable[[Any], Value | None]],
    ) -> None:
        """Create an empty table."""
        self.entry = entry
        self.columns = columns
        self._numbers = sorted(columns)
        self._rows: tuple[list[Oid], dict[Oid, Any]] = ([], {})

    def fill(self, rows: dict[Oid, Any]) -> None:
        """Replace the rows."""
        self._rows = (sorted(rows), rows)

    def indexes(self) -> set[Oid]:
        """Return the indexes of the rows."""
        return set(self._rows[1])

    def get(self, oid: Oid) -> Value | None:
        """Return the value of an object."""
        size = len(self.entry)
        if oid[:size] != self.entry or len(oid) <= size:
            return None
        row = self._rows[1].get(oid[size + 1 :])
        column = self.columns.get(oid[size])
        return column(row) if row is not None and column else None

    def next(self, oid: Oid, *, include: bool) -> tuple[Oid, Value] | None:
        """Return the first object after oid; or at it, with include."""
        indexes, rows = self._rows
        size = len(self.entry)
        column = position = 0
        if oid[:size] == self.entry and len(oid) > size:
            column = bisect.bisect_left(self._numbers, oid[size])
            if column < len(self._numbers) and self._numbers[column] == oid[size]:
                search = bisect.bisect_left if include else bisect.bisect_right
                position = search(indexes, oid[size + 1 :])
        elif oid > self.entry:
            return None
        for number in self._numbers[column:]:
            for index in itertools.islice(indexes, position, None):
                if (value := self.columns[number](rows[index])) is not None:
                    return (*self.entry, number, *index), value
            position = 0
        return None


def _counter(kind: int, name: str) -> Callable[[Tunnel], Value | None]:
    def column(tunnel: Tunnel) -> Value | None:
        counters = tunnel.state.counters
        return (kind, getattr(counters, name)) if counters else None

    return column


def _name(tunnel: Tunnel) -> Value:
    return agentx.OCTET_STRING, tunnel.state.id.encode()


def _if_type(tunnel: Tunnel) -> Value:
    physical = tunnel.state.type == enums.ConnectionType.PHYSICAL
    return agentx.INTEGER, IF_TYPE_ETHERNET if physical else IF_TYPE_TUNNEL


def _mtu(tunnel: Tunnel) -> Value | None:
    mtu = tunnel.state.mtu
    return (agentx.INTEGER, mtu) if mtu else None


def _admin_status(tunnel: Tunnel) -> Value:
    return agentx.INTEGER, UP if tunnel.state.admin_status == "UP" else DOWN


def _oper_status(tunnel: Tunnel) -> Value:
    current = tunnel.state
    if current.admin_status != "UP":
        return agentx.INTEGER, DOWN
    return agentx.INTEGER, {"UP": UP, "DORMANT": DORMANT}.get(current.oper_status, DOWN)


def _constant(kind: int, value: int | bytes) -> Callable[[Any], Value]:
    return lambda _: (kind, value)


class Mib:
    """The tables, filled from the state of vpnc."""

    def __init__(self) -> None:
        """Create the tables, without rows."""
        # snmpd's sysUpTime now, in hundredths of a second.
        self.uptime: Callable[[], int] = lambda: 0
        # Changes when the tunnels to register may have changed.
        self.version = 0
        counter32 = agentx.COUNTER32
        counter64 = agentx.COUNTER64
        self.interfaces = Table(
            IF_ENTRY,
            {
                1: lambda tunnel: (agentx.INTEGER, tunnel.index),
                2: _name,
                3: _if_type,
                4: _mtu,
                7: _admin_status,
                8: _oper_status,
                9: self._last_change,
                10: _counter(counter32, "in_octets"),
                11: _counter(counter32, "in_pkts"),
                13: _counter(counter32, "in_discards"),
                14: _counter(counter32, "in_errors"),
                16: _counter(counter32, "out_octets"),
                17: _counter(counter32, "out_pkts"),
                19: _counter(counter32, "out_discards"),
                20: _counter(counter32, "out_errors"),
            },
        )
        self.interfaces_x = Table(
            IFX_ENTRY,
            {
                1: _name,
                6: _counter(counter64, "in_octets"),
                7: _counter(counter64, "in_pkts"),
                10: _counter(counter64, "out_octets"),
                11: _counter(counter64, "out_pkts"),
            },
        )
        # From mplsL3VpnVrfRteInetCidrIfIndex on; the columns before are the index.
        self.routes = Table(
            ROUTE_ENTRY,
            {
                7: lambda route: (agentx.INTEGER, route.if_index),
                8: lambda route: (agentx.INTEGER, route.type),
                9: lambda route: (agentx.INTEGER, route.protocol),
                # Age and next hop AS: unknown.
                10: _constant(agentx.GAUGE32, 0),
                11: _constant(agentx.GAUGE32, 0),
                12: lambda route: (agentx.INTEGER, route.metric),
                # Unused metrics.
                **{number: _constant(agentx.INTEGER, -1) for number in range(13, 17)},
                # No label stack.
                17: _constant(agentx.OCTET_STRING, b"\0"),
                18: _constant(agentx.INTEGER, ROW_ACTIVE),
            },
        )
        # In the order of their objects, for next().
        self._tables = (self.interfaces, self.routes, self.interfaces_x)

    def _last_change(self, tunnel: Tunnel) -> Value:
        """Return ifLastChange: snmpd's sysUpTime when the oper_status changed."""
        ago = int((time.time() - tunnel.changed) * 100)
        return agentx.TIMETICKS, max(0, self.uptime() - ago)

    def get(self, oid: Oid) -> Value | None:
        """Return the value of an object."""
        for table in self._tables:
            if (value := table.get(oid)) is not None:
                return value
        return None

    def next(self, oid: Oid, *, include: bool) -> tuple[Oid, Value] | None:
        """Return the first object after oid; or at it, with include."""
        for table in self._tables:
            if found := table.next(oid, include=include):
                return found
        return None

    def load(self) -> None:
        """Fill the tables from the connections and the routes as they are now."""
        tunnels = {
            (if_index(current.id),): Tunnel(
                if_index(current.id),
                current,
                datetime.datetime.fromisoformat(current.last_change).timestamp(),
            )
            for current in status.connection_states()
        }
        if set(tunnels) != self.interfaces.indexes():
            self.version += 1
        self.interfaces.fill(tunnels)
        self.interfaces_x.fill(tunnels)
        self.routes.fill(_routes())


def _route_index(ni_id: str, route: state.KernelRoute, policy: int) -> Oid:
    """Return the index of a route: the VRF name and inetCidrRouteTable's index."""
    family = 1 if route.dst.version == 4 else 2  # noqa: PLR2004
    destination = route.dst.network_address.packed
    name = ni_id.encode()
    index = (len(name), *name, family, len(destination), *destination)
    # The policy tells routes to one destination via one next hop apart.
    index += (route.dst.prefixlen, 2, 0, policy)
    if route.gateway is None:
        return (*index, 0, 0)
    gateway = route.gateway.packed
    return (*index, 1 if route.gateway.version == 4 else 2, len(gateway), *gateway)  # noqa: PLR2004


def _routes() -> dict[Oid, Route]:
    """Return the routes of the main table of every network instance."""
    rows: dict[Oid, Route] = {}
    for ni in list(helpers.network_instances().values()):
        indexes = {
            connection.intf_name(ni): if_index(connection.name(ni))
            for connection in ni.connections.values()
        }
        try:
            routes = state.main_routes(ni.id)
        except OSError:
            # No namespace (yet).
            continue
        for route in routes:
            if route.type in ROUTE_TYPES:
                kind = ROUTE_TYPES[route.type]
            else:
                kind = ROUTE_REMOTE if route.gateway else ROUTE_LOCAL
            row = Route(
                if_index=indexes.get(route.dev or "", 0),
                type=kind,
                protocol=PROTOCOLS.get(route.protocol, PROTOCOL_OTHER),
                metric=route.metric,
            )
            policy = 0
            while (index := _route_index(ni.id, route, policy)) in rows:
                policy += 1
            rows[index] = row
    return rows


MIB = Mib()
_CONNECTED = threading.Event()


def _instances(index: Oid) -> list[Oid]:
    """Return the objects of a row of the interface tables."""
    return [
        (*table.entry, number, *index)
        for table in (MIB.interfaces, MIB.interfaces_x)
        for number in table.columns
    ]


def _session() -> None:
    """Serve snmpd until the connection breaks or vpnc stops."""
    with contextlib.closing(agentx.Session(SOCKET, "vpnc", MIB)) as session:
        logger.info("Connected to snmpd.")
        MIB.uptime = session.uptime
        for number in MIB.routes.columns:
            session.register((*ROUTE_ENTRY, number), ROUTE_PRIORITY)
        registered: set[Oid] = set()
        version = None
        pinged = time.monotonic()
        _CONNECTED.set()
        while not shared.STOP_EVENT.is_set():
            if version != MIB.version:
                version = MIB.version
                wanted = MIB.interfaces.indexes()
                for index in registered - wanted:
                    for oid in _instances(index):
                        session.unregister(oid)
                for index in wanted - registered:
                    for oid in _instances(index):
                        session.register(oid, instance=True)
                registered = wanted
            session.serve(1)
            if time.monotonic() - pinged > RETRY:
                session.ping()
                pinged = time.monotonic()


def _serve() -> None:
    """Keep a session with snmpd, if it runs."""
    waiting = False
    while not shared.STOP_EVENT.is_set():
        try:
            _session()
        except (OSError, agentx.Error) as error:
            if _CONNECTED.is_set() or not waiting:
                logger.info("No connection to snmpd (%s): retrying.", error)
            waiting = True
        except Exception:
            logger.exception("The SNMP subagent failed: starting again.")
        _CONNECTED.clear()
        shared.STOP_EVENT.wait(RETRY)


def _refresh() -> None:
    """Keep the tables up to date while connected to snmpd."""
    loaded = 0.0
    while not shared.STOP_EVENT.wait(1):
        if not _CONNECTED.is_set():
            loaded = 0.0
            continue
        if loaded and time.monotonic() - loaded < REFRESH:
            continue
        try:
            MIB.load()
        except Exception:
            logger.exception("Reading the state for SNMP failed.")
        loaded = time.monotonic()


def start() -> None:
    """Start the SNMP subagent. Without snmpd it keeps trying to connect."""
    for target in (_serve, _refresh):
        name = f"snmp{target.__name__}"
        threading.Thread(target=target, name=name, daemon=True).start()
