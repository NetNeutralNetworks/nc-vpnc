"""Reset connections that stay down, e.g. stuck halfway through setting up.

Runs in the full check. A connection that isn't up for RESET_AFTER seconds is
reset, like `vpnctl connections reset`. So is one that's up while none of its
probes is answered. Each reset that doesn't help doubles the wait, up to
RESET_AFTER_MAX. An IPsec responder that isn't up is only reset when it has an
SA (a half-state): only its peer can set it up. An SSH connection isn't reset
while the connection its server is routed via is down.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from vpnc import config, eventlog, helpers, shared
from vpnc.api import status
from vpnc.models import enums
from vpnc.models.ipsec import Initiation
from vpnc.services import control, failures, peers, probes

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# Longer than charon retransmits an IKE request (165s with the defaults).
RESET_AFTER = 180
RESET_AFTER_MAX = 1800


@dataclass
class Down:
    """Since when a connection is down, and how often it was reset since."""

    since: float
    resets: int = 0


# Connections that may need a reset, by name.
DOWN: dict[str, Down] = {}


def resettable(current: status.ConnectionState, connection: Connection) -> bool:
    """Return whether a reset could set the connection up."""
    if current.oper_status == "UP" or current.admin_status == "DOWN":
        return False
    ctype = connection.config.type
    if ctype == enums.ConnectionType.IPSEC:
        return (
            connection.config.initiation == Initiation.INITIATOR
            or current.oper_status == "DORMANT"
        )
    if ctype in (enums.ConnectionType.WIREGUARD, enums.ConnectionType.SSH):
        # Without its interface, the network instance check creates it first.
        return current.interface is not None
    return False


def works(current: status.ConnectionState) -> bool:
    """Return whether a connection is up and, if it has any, a probe is answered."""
    return current.oper_status == "UP" and not probes.failing(current.id)


def path_down(
    connection: Connection,
    ni: NetworkInstance,
    states: dict[str, status.ConnectionState],
) -> bool:
    """Return whether an SSH server is routed via a connection that doesn't work."""
    if connection.config.type != enums.ConnectionType.SSH:
        return False
    server = connection.config.remote_addrs[0]
    return any(
        not works(states[other.name(ni)])
        for other in ni.connections.values()
        if other is not connection
        and other.name(ni) in states
        and any(
            server in route.to
            for route in other.routes.all
            if route.to.version == server.version
        )
    )


def check(
    keys: set[str] | None,
    sas_listing: list[dict[str, Any]] | None = None,
) -> None:
    """Reset the connections that have been down too long.

    With the SAs as just listed (as vici returns them), if given.
    """
    if keys is not None:
        return
    peers.sample()
    note_bgp()
    network_instances = list(helpers.network_instances().values())
    connections: dict[str, tuple[NetworkInstance, Connection]] = {
        c.name(ni): (ni, c) for ni in network_instances for c in ni.connections.values()
    }
    states = {
        s.id: s
        for s in status.connection_states(
            network_instances,
            interfaces=False,
            sas_listing=sas_listing,
        )
    }
    probes.run(
        [
            connections[s.id]
            for s in states.values()
            if s.id in connections and s.oper_status == "UP" and s.admin_status == "UP"
        ],
        {name: connection for name, (_, connection) in connections.items()},
    )
    failures.keep(set(connections))
    now = time.monotonic()
    down: set[str] = set()
    for current in states.values():
        if current.id not in connections:
            continue
        ni, connection = connections[current.id]
        if works(current) or current.admin_status == "DOWN":
            continue
        entry = DOWN.get(current.id)
        failing = probes.failing(current.id)
        if not (failing or resettable(current, connection)) or path_down(
            connection,
            ni,
            states,
        ):
            # A reset can't help now. Earlier resets still count once it can.
            if entry is not None and entry.resets:
                down.add(current.id)
                entry.since = now
            continue
        down.add(current.id)
        if entry is None:
            entry = DOWN[current.id] = Down(since=now)
        wait = min(RESET_AFTER * 2**entry.resets, RESET_AFTER_MAX)
        if now - entry.since < wait:
            continue
        eventlog.record(
            "AUTO_RESET",
            f"reset by vpnc: {eventlog.duration(now - entry.since)} "
            + ("without an answered probe" if failing else current.oper_status),
            connection=current.id,
            level=logging.WARNING,
            reason="PROBES" if failing else current.oper_status,
            resets=entry.resets + 1,
        )
        _reset(ni, connection)
        entry.since = now
        entry.resets += 1

    for name in DOWN.keys() - down:
        del DOWN[name]


# Per BGP neighbor: whether its session is established, and since when.
BGP: dict[str, tuple[bool, float]] = {}
# When vpnc started: a session established since is an event when first seen.
STARTED = time.time()


def _established_at(text: str | None) -> float | None:
    """Return a session's last_established as Unix time, if known."""
    try:
        return dt.datetime.fromisoformat(text).timestamp() if text else None
    except ValueError:
        return None


def note_bgp() -> None:
    """Record the BGP sessions (hub mode) that came up or went down, as CORE's."""
    if not helpers.is_hub():
        return
    try:
        neighbors = status.bgp_neighbors()
    except Exception:  # noqa: BLE001 (e.g. FRR is restarting)
        return
    now = time.time()
    for neighbor in neighbors:
        address = neighbor.neighbor_address
        established = neighbor.session_state == "ESTABLISHED"
        was, since = BGP.get(address, (None, now))
        if was is not None and was == established:
            continue
        changed = now
        if was is None:
            # The first time it's seen: a change only if it was established since
            # vpnc started (before the first full check).
            up = _established_at(neighbor.last_established) if established else None
            if up is None or up < STARTED:
                BGP[address] = (established, up or now)
                continue
            since, changed = STARTED, up
        BGP[address] = (established, changed)
        name = f"{address} ({neighbor.hostname})" if neighbor.hostname else address
        lasted = eventlog.duration(changed - since)
        if established:
            message = f"BGP session with {name} established, was down for {lasted}"
        else:
            message = (
                f"BGP session with {name} down ({neighbor.session_state}), was "
                f"established for {lasted}"
            )
        eventlog.record(
            "BGP_ESTABLISHED" if established else "BGP_DOWN",
            message,
            network_instance=config.CORE_NI,
            level=logging.INFO if established else logging.WARNING,
            neighbor_address=address,
        )
    for address in BGP.keys() - {n.neighbor_address for n in neighbors}:
        del BGP[address]


def note(keys: set[str] | None) -> None:
    """Note the oper status of the connections of network instances (keys) now.

    After a link changed, so the change is an event right away. The full check
    notes all of them, in check().
    """
    if keys is None:
        return
    configured = helpers.network_instances()
    status.connection_states(
        [configured[key] for key in keys if key in configured],
        interfaces=False,
    )


def _reset(ni: NetworkInstance, connection: Connection) -> None:
    """Reset a connection and count it."""
    name = connection.name(ni)
    try:
        control.reset(ni, connection, force=True)
    except Exception:
        logger.exception("Resetting connection %s failed.", name)
    reset_at = time.time()
    shared.AUTO_RESETS[name] = [
        *(
            t
            for t in shared.AUTO_RESETS.get(name, [])
            if t >= reset_at - shared.AUTO_RESET_HISTORY
        ),
        reset_at,
    ]
