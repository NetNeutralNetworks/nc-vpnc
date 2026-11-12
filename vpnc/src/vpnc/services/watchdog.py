"""Reset connections that stay down, e.g. stuck halfway through setting up.

Runs in the full check. A connection that isn't up for RESET_AFTER seconds is
reset, like `vpnctl connections reset`. Each reset that doesn't help doubles the
wait, up to RESET_AFTER_MAX. An IPsec responder is only reset when it has an SA
that isn't up (a half-state): only its peer can set it up. An SSH connection
isn't reset while the connection its server is routed via is down.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from vpnc import helpers, shared
from vpnc.api import status
from vpnc.models import enums
from vpnc.models.ipsec import Initiation
from vpnc.services import control

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
    if current.state in ("up", "stopped"):
        return False
    ctype = connection.config.type
    if ctype == enums.ConnectionType.IPSEC:
        return (
            connection.config.initiation == Initiation.INITIATOR
            or current.state == "connecting"
        )
    if ctype in (enums.ConnectionType.WIREGUARD, enums.ConnectionType.SSH):
        # Without its interface, the network instance check creates it first.
        return current.interface is not None
    return False


def path_down(
    connection: Connection,
    ni: NetworkInstance,
    states: dict[str, status.ConnectionState],
) -> bool:
    """Return whether an SSH server is routed via a connection that isn't up."""
    if connection.config.type != enums.ConnectionType.SSH:
        return False
    server = connection.config.remote_addrs[0]
    return any(
        states[other.name(ni)].state != "up"
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
    network_instances = list(helpers.network_instances().values())
    connections: dict[str, tuple[NetworkInstance, Connection]] = {
        c.name(ni): (ni, c)
        for ni in network_instances
        for c in ni.connections.values()
    }
    now = time.monotonic()
    down: set[str] = set()
    states = {
        s.id: s
        for s in status.connection_states(
            network_instances,
            interfaces=False,
            sas_listing=sas_listing,
        )
    }
    for current in states.values():
        if current.id not in connections:
            continue
        ni, connection = connections[current.id]
        if not resettable(current, connection) or path_down(connection, ni, states):
            continue
        down.add(current.id)
        entry = DOWN.setdefault(current.id, Down(since=now))
        wait = min(RESET_AFTER * 2**entry.resets, RESET_AFTER_MAX)
        if now - entry.since < wait:
            continue
        logger.warning(
            "Connection %s has been %s for %ds. Resetting it.",
            current.id,
            current.state,
            now - entry.since,
        )
        try:
            control.reset(ni, connection, force=True)
        except Exception:
            logger.exception("Resetting connection %s failed.", current.id)
        entry.since = now
        entry.resets += 1
        reset_at = time.time()
        shared.AUTO_RESETS[current.id] = [
            *(
                t
                for t in shared.AUTO_RESETS.get(current.id, [])
                if t >= reset_at - shared.AUTO_RESET_HISTORY
            ),
            reset_at,
        ]

    for name in DOWN.keys() - down:
        del DOWN[name]
