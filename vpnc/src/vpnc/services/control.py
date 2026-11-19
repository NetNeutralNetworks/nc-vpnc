"""Apply a connection's enabled setting right away, and reset connections.

A disabled connection (enabled: false) stays down: its interface is down, IPsec
is unloaded from charon, WireGuard has no peer and SSH doesn't run.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from vpnc.models import enums
from vpnc.models.ipsec import Initiation
from vpnc.network import state
from vpnc.services import ssh, wireguard
from vpnc.services.strongswan import strongswan

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

LOCK = threading.Lock()


class ControlError(Exception):
    """The connection can't be reset."""


def _initiate(name: str, connection: Connection) -> None:
    # A responder's peer sets the connection up again.
    if connection.config.initiation == Initiation.INITIATOR:
        strongswan.initiate(name)


def _apply_service(ni: NetworkInstance, connection: Connection) -> None:
    """Load or unload IPsec, set or remove the WireGuard peer, run or stop ssh."""
    ctype = connection.config.type
    if ctype == enums.ConnectionType.IPSEC:
        strongswan.apply(ni)
    elif ctype == enums.ConnectionType.WIREGUARD:
        wireguard.sync(ni, connection, connection.intf_name(ni))
    elif ctype == enums.ConnectionType.SSH:
        ssh.start(ni, connection)


def _apply(ni: NetworkInstance, connection: Connection) -> None:
    """Make the connection as configured: enabled or disabled."""
    # An XFRM interface follows its SAs.
    if connection.config.type != enums.ConnectionType.IPSEC:
        with state.netns(ni.id) as netns:
            state.ensure_link_state(
                netns.ipr,
                netns.state,
                connection.intf_name(ni),
                up=connection.enabled,
            )
    _apply_service(ni, connection)


def apply(ni: NetworkInstance, connection: Connection) -> None:
    """Enable or disable a connection as configured, without waiting for a check."""
    name = connection.name(ni)
    with LOCK:
        logger.info(
            "%s connection %s.",
            "Enabling" if connection.enabled else "Disabling",
            name,
        )
        _apply(ni, connection)
        if connection.config.type != enums.ConnectionType.IPSEC:
            return
        if connection.enabled:
            _initiate(name, connection)
        else:
            strongswan.terminate(name)


def reset(ni: NetworkInstance, connection: Connection, *, force: bool = False) -> None:
    """Set a connection up again: a new IKE SA, WireGuard session or SSH session.

    With force, IKE SAs are removed without waiting for the peer.
    """
    ctype = connection.config.type
    name = connection.name(ni)
    if ctype == enums.ConnectionType.PHYSICAL:
        msg = "A physical connection can't be reset."
        raise ControlError(msg)
    if not connection.enabled:
        msg = f"{name} is disabled; start it instead."
        raise ControlError(msg)
    with LOCK:
        logger.info("Resetting connection %s.", name)
        if ctype == enums.ConnectionType.IPSEC:
            strongswan.terminate(name, force=force)
            _initiate(name, connection)
            return
        # Removes the WireGuard peer or stops ssh, then sets it up again.
        _apply_service(ni, connection.model_copy(update={"enabled": False}))
        _apply_service(ni, connection)
