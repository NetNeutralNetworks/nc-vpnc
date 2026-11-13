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
from vpnc.services import charon, ssh, wireguard
from vpnc.services.strongswan import strongswan

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# Seconds to wait for the peer to confirm a terminated IKE SA.
TERMINATE_TIMEOUT = 5

LOCK = threading.Lock()


class ControlError(Exception):
    """The connection can't be reset."""


def _terminate(name: str, *, force: bool = False) -> None:
    """Terminate a connection's IKE SAs; with force without telling the peer."""
    with charon.session(charon.VICI_TIMEOUT + TERMINATE_TIMEOUT) as vcs:
        # Fails when there's no SA, or the peer doesn't confirm in time.
        charon.terminate(
            vcs,
            ike=name,
            wait=TERMINATE_TIMEOUT,
            force=force,
            warn=False,
        )


def _initiate(name: str, connection: Connection) -> None:
    if connection.config.initiation != Initiation.INITIATOR:
        # The peer sets the connection up again.
        return
    with charon.session() as vcs:
        charon.initiate(vcs, name, warn=False)


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
            _terminate(name)


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
            _terminate(name, force=force)
            _initiate(name, connection)
            return
        # Removes the WireGuard peer or stops ssh, then sets it up again.
        _apply_service(ni, connection.model_copy(update={"enabled": False}))
        _apply_service(ni, connection)
