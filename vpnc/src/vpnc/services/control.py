"""Stop, start and reset connections until vpnc restarts.

A stopped connection stays down: IPsec is unloaded from charon, WireGuard has
no peer and SSH doesn't run. Its interface remains.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import TYPE_CHECKING

import vici
import vici.exception

from vpnc import shared
from vpnc.models import enums
from vpnc.models.ipsec import Initiation
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
    """The connection can't be stopped, started or reset."""


def _vici() -> contextlib.AbstractContextManager[vici.Session]:
    return charon.session(charon.VICI_TIMEOUT + TERMINATE_TIMEOUT)


def _terminate(name: str, *, force: bool = False) -> None:
    """Terminate a connection's IKE SAs; with force without telling the peer."""
    request = {"ike": name, "timeout": str(TERMINATE_TIMEOUT * 1000)}
    if force:
        request["force"] = "yes"
    with _vici() as vcs, contextlib.suppress(vici.exception.CommandException):
        # Fails when there's no SA, or the peer doesn't confirm in time.
        for _ in vcs.terminate(request):
            pass


def _initiate(name: str, connection: Connection) -> None:
    if connection.config.initiation != Initiation.INITIATOR:
        # The peer sets the connection up again.
        return
    with _vici() as vcs, contextlib.suppress(vici.exception.CommandException):
        # Don't wait: an unreachable peer would block.
        for _ in vcs.initiate({"ike": name, "child": name, "timeout": "-1"}):
            pass


def _check(connection: Connection) -> enums.ConnectionType:
    ctype = connection.config.type
    if ctype == enums.ConnectionType.PHYSICAL:
        msg = "A physical connection can't be stopped, started or reset."
        raise ControlError(msg)
    return ctype


def _apply(ni: NetworkInstance, connection: Connection) -> None:
    """Make the connection as configured, or stopped."""
    ctype = connection.config.type
    if ctype == enums.ConnectionType.IPSEC:
        strongswan.apply(ni)
    elif ctype == enums.ConnectionType.WIREGUARD:
        wireguard.sync(ni, connection, connection.intf_name(ni))
    elif ctype == enums.ConnectionType.SSH:
        ssh.start(ni, connection)


def stop(ni: NetworkInstance, connection: Connection) -> None:
    """Stop a connection."""
    ctype = _check(connection)
    name = f"{ni.id}-{connection.id}"
    with LOCK:
        logger.info("Stopping connection %s.", name)
        shared.STOPPED_CONNECTIONS.add(name)
        _apply(ni, connection)
        if ctype == enums.ConnectionType.IPSEC:
            _terminate(name)


def start(ni: NetworkInstance, connection: Connection) -> None:
    """Start a stopped connection."""
    ctype = _check(connection)
    name = f"{ni.id}-{connection.id}"
    with LOCK:
        logger.info("Starting connection %s.", name)
        shared.STOPPED_CONNECTIONS.discard(name)
        _apply(ni, connection)
        if ctype == enums.ConnectionType.IPSEC:
            _initiate(name, connection)


def reset(ni: NetworkInstance, connection: Connection, *, force: bool = False) -> None:
    """Set a connection up again: a new IKE SA, WireGuard session or SSH session.

    With force, IKE SAs are removed without waiting for the peer.
    """
    ctype = _check(connection)
    name = f"{ni.id}-{connection.id}"
    if name in shared.STOPPED_CONNECTIONS:
        msg = f"{name} is stopped; start it instead."
        raise ControlError(msg)
    with LOCK:
        logger.info("Resetting connection %s.", name)
        if ctype == enums.ConnectionType.IPSEC:
            _terminate(name, force=force)
            _initiate(name, connection)
            return
        # Removes the WireGuard peer or stops ssh, then sets it up again.
        shared.STOPPED_CONNECTIONS.add(name)
        try:
            _apply(ni, connection)
        finally:
            shared.STOPPED_CONNECTIONS.discard(name)
        _apply(ni, connection)
