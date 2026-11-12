"""Sessions with charon over vici, with a timeout, and its SAs."""

from __future__ import annotations

import contextlib
import logging
import socket
import time
from typing import TYPE_CHECKING, Any

import vici
import vici.exception

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger("vpnc")

VICI_SOCKET = "/var/run/charon.vici"
# Seconds before a VICI request fails, so a hanging charon can't block vpnc.
VICI_TIMEOUT = 10
# Seconds between tries to connect.
RETRY_DELAY = 2


def _connect(timeout: float | None, tries: int) -> socket.socket:
    for attempt in range(1, tries + 1):
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(timeout)
        try:
            sock.connect(VICI_SOCKET)
        except (ConnectionRefusedError, FileNotFoundError, TimeoutError):
            sock.close()
            if attempt == tries:
                raise
            logger.info("VICI socket is not yet available. Retrying.")
            time.sleep(RETRY_DELAY)
        except BaseException:
            sock.close()
            raise
        else:
            return sock
    raise ValueError(tries)


@contextlib.contextmanager
def session(
    timeout: float | None = VICI_TIMEOUT,
    *,
    tries: int = 1,
) -> Iterator[vici.Session]:
    """Open a vici session whose requests fail (OSError) after timeout seconds.

    Use timeout=None to listen for events, and tries when charon may be starting.
    """
    sock = _connect(timeout, tries)
    try:
        yield vici.Session(sock)
    finally:
        sock.close()


def decode(value: Any) -> Any:  # noqa: ANN401
    """Return what vici returned with its bytes as strings."""
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, dict):
        return {k: decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode(v) for v in value]
    return value


def is_initiator(connection: dict[str, Any]) -> bool:
    """Return whether a list-conns entry is an initiator (close_action=start)."""
    return any(
        child.get("close_action") == b"start"
        for child in connection.get("children", {}).values()
    )


def sa_up(ike_sa: dict[str, Any]) -> bool:
    """Return whether an IKE SA is established and has an installed child SA.

    As vici returns it, or decoded. During rekeying, reauthentication or with
    duplicate SAs a connection has multiple SAs, some of which are being
    deleted: it's up if any of them is.
    """
    return ike_sa.get("state") in (b"ESTABLISHED", "ESTABLISHED") and any(
        child.get("state") in (b"INSTALLED", "INSTALLED")
        for child in ike_sa.get("child-sas", {}).values()
    )


def initiate(vcs: vici.Session, name: str, *, warn: bool = True) -> None:
    """Initiate a connection, without waiting: an unreachable peer would block."""
    try:
        for _ in vcs.initiate({"ike": name, "child": name, "timeout": "-1"}):
            pass
    except vici.exception.CommandException:
        if warn:
            logger.warning("Initiating '%s' failed.", name, exc_info=True)


def terminate(  # noqa: PLR0913
    vcs: vici.Session,
    *,
    ike: str | None = None,
    ike_id: str | bytes | None = None,
    child_id: str | bytes | None = None,
    wait: int | None = None,
    force: bool = False,
    warn: bool = True,
) -> None:
    """Terminate the IKE SAs of a connection (ike), or one IKE or child SA by id.

    Doesn't wait for the peer to confirm, unless given the seconds to wait.
    With force the SA is removed without telling the peer.
    """
    request: dict[str, str | bytes] = {
        key: value
        for key, value in (("ike", ike), ("ike-id", ike_id), ("child-id", child_id))
        if value is not None
    }
    described = decode(request)
    request["timeout"] = "-1" if wait is None else str(wait * 1000)
    if force:
        request["force"] = "yes"
    try:
        for _ in vcs.terminate(request):
            pass
    except vici.exception.SessionException:
        logger.warning("Terminating SA %s may have failed.", described, exc_info=True)
    except vici.exception.CommandException:
        # Also when there's no SA, or the peer doesn't confirm in time.
        if warn:
            logger.warning("Terminating SA %s failed.", described, exc_info=True)
