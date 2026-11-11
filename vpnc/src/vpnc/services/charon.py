"""Sessions with charon over vici, with a timeout."""

from __future__ import annotations

import contextlib
import socket
from typing import TYPE_CHECKING

import vici

if TYPE_CHECKING:
    from collections.abc import Iterator

VICI_SOCKET = "/var/run/charon.vici"
# Seconds before a VICI request fails, so a hanging charon can't block vpnc.
VICI_TIMEOUT = 10


@contextlib.contextmanager
def session(timeout: float | None = VICI_TIMEOUT) -> Iterator[vici.Session]:
    """Open a vici session whose requests fail (OSError) after timeout seconds."""
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(timeout)
    try:
        sock.connect(VICI_SOCKET)
        yield vici.Session(sock)
    finally:
        sock.close()
