"""Shared items that aren't configuration related."""

from __future__ import annotations

import threading
import time

# Define a global stop event
STOP_EVENT = threading.Event()

# Lock to update/reload the vpncmangle configuration.
VPNCMANGLE_LOCK = threading.Lock()

# Connections stopped through the API (e.g. C0001-00-0), until vpnc restarts.
STOPPED_CONNECTIONS: set[str] = set()

# When (Unix time) the watchdog reset a connection, by connection name.
AUTO_RESETS: dict[str, list[float]] = {}
# Resets are counted over this many seconds.
AUTO_RESET_HISTORY = 86400


def auto_resets(name: str) -> int:
    """Return how often the watchdog reset a connection in the last 24 hours."""
    since = time.time() - AUTO_RESET_HISTORY
    return sum(t >= since for t in AUTO_RESETS.get(name, []))
