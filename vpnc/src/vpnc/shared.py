"""Shared items that aren't configuration related."""

from __future__ import annotations

import threading

# Define a global stop event
STOP_EVENT = threading.Event()

# Lock to update/reload the vpncmangle configuration.
VPNCMANGLE_LOCK = threading.Lock()

# When (Unix time) the watchdog reset a connection, by connection name.
AUTO_RESETS: dict[str, list[float]] = {}
# Resets are counted over this many seconds.
AUTO_RESET_HISTORY = 86400
