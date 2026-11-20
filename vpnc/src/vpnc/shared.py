"""Shared items that aren't configuration related."""

from __future__ import annotations

import threading
import time

# Define a global stop event
STOP_EVENT = threading.Event()
# When vpnc started (Unix time): what's set up since is an event when first seen.
# Less a second: peers and FRR give times in whole seconds.
STARTED = time.time() - 1

# Lock to update/reload the vpncmangle configuration.
VPNCMANGLE_LOCK = threading.Lock()

# When (Unix time) the watchdog reset a connection, by connection name.
AUTO_RESETS: dict[str, list[float]] = {}
# Resets are counted over this many seconds.
AUTO_RESET_HISTORY = 86400
