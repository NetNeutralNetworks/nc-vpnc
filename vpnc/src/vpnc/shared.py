"""Shared items that aren't configuration related."""

from __future__ import annotations

import threading

# Define a global stop event
STOP_EVENT = threading.Event()

# Lock to update/reload the vpncmangle configuration.
VPNCMANGLE_LOCK = threading.Lock()
