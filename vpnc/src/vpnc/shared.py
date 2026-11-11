"""Shared items that aren't configuration related."""

from __future__ import annotations

import threading

# Define a global stop event
STOP_EVENT = threading.Event()

# Lock to update/reload the vpncmangle configuration.
VPNCMANGLE_LOCK = threading.Lock()

# Connections stopped through the API (e.g. C0001-00-0), until vpnc restarts.
STOPPED_CONNECTIONS: set[str] = set()
