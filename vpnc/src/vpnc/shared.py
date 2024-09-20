"""Shared items that aren't configuration related."""

from __future__ import annotations

import threading

# Define a global stop event
STOP_EVENT = threading.Event()

# Lock/mutex when editing a network instance.
NI_LOCK: dict[str, threading.Lock] = {}

# Lock used to create the NI_LOCK as that step can happen concurrently if files
# are edited quickly.
NI_START_LOCK = threading.Lock()
