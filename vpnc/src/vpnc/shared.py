"""Shared items that aren't configuration related."""

import threading

# Define a global stop event
stop_event = threading.Event()
