"""Counters of the DNS answers vpncmangle handled, written to a file for vpnc."""

from __future__ import annotations

import collections
import json
import logging
import pathlib
import threading
import time

logger = logging.getLogger("vpncmangle")

# vpnc makes the directory, writable for vpncmangle's account.
STATS_PATH = pathlib.Path("/run/vpncmangle/stats.json")
# Seconds between writes.
INTERVAL = 30

# Why answers are dropped.
NOT_DNS = "NOT_DNS"
NO_TRANSLATIONS = "NO_TRANSLATIONS"
UNKNOWN_SOURCE = "UNKNOWN_SOURCE"
ERROR = "ERROR"

_LOCK = threading.Lock()
_STARTED = time.time()
# By network instance.
_TRANSLATED: collections.Counter[str] = collections.Counter()
_DROPPED: collections.Counter[str] = collections.Counter()
# By reason.
_REASONS: collections.Counter[str] = collections.Counter()


def translated(ni_id: str) -> None:
    """Count an answer translated for a network instance."""
    with _LOCK:
        _TRANSLATED[ni_id] += 1


def dropped(reason: str, ni_id: str | None = None) -> None:
    """Count a dropped answer, of a network instance if known."""
    with _LOCK:
        _REASONS[reason] += 1
        if ni_id is not None:
            _DROPPED[ni_id] += 1


def write() -> None:
    """Write the counters (since vpncmangle started) atomically."""
    with _LOCK:
        data = {
            "started": _STARTED,
            "written": time.time(),
            "translated": sum(_TRANSLATED.values()),
            "dropped": dict(_REASONS),
            "network_instances": {
                ni: {"translated": _TRANSLATED[ni], "dropped": _DROPPED[ni]}
                for ni in sorted({*_TRANSLATED, *_DROPPED})
            },
        }
    temporary = STATS_PATH.with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps(data), encoding="utf-8")
        temporary.replace(STATS_PATH)
    except OSError:
        logger.warning("Writing the counters to %s failed.", STATS_PATH)


def start() -> None:
    """Write the counters now and every INTERVAL seconds, in a thread."""

    def run() -> None:
        while True:
            write()
            time.sleep(INTERVAL)

    threading.Thread(target=run, name="stats", daemon=True).start()
