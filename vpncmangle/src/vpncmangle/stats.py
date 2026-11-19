"""Counters of the DNS answers vpncmangle handled, written to a file for vpnc."""

from __future__ import annotations

import collections
import json
import logging
import pathlib
import threading
import time

from . import nftables

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
# Over the service's dns limits: max_size, max_records, and rate_limit (which
# nftables counts, before the queue).
OVERSIZED = "OVERSIZED"
TOO_MANY_RECORDS = "TOO_MANY_RECORDS"
RATE_LIMITED = "RATE_LIMITED"

_LOCK = threading.Lock()
_STARTED = time.time()
# By network instance.
_TRANSLATED: collections.Counter[str] = collections.Counter()
_DROPPED: collections.Counter[str] = collections.Counter()
# By reason, and by network instance and reason.
_REASONS: collections.Counter[str] = collections.Counter()
_NI_REASONS: collections.Counter[tuple[str, str]] = collections.Counter()


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
            _NI_REASONS[ni_id, reason] += 1


def write() -> None:
    """Write the counters (since vpncmangle started) atomically."""
    limited = nftables.rate_limited()
    with _LOCK:
        reasons = dict(_REASONS)
        if limited:
            reasons[RATE_LIMITED] = sum(limited.values())
        by_ni = {(ni, RATE_LIMITED): count for ni, count in limited.items()}
        by_ni.update(_NI_REASONS)
        data = {
            "started": _STARTED,
            "written": time.time(),
            "translated": sum(_TRANSLATED.values()),
            "dropped": reasons,
            "network_instances": {
                ni: {
                    "translated": _TRANSLATED[ni],
                    "dropped": _DROPPED[ni] + limited.get(ni, 0),
                    "reasons": {
                        reason: count
                        for (name, reason), count in sorted(by_ni.items())
                        if name == ni
                    },
                }
                for ni in sorted({*_TRANSLATED, *_DROPPED, *limited})
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
