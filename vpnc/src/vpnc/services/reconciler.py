"""The reconciler: runs checks of the configured state against the actual state.

The full check runs every FULL_CHECK_INTERVAL seconds as a safety net for missed
events and manual changes. Events call trigger() to run a check sooner, for the
affected keys only.

Checks run one at a time in a single worker thread, in registration order.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from vpnc import shared
from vpnc.network import state

logger = logging.getLogger("vpnc")

# Seconds between full checks.
FULL_CHECK_INTERVAL = 30
# Seconds to wait after a trigger, so a burst of events results in one run.
TRIGGER_DELAY = 0.5

# A check gets the keys to reconcile (e.g. network instance names), or None for
# everything.
Check = Callable[[set[str] | None], None]


class Reconciler:
    """Run registered checks periodically (full) and on demand (scoped)."""

    def __init__(
        self,
        interval: float = FULL_CHECK_INTERVAL,
        trigger_delay: float = TRIGGER_DELAY,
    ) -> None:
        """Create a reconciler. Register checks and call start() to run it."""
        self.interval = interval
        self.trigger_delay = trigger_delay
        self._checks: dict[str, Check] = {}
        self._pending: dict[str, set[str] | None] = {}
        self._condition = threading.Condition()
        self._thread: threading.Thread | None = None

    def register(self, name: str, check: Check) -> None:
        """Register a check. Checks run in registration order."""
        with self._condition:
            self._checks[name] = check

    def trigger(self, check: str | None = None, *keys: str) -> None:
        """Run a check soon for the given keys; without keys fully, without check all.

        Unknown checks are ignored.
        """
        with self._condition:
            if check is None:
                self._pending = dict.fromkeys(self._checks)
            elif check in self._checks:
                current = self._pending.get(check, set())
                if not keys:
                    self._pending[check] = None
                elif current is not None:
                    self._pending[check] = current | set(keys)
            self._condition.notify()

    def start(self) -> None:
        """Start the worker thread. A full check runs right away."""
        if self._thread and self._thread.is_alive():
            return
        logger.info("Starting reconciler with checks: %s.", ", ".join(self._checks))
        self._thread = threading.Thread(
            target=self._run,
            name="reconciler",
            daemon=True,
        )
        self._thread.start()

    def is_alive(self) -> bool:
        """Return whether the worker thread runs."""
        return self._thread is not None and self._thread.is_alive()

    def run_checks(self, pending: dict[str, set[str] | None]) -> None:
        """Run the pending checks now, in registration order."""
        for name, check in list(self._checks.items()):
            if name not in pending or shared.STOP_EVENT.is_set():
                continue
            keys = pending[name]
            start = time.monotonic()
            try:
                check(keys)
            except Exception:
                logger.exception("Reconcile check '%s' failed.", name)
            logger.debug(
                "Reconcile check '%s' (%s) took %.2fs.",
                name,
                "full" if keys is None else ", ".join(sorted(keys)),
                time.monotonic() - start,
            )

    def run_triggered(self) -> None:
        """Run the scoped checks triggered so far, e.g. halfway a full check.

        Full triggers stay pending for the worker.
        """
        with self._condition:
            pending = {
                name: keys for name, keys in self._pending.items() if keys is not None
            }
            for name in pending:
                del self._pending[name]
        if pending:
            self.run_checks(pending)

    def _run(self) -> None:
        state.keep_sockets()
        next_full_check = time.monotonic()
        while not shared.STOP_EVENT.is_set():
            with self._condition:
                timeout = max(0.0, next_full_check - time.monotonic())
                if not self._pending and timeout > 0:
                    self._condition.wait(timeout)
            if shared.STOP_EVENT.is_set():
                return

            full_check = time.monotonic() >= next_full_check
            if not full_check:
                # Let a burst of events accumulate.
                time.sleep(self.trigger_delay)
            with self._condition:
                if full_check:
                    pending: dict[str, set[str] | None] = dict.fromkeys(self._checks)
                else:
                    pending = self._pending
                self._pending = {}

            self.run_checks(pending)
            if full_check:
                # From its end: a long full check leaves time for triggered ones.
                next_full_check = time.monotonic() + self.interval


# The reconciler of the service.
RECONCILER = Reconciler()
