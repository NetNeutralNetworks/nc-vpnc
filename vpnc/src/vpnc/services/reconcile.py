"""Reconcile the configured state with the actual state.

Every check is idempotent: it compares the configuration with the system and
only changes what differs. The full check runs every FULL_CHECK_INTERVAL
seconds as a safety net for missed events and manual changes. Events call
trigger() to run a check sooner, for the affected keys only.

Checks run one at a time in a single worker thread, in registration order.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from pyroute2 import netns

from vpnc import config, shared
from vpnc.network import namespace
from vpnc.services import routes

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

    def _run(self) -> None:
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
            if full_check:
                next_full_check = time.monotonic() + self.interval

            self.run_checks(pending)


def check_network_instances(keys: set[str] | None) -> None:
    """Reconcile configured network instances; on a full check remove leftovers."""
    configured = {
        ni.id: ni
        for tenant in list(config.VPNC_CONFIG_TENANT.values())
        for ni in tenant.network_instances.values()
    }
    for ni_id, network_instance in configured.items():
        if keys is not None and ni_id not in keys:
            continue
        try:
            network_instance.reconcile()
        except Exception:
            logger.exception("Reconciling network instance %s failed.", ni_id)

    if keys is not None:
        return
    for name in netns.listnetns():
        if config.DOWNLINK_NI_RE.match(name) and name not in configured:
            logger.warning("Removing unconfigured network instance %s.", name)
            routes.stop(name)
            namespace.delete(name)
    routes.delete_stale_core_routes(list(configured.values()))


# The reconciler of the service.
RECONCILER = Reconciler()
