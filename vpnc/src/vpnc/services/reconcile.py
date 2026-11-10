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
from typing import TYPE_CHECKING

from pyroute2 import netns

from vpnc import config, shared
from vpnc.models import enums, tenant
from vpnc.network import namespace
from vpnc.services import configuration, frr, routes

if TYPE_CHECKING:
    from vpnc.models.network_instance import NetworkInstance

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


# The configuration last applied per network instance, to remove what's gone.
APPLIED: dict[str, NetworkInstance] = {}


def configured_network_instances() -> dict[str, tuple[str, NetworkInstance]]:
    """Return the configured network instances with their tenant id."""
    return {
        ni.id: (tenant.id, ni)
        for tenant in list(config.VPNC_CONFIG_TENANT.values())
        for ni in tenant.network_instances.values()
    }


def check_network_instances(keys: set[str] | None) -> None:
    """Reconcile network instances; remove the ones no longer configured."""
    configured = configured_network_instances()
    updated_tenants: set[str] = set()
    for ni_id, (tenant_id, network_instance) in configured.items():
        if keys is not None and ni_id not in keys:
            continue
        try:
            if network_instance.reconcile(APPLIED.get(ni_id)):
                updated_tenants.add(tenant_id)
            APPLIED[ni_id] = network_instance
        except Exception:
            logger.exception("Reconciling network instance %s failed.", ni_id)

    for tenant_id in updated_tenants:
        configuration.write_tenant(tenant_id)
    remove_unconfigured(configured, keys)


def remove_unconfigured(
    configured: dict[str, tuple[str, NetworkInstance]],
    keys: set[str] | None,
) -> None:
    """Remove network instances that are no longer configured."""
    for ni_id in list(APPLIED):
        if ni_id in configured or (keys is not None and ni_id not in keys):
            continue
        logger.info("Removing network instance %s.", ni_id)
        try:
            remove_network_instance(APPLIED.pop(ni_id))
        except Exception:
            logger.exception("Removing network instance %s failed.", ni_id)

    if keys is not None:
        return
    # Leftovers vpnc doesn't know about (e.g. from before a restart).
    for name in netns.listnetns():
        if config.DOWNLINK_NI_RE.match(name) and name not in configured:
            logger.warning("Removing unknown network instance %s.", name)
            routes.stop(name)
            namespace.delete(name)
    routes.delete_stale_core_routes([ni for _, ni in configured.values()])


def remove_network_instance(network_instance: NetworkInstance) -> None:
    """Remove a network instance with its connections, VPN and routing config."""
    config.IPSEC_CONFIG_DIR.joinpath(f"{network_instance.id}.conf").unlink(
        missing_ok=True,
    )
    network_instance.delete()
    if tenant.get_default_tenant().mode == enums.ServiceMode.HUB:
        frr.generate_config()


def check_routes(keys: set[str] | None) -> None:
    """Reconcile the routes of network instances (after link changes)."""
    for ni_id, (_, network_instance) in configured_network_instances().items():
        if keys is not None and ni_id not in keys:
            continue
        if not namespace.exists(ni_id):
            continue
        with (
            namespace.IPRoute(ni_id) as ni_dl,
            namespace.IPRoute(config.CORE_NI) as ni_core,
        ):
            routes.reconcile_routes(ni_dl, ni_core, network_instance, None)


# The reconciler of the service.
RECONCILER = Reconciler()
RECONCILER.register("network_instances", check_network_instances)
RECONCILER.register("routes", check_routes)
# Link changes (e.g. a tunnel going down) only affect routes.
routes.ON_LINK_EVENT = lambda ni_id: RECONCILER.trigger("routes", ni_id)
