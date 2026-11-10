"""Reconcile the configured state with the actual state.

Every check is idempotent: it compares the configuration with the system and
only changes what differs. The full check runs every FULL_CHECK_INTERVAL
seconds as a safety net for missed events and manual changes. Events call
trigger() to run a check sooner, for the affected keys only.

Checks run one at a time in a single worker thread, in registration order.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pyroute2 import netns

from vpnc import config, shared
from vpnc.models import enums, tenant
from vpnc.network import namespace, state
from vpnc.network.events import LinkMonitor
from vpnc.services import configuration, frr

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
# Link monitor per network instance.
MONITORS: dict[str, LinkMonitor] = {}


def configured_network_instances() -> dict[str, tuple[str, NetworkInstance]]:
    """Return the configured network instances with their tenant id."""
    return {
        ni.id: (tenant.id, ni)
        for tenant in list(config.VPNC_CONFIG_TENANT.values())
        for ni in tenant.network_instances.values()
    }


def apply_network_instance(network_instance: NetworkInstance) -> bool:
    """Reconcile a network instance and its routes.

    Returns whether the configuration was updated (new NPTv6 prefixes).
    """
    previous = APPLIED.get(network_instance.id)
    with state.session():
        updated = network_instance.reconcile(previous)
    # Monitor before reading the links again, so no change is missed.
    watch(network_instance.id)
    reconcile_routes(network_instance, previous)
    APPLIED[network_instance.id] = network_instance
    return updated


def check_network_instances(keys: set[str] | None) -> None:
    """Reconcile network instances; remove the ones no longer configured.

    A full check runs triggered checks between network instances, so changes don't
    wait for it. The configuration is looked up per network instance, as it can
    change meanwhile.
    """
    updated_tenants: set[str] = set()
    for ni_id in list(configured_network_instances()):
        if keys is not None and ni_id not in keys:
            continue
        if keys is None:
            RECONCILER.run_triggered()
        if (current := configured_network_instances().get(ni_id)) is None:
            continue
        tenant_id, network_instance = current
        try:
            if apply_network_instance(network_instance):
                updated_tenants.add(tenant_id)
        except Exception:
            logger.exception("Reconciling network instance %s failed.", ni_id)

    for tenant_id in updated_tenants:
        configuration.write_tenant(tenant_id)
    remove_unconfigured(configured_network_instances(), keys)


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
            unwatch(name)
            namespace.delete(name)
    delete_stale_core_routes([ni for _, ni in configured.values()])


def remove_network_instance(network_instance: NetworkInstance) -> None:
    """Remove a network instance with its connections, routes and VPN config."""
    config.IPSEC_CONFIG_DIR.joinpath(f"{network_instance.id}.conf").unlink(
        missing_ok=True,
    )
    unwatch(network_instance.id)
    network_instance.delete()
    delete_core_routes(network_instance)
    if tenant.get_default_tenant().mode == enums.ServiceMode.HUB:
        frr.generate_config()


def watch(ni_id: str) -> None:
    """Reconcile a network instance when its links or global addresses change.

    Link changes only affect its routes.
    """
    if ni_id in MONITORS:
        return

    def on_event(event: Any) -> None:  # noqa: ANN401
        if event["event"] in ("RTM_NEWLINK", "RTM_DELLINK"):
            RECONCILER.trigger("routes", ni_id)
        elif (
            event["event"] in ("RTM_NEWADDR", "RTM_DELADDR")
            and event["scope"] == state.RT_SCOPE_UNIVERSE
        ):
            RECONCILER.trigger("network_instances", ni_id)

    logger.info("Monitoring the links of network instance %s.", ni_id)
    MONITORS[ni_id] = LinkMonitor(ni_id, on_event)
    MONITORS[ni_id].start()
    # Registered after the namespace cleanup, so it runs before it.
    atexit.register(unwatch, ni_id)


def unwatch(ni_id: str) -> None:
    """Stop monitoring the links of a network instance."""
    if (monitor := MONITORS.pop(ni_id, None)) is not None:
        logger.info("Stopped monitoring the links of network instance %s.", ni_id)
        monitor.stop()


def reconcile_routes(
    net_inst: NetworkInstance,
    previous: NetworkInstance | None = None,
) -> None:
    """Make the routes of a network instance, and its routes in CORE, as desired.

    Routes of removed connections or destinations are deleted. In CORE only this
    network instance's destinations (current and previous) and routes via its link
    are managed, as CORE holds the routes of all network instances.
    """
    if (
        net_inst.type == enums.NetworkInstanceType.CORE
        and tenant.get_default_tenant().mode == enums.ServiceMode.HUB
    ):
        return

    with (
        namespace.IPRoute(net_inst.id) as ni_dl,
        namespace.IPRoute(config.CORE_NI) as ni_core,
    ):
        ni_state = state.NetnsState.read(ni_dl)
        ni_routes, core_routes = net_inst.desired_routes(ni_state.links)
        previous_ni: list[state.Route] = []
        previous_core: list[state.Route] = []
        if previous:
            previous_ni, previous_core = previous.desired_routes({})

        if net_inst.type == enums.NetworkInstanceType.CORE:
            # CORE also holds other network instances' routes.
            managed = {r.dst for r in [*ni_routes, *previous_ni]}
            state.ensure_routes(ni_dl, ni_state, ni_routes, managed=managed)
            return
        state.ensure_routes(ni_dl, ni_state, ni_routes)

        core_state = state.NetnsState.read(ni_core)
        core_link = f"{net_inst.id}_C"
        managed = {r.dst for r in [*core_routes, *previous_core]} | {
            dst for dst, route in core_state.routes.items() if route.dev == core_link
        }
        state.ensure_routes(ni_core, core_state, core_routes, managed=managed)


def delete_core_routes(net_inst: NetworkInstance) -> None:
    """Delete a network instance's routes in CORE."""
    if net_inst.type not in (
        enums.NetworkInstanceType.DOWNLINK,
        enums.NetworkInstanceType.ENDPOINT,
    ):
        return
    _, core_routes = net_inst.desired_routes({})
    core_link = f"{net_inst.id}_C"
    with namespace.IPRoute(config.CORE_NI) as ni_core:
        core_state = state.NetnsState.read(ni_core)
        managed = {r.dst for r in core_routes} | {
            dst for dst, route in core_state.routes.items() if route.dev == core_link
        }
        state.ensure_routes(ni_core, core_state, [], managed=managed)


def delete_stale_core_routes(network_instances: list[NetworkInstance]) -> None:
    """Delete vpnc's routes in CORE that no configured network instance wants."""
    wanted: set[state.IPNetwork] = set()
    for net_inst in network_instances:
        ni_routes, core_routes = net_inst.desired_routes({})
        wanted |= {r.dst for r in core_routes}
        if net_inst.id == config.CORE_NI:
            wanted |= {r.dst for r in ni_routes}
    with namespace.IPRoute(config.CORE_NI) as ni_core:
        core_state = state.NetnsState.read(ni_core)
        stale = set(core_state.routes) - wanted
        if stale:
            state.ensure_routes(ni_core, core_state, [], managed=stale)


def check_routes(keys: set[str] | None) -> None:
    """Reconcile the routes of network instances whose links changed.

    Full checks skip this: check_network_instances already reconciles all routes.
    """
    if keys is None:
        return
    for ni_id, (_, network_instance) in configured_network_instances().items():
        if ni_id in keys and namespace.exists(ni_id):
            reconcile_routes(network_instance)


# The reconciler of the service.
RECONCILER = Reconciler()
RECONCILER.register("network_instances", check_network_instances)
RECONCILER.register("routes", check_routes)
