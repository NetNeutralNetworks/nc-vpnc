"""Applies and removes network instances and their routes: the reconciler's checks.

Every check is idempotent: it compares the configuration with the system and
only changes what differs.
"""

from __future__ import annotations

import atexit
import logging
from typing import TYPE_CHECKING, Any

from pyroute2 import netns

from vpnc import config, eventlog, helpers
from vpnc.models import enums
from vpnc.models.network_instance import (
    forget_firewall,
    jool_instances,
    open_external,
)
from vpnc.network import events, namespace, state
from vpnc.services import configuration, frr, ssh, strongswan
from vpnc.services.reconciler import RECONCILER

if TYPE_CHECKING:
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# The network instances that can have IPsec connections.
IPSEC_TYPES = (enums.NetworkInstanceType.CORE, enums.NetworkInstanceType.DOWNLINK)
# The configuration last applied per network instance, to remove what's gone.
APPLIED: dict[str, NetworkInstance] = {}
# Network instances whose link and address events are watched, with the identity
# of their namespace.
WATCHED: dict[str, tuple[int, int]] = {}


def configured_network_instance(tenant_id: str, ni_id: str) -> NetworkInstance | None:
    """Return a network instance as configured now; None if it isn't anymore."""
    if (tenant_config := config.VPNC_CONFIG_TENANT.get(tenant_id)) is None:
        return None
    return next(
        (ni for ni in tenant_config.network_instances.values() if ni.id == ni_id),
        None,
    )


def apply(network_instance: NetworkInstance) -> bool:
    """Reconcile a network instance and its routes.

    Returns whether the configuration was updated (new NPTv6 prefixes).
    """
    previous = APPLIED.get(network_instance.id)
    if previous is network_instance:
        # Unchanged: nothing of it is gone.
        previous = None
    with state.session():
        updated = network_instance.reconcile(previous)
        if network_instance.type in IPSEC_TYPES:
            strongswan.apply(network_instance)
        if network_instance.type == enums.NetworkInstanceType.CORE and helpers.is_hub():
            frr.generate_config()
        if watch(network_instance.id):
            # The links were read before they were monitored: read them again,
            # so no change is missed.
            state.changed(network_instance.id)
        reconcile_routes(network_instance, previous)
    APPLIED[network_instance.id] = network_instance
    return updated


def check(keys: set[str] | None) -> None:
    """Reconcile network instances; remove the ones no longer configured.

    A full check runs triggered checks between network instances, so changes don't
    wait for it. The configuration is looked up per network instance, as it can
    change meanwhile. It reads CORE, which holds every network instance's link and
    routes, and the Jool instances once instead of per network instance.
    """
    if keys is None:
        state.forget_stale()
        # Opened below; a missing CORE would fail every full check.
        namespace.add(name=config.CORE_NI)
        with state.session(), state.netns(config.CORE_NI), jool_instances():
            _check(keys)
    else:
        _check(keys)


def _check(keys: set[str] | None) -> None:
    # First: new peers are accepted before their connections are loaded.
    open_external()
    updated_tenants: set[str] = set()
    for ni_id, configured in list(helpers.network_instances().items()):
        if keys is not None and ni_id not in keys:
            continue
        tenant_id = configured.tenant_id
        if keys is None:
            RECONCILER.run_triggered()
        network_instance = configured_network_instance(tenant_id, ni_id)
        if network_instance is None:
            continue
        try:
            if apply(network_instance):
                updated_tenants.add(tenant_id)
        except Exception:
            logger.exception("Reconciling network instance %s failed.", ni_id)

    # With what vpnc assigned or learned: NPTv6 prefixes, SSH host keys.
    for tenant_id in updated_tenants | ssh.adopt_host_keys():
        configuration.write_tenant(tenant_id)
    remove_unconfigured(helpers.network_instances(), keys)
    ssh.delete_unconfigured_keys()


def remove_unconfigured(
    configured: dict[str, NetworkInstance],
    keys: set[str] | None,
) -> None:
    """Remove network instances that are no longer configured."""
    for ni_id in list(APPLIED):
        if ni_id in configured or (keys is not None and ni_id not in keys):
            continue
        eventlog.record("REMOVED", "removed", network_instance=ni_id)
        # Forgotten only once removed, so a failure is retried.
        try:
            remove(APPLIED[ni_id])
        except Exception:
            logger.exception("Removing network instance %s failed.", ni_id)
        else:
            del APPLIED[ni_id]

    if keys is not None:
        return
    # Leftovers vpnc doesn't know about (e.g. from before a restart).
    for name in netns.listnetns():
        if config.DOWNLINK_NI_RE.match(name) and name not in configured:
            logger.warning("Removing unknown network instance %s.", name)
            unwatch(name)
            namespace.delete(name)
            forget_firewall(name)
            # The kernel deleted its link to CORE.
            state.changed(config.CORE_NI)
    delete_stale_core_routes(list(configured.values()))


def remove(network_instance: NetworkInstance) -> None:
    """Remove a network instance with its connections, routes and VPN config."""
    strongswan.remove(network_instance.id)
    unwatch(network_instance.id)
    state.forget(network_instance.id)
    network_instance.delete()
    # The kernel deleted its link to CORE.
    state.changed(config.CORE_NI)
    delete_core_routes(network_instance)
    if helpers.is_hub():
        frr.generate_config()


def watch(ni_id: str) -> bool:
    """Reconcile a network instance when its links or global addresses change.

    Link changes only affect its routes. Returns whether it wasn't watched yet.
    """
    identity = state.netns_identity(ni_id)
    if WATCHED.get(ni_id) == identity:
        return False
    # The namespace was replaced: the old socket is in, and keeps, the old one.
    unwatch(ni_id)

    def on_event(event: dict[str, Any]) -> None:
        state.changed(ni_id)
        if event["event"] in ("RTM_NEWLINK", "RTM_DELLINK"):
            RECONCILER.trigger("routes", ni_id)
            # A connection may have gone up or down.
            RECONCILER.trigger("status", ni_id)
        elif event["event"] == events.RESYNC:
            RECONCILER.trigger("routes", ni_id)
            RECONCILER.trigger("network_instances", ni_id)
        elif (
            event["event"] in events.ADDRESS_EVENTS
            and event["scope"] == state.RT_SCOPE_UNIVERSE
        ):
            RECONCILER.trigger("network_instances", ni_id)

    logger.info("Monitoring the links of network instance %s.", ni_id)
    events.MONITOR.watch(ni_id, on_event)
    WATCHED[ni_id] = identity
    # Registered after the namespace cleanup, so it runs before it.
    atexit.register(unwatch, ni_id)
    return True


def unwatch(ni_id: str) -> None:
    """Stop monitoring the links of a network instance."""
    if WATCHED.pop(ni_id, None) is not None:
        logger.info("Stopped monitoring the links of network instance %s.", ni_id)
        events.MONITOR.unwatch(ni_id)


def reconcile_routes(
    net_inst: NetworkInstance,
    previous: NetworkInstance | None = None,
) -> None:
    """Make the routes of a network instance, and its routes in CORE, as desired.

    Routes of removed connections or destinations are deleted. In CORE only this
    network instance's destinations (current and previous) and routes via its link
    are managed, as CORE holds the routes of all network instances.
    """
    if net_inst.type == enums.NetworkInstanceType.CORE and helpers.is_hub():
        return

    with (
        state.session(),
        state.netns(net_inst.id) as dl,
        state.netns(config.CORE_NI) as core,
    ):
        ni_dl, ni_state = dl.ipr, dl.state
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

        managed = _core_destinations(core, net_inst, [*core_routes, *previous_core])
        state.ensure_routes(core.ipr, core.state, core_routes, managed=managed)


def _core_destinations(
    core: state.Netns,
    net_inst: NetworkInstance,
    routes: list[state.Route],
) -> set[state.IPNetwork]:
    """Return the destinations in CORE of the routes and of routes via its link."""
    core_link = net_inst.veth_core
    return {r.dst for r in routes} | {
        dst for dst, route in core.state.routes.items() if route.dev == core_link
    }


def delete_core_routes(net_inst: NetworkInstance) -> None:
    """Delete a network instance's routes in CORE."""
    if not net_inst.linked_to_core:
        return
    _, core_routes = net_inst.desired_routes({})
    with state.netns(config.CORE_NI) as core:
        managed = _core_destinations(core, net_inst, core_routes)
        state.ensure_routes(core.ipr, core.state, [], managed=managed)


def delete_stale_core_routes(network_instances: list[NetworkInstance]) -> None:
    """Delete vpnc's routes in CORE that no configured network instance wants."""
    wanted: set[state.IPNetwork] = set()
    for net_inst in network_instances:
        ni_routes, core_routes = net_inst.desired_routes({})
        wanted |= {r.dst for r in core_routes}
        if net_inst.id == config.CORE_NI:
            wanted |= {r.dst for r in ni_routes}
    with state.netns(config.CORE_NI) as core:
        stale = set(core.state.routes) - wanted
        if stale:
            state.ensure_routes(core.ipr, core.state, [], managed=stale)


def check_routes(keys: set[str] | None) -> None:
    """Reconcile the routes of network instances whose links changed.

    Full checks skip this: check() already reconciles all routes.
    """
    if keys is None:
        return
    for ni_id, network_instance in helpers.network_instances().items():
        if ni_id in keys and namespace.exists(ni_id):
            reconcile_routes(network_instance)
