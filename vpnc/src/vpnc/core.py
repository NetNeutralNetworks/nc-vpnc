"""Runs the core of the application.

Sets up the network and starts the monitors and
observers.
"""

import logging
import pathlib
import sys
import time

import vpnc
from vpnc import api, config, eventlog, helpers, shared
from vpnc.models import enums
from vpnc.models.network_instance import NetworkInstance
from vpnc.network import events, namespace
from vpnc.services import (
    configuration,
    frr,
    network_instances,
    snmp,
    strongswan,
    vpncmangle,
    watchdog,
    wireguard,
)
from vpnc.services.reconciler import RECONCILER

logger = logging.getLogger("vpnc")


def prepare_namespaces() -> None:
    """Mount the DEFAULT namespace and create the CORE namespace."""
    # The system's namespace as DEFAULT, to use it as any other network instance.
    logger.info("Mounting default namespace as %s", config.DEFAULT_NI)
    namespace.add_own(config.DEFAULT_NI)

    # Create CORE up front: threads opening it concurrently would race to create it.
    namespace.add(name=config.CORE_NI)


def start_hub_services() -> None:
    """Start Jool, vpncmangle and FRR (hub mode)."""
    # NAT64 with Jool, loaded at boot (/etc/modules-load.d/vpnc.conf): the unit
    # can't load modules.
    if not pathlib.Path("/sys/module/jool").is_dir():
        logger.critical("The kernel module Jool isn't loaded.")
        sys.exit(1)

    # VPNC in hub mode doctors DNS responses so requests are sent via the tunnel.
    # Start the VPNC mangle process in the CORE network instance.
    # This process mangles DNS responses to translate A responses to AAAA responses.
    vpncmangle.start()
    RECONCILER.register("vpncmangle", lambda _: vpncmangle.ensure_running())

    # VPNC in hub mode uses FRR to exchange routes. Start FRR to make sure it can
    # load the CORE and EXTERNAL network instances
    frr.start()
    RECONCILER.register("frr", lambda _: frr.ensure_reloaded())


def apply_or_exit(network_instance: NetworkInstance) -> None:
    """Set up a network instance of the service; without it vpnc can't run."""
    try:
        network_instances.apply(network_instance)
    except ValueError:
        sys.exit(1)


def concentrator() -> None:  # noqa: PLR0915 (the start sequence)
    """Set up the DEFAULT tenant."""
    default_tenant = helpers.get_default_tenant()
    logger.info("#" * 100)
    eventlog.record(
        "STARTED",
        f"vpnc {vpnc.__version__} started in {default_tenant.mode.value} mode",
        tenant=config.DEFAULT_TENANT,
    )

    # Before anything triggers them. Checks run in the order they're registered.
    RECONCILER.register(
        "configuration",
        lambda keys: configuration.rescan() if keys is None else None,
    )
    RECONCILER.register("network_instances", network_instances.check)
    RECONCILER.register("routes", network_instances.check_routes)

    prepare_namespaces()
    # Written again as the connections are set up.
    wireguard.remove_files()

    # Create and mount the EXTERNAL network instance.
    # This provides VPN connectivity
    apply_or_exit(default_tenant.network_instances[config.EXTERNAL_NI])

    # The IPSec process must be started in the EXTERNAL network instance.
    strongswan.start()

    # Start the VPNC Security Association monitor to fix duplicate connections.
    logger.info("Starting Strongswan monitor")
    sa_mon = strongswan.Monitor(daemon=True)
    sa_mon.start()

    def check_connections(keys: set[str] | None) -> None:
        """Reconcile charon's connections, then reset connections that stay down.

        Both use one listing of the SAs.
        """
        sas_listing = None
        try:
            sas_listing = sa_mon.reconcile_connections()
        finally:
            watchdog.check(keys, sas_listing)

    RECONCILER.register("connections", check_connections)
    RECONCILER.register("status", watchdog.note)

    # Create and mount the CORE network instance. This provides the management
    # connectivity. The CORE namespace has no internet connectivity.
    apply_or_exit(default_tenant.network_instances[config.CORE_NI])
    if default_tenant.mode == enums.ServiceMode.ENDPOINT:
        apply_or_exit(default_tenant.network_instances[config.ENDPOINT_NI])

    if default_tenant.mode == enums.ServiceMode.HUB:
        start_hub_services()

    # Start the event handler.
    logger.info("Monitoring tenant config changes.")
    configuration_obs = configuration.observe()
    configuration_obs.start()

    config_files = list(config.VPNC_A_CONFIG_DIR.glob(pattern="*.yaml"))
    for file_path in config_files:
        configuration.manage_tenant(file_path, check=False)

    # Apply the configuration and keep correcting differences from it.
    RECONCILER.start()

    # Without one of these vpnc does nothing, unnoticed: exit, so it's restarted.
    threads = {
        "reconciler": RECONCILER,
        "link monitor": events.MONITOR,
        "configuration watcher": configuration_obs,
        "API": api.start(),
    }
    if frr.OBSERVER is not None:
        threads["FRR watcher"] = frr.OBSERVER

    # Monitoring only: vpnc runs without it.
    snmp.start()

    # Keep the program running, but terminate if needed.
    try:
        while not shared.STOP_EVENT.is_set():
            time.sleep(1)
            dead = [name for name, thread in threads.items() if not thread.is_alive()]
            if dead and not shared.STOP_EVENT.is_set():
                logger.critical("Stopped unexpectedly: %s. Exiting.", ", ".join(dead))
                sys.exit(1)
    except KeyboardInterrupt:
        shared.STOP_EVENT.set()
    except Exception:
        logger.critical(
            "VPNC ended prematurely.",
            exc_info=True,
        )
        sys.exit(1)
