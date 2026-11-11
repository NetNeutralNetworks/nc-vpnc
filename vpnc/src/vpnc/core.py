"""Runs the core of the application.

Sets up the network and starts the monitors and
observers.
"""

import logging
import subprocess
import sys
import time

from vpnc import api, config, shared
from vpnc.models import enums, tenant
from vpnc.network import events, namespace
from vpnc.services import (
    configuration,
    frr,
    reconcile,
    strongswan,
    vpncmangle,
)

logger = logging.getLogger("vpnc")


def prepare_namespaces() -> None:
    """Mount the DEFAULT namespace and create the CORE namespace."""
    # Mount the DEFAULT network instance with it's alias. This makes for consistent
    # operation between all network instances
    logger.info("Mounting default namespace as %s", config.DEFAULT_NI)
    proc = subprocess.run(  # noqa: S602
        f"""
        mkdir -m=755 -p /var/run/netns/
        touch /var/run/netns/{config.DEFAULT_NI}
        mount --bind /proc/1/ns/net /var/run/netns/{config.DEFAULT_NI}
        """,
        stdout=subprocess.PIPE,
        shell=True,
        check=True,
    )
    logger.debug(proc.stdout)

    # Create CORE up front: threads opening it concurrently would race to create it.
    namespace.add(name=config.CORE_NI)


def start_hub_services() -> None:
    """Start Jool, vpncmangle and FRR (hub mode)."""
    # VPNC in hub mode performs NAT64 using Jool. The kernel module must be loaded
    # before it can be used.
    # Load the NAT64 kernel module (jool). This may cause the program to exit if
    # it fails to start
    logger.info("Loading kernel module Jool.")
    proc = subprocess.run(  # noqa: S603
        ["/usr/sbin/modprobe", "jool"],
        stdout=subprocess.PIPE,
        check=True,
    )
    logger.debug(proc.stdout)

    # VPNC in hub mode doctors DNS responses so requests are sent via the tunnel.
    # Start the VPNC mangle process in the CORE network instance.
    # This process mangles DNS responses to translate A responses to AAAA responses.
    vpncmangle.start()
    reconcile.RECONCILER.register("vpncmangle", lambda _: vpncmangle.ensure_running())

    # VPNC in hub mode uses FRR to exchange routes. Start FRR to make sure it can
    # load the CORE and EXTERNAL network instances
    frr.start()
    reconcile.RECONCILER.register("frr", lambda _: frr.ensure_reloaded())


def concentrator() -> None:
    """Set up the DEFAULT tenant."""
    default_tenant = tenant.get_default_tenant()
    logger.info("#" * 100)
    logger.info(
        "Starting ncubed vpnc daemon in %s mode.",
        default_tenant.mode,
    )

    prepare_namespaces()

    # Create and mount the EXTERNAL network instance.
    # This provides VPN connectivity
    external_ni = default_tenant.network_instances[config.EXTERNAL_NI]
    try:
        reconcile.apply_network_instance(external_ni)
    except ValueError:
        sys.exit(1)

    # The IPSec process must be started in the EXTERNAL network instance.
    strongswan.start()

    # Start the VPNC Security Association monitor to fix duplicate connections.
    logger.info("Starting Strongswan monitor")
    sa_mon = strongswan.Monitor(daemon=True)
    sa_mon.start()
    reconcile.RECONCILER.register(
        "strongswan",
        lambda _: sa_mon.reconcile_connections(),
    )

    # Create and mount the CORE network instance. This provides the management
    # connectivity. The CORE namespace has no internet connectivity.
    core_ni = default_tenant.network_instances[config.CORE_NI]
    try:
        reconcile.apply_network_instance(core_ni)
    except ValueError:
        sys.exit(1)
    if default_tenant.mode == enums.ServiceMode.ENDPOINT:
        endpoint_ni = default_tenant.network_instances[config.ENDPOINT_NI]
        try:
            reconcile.apply_network_instance(endpoint_ni)
        except ValueError:
            sys.exit(1)

    if default_tenant.mode == enums.ServiceMode.HUB:
        start_hub_services()

    # Start the event handler.
    logger.info("Monitoring tenant config changes.")
    configuration_obs = configuration.observe_configuration()
    configuration_obs.start()

    config_files = list(config.VPNC_A_CONFIG_DIR.glob(pattern="*.yaml"))
    for file_path in config_files:
        configuration.manage_tenant(file_path)

    # Apply the configuration and keep correcting differences from it.
    reconcile.RECONCILER.start()

    # Without one of these vpnc does nothing, unnoticed: exit, so it's restarted.
    threads = {
        "reconciler": reconcile.RECONCILER,
        "link monitor": events.MONITOR,
        "configuration watcher": configuration_obs,
        "API": api.start(),
    }
    if frr.OBSERVER is not None:
        threads["FRR watcher"] = frr.OBSERVER

    # Keep the program running, but terminate if needed.
    try:
        while not shared.STOP_EVENT.is_set():
            time.sleep(1)
            dead = [name for name, thread in threads.items() if not thread.is_alive()]
            if dead and not shared.STOP_EVENT.is_set():
                logger.critical("Stopped unexpectedly: %s. Exiting.", ", ".join(dead))
                sys.exit(1)
    except KeyboardInterrupt:
        shared.STOP_EVENT.is_set()
    except Exception:
        logger.critical(
            "VPNC ended prematurely.",
            exc_info=True,
        )
        sys.exit(1)
