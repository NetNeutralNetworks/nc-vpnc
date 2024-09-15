"""Runs the core of the application.

Sets up the network and starts the monitors and
observers.
"""

import logging
import subprocess
import sys
import time

import vici

from vpnc import shared

from . import config, models, network_instance
from .services import frr, strongswan, vpncmangle

logger = logging.getLogger("vpnc")


def concentrator() -> None:
    """Set up the DEFAULT tenant."""
    logger.info("#" * 100)
    logger.info(
        "Starting ncubed vpnc daemon in %s mode.",
        config.VPNC_CONFIG_SERVICE.mode.name,
    )

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

    # Create and mount the EXTERNAL network instance.
    # This provides VPN connectivity
    external_ni = config.VPNC_CONFIG_SERVICE.network_instances[config.EXTERNAL_NI]
    try:
        network_instance.set_network_instance(external_ni, None)
    except ValueError:
        logger.critical(
            "Setting up the %s network instance failed.",
            config.EXTERNAL_NI,
        )
        sys.exit(1)
    network_instance.add_external_iptables(external_ni)

    # Create and mount the CORE network instance. This provides the management
    # connectivity. The CORE namespace has no internet connectivity.
    core_ni = config.VPNC_CONFIG_SERVICE.network_instances[config.CORE_NI]
    try:
        network_instance.set_network_instance(core_ni, None)
    except ValueError:
        logger.critical("Setting up the %s network instance failed.", config.CORE_NI)
        sys.exit(1)

    # The IPSec process must be started in the EXTERNAL network instance.
    logger.info("Starting Strongswan process.")
    strongswan.start()
    tries = 50
    delay = 0.1
    for i in range(tries):
        try:
            vici.Session()
            break
        except (ConnectionRefusedError, FileNotFoundError):
            if i >= tries:
                logger.critical(
                    "VICI socket not available after %s tries. Exiting.",
                    tries,
                )
                sys.exit(1)
            logger.info("VICI socket is not yet available. Retrying.")
            time.sleep(delay)
    # Start the VPNC Security Association monitor to fix duplicate connections.
    logger.info("Starting Strongswan monitor")
    sa_mon = strongswan.Monitor(daemon=True)
    sa_mon.start()

    if config.VPNC_CONFIG_SERVICE.mode == models.ServiceMode.HUB:
        # VPNC in hub mode performs NAT64 using Jool. The kernel module must be loaded
        # before it can be used.
        # Load the NAT64 kernel module (jool).
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

        # VPNC in hub mode uses FRR to exchange routes. Start FRR to make sure it can
        # load the CORE and EXTERNAL network instances
        frr.start()

    # Start the event handler.
    logger.info("Monitoring %s network instance config changes.", config.CORE_NI)
    core_obs = network_instance.observe_core()
    core_obs.start()

    # Start the event handler.
    logger.info("Monitoring DOWNLINK network instance config changes.")
    downlink_obs = network_instance.observe_downlink()
    downlink_obs.start()

    network_instance.set_core_network_instance(startup=True)

    config_files = list(config.VPNC_A_CONFIG_DIR.glob(pattern="*.yaml"))
    for file_path in config_files:
        network_instance.manage_downlink_tenant(file_path)

    try:
        while not shared.stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        shared.stop_event.is_set()
    except Exception:
        logger.critical(
            "VPNC ended prematurely.",
            exc_info=True,
        )
        sys.exit(1)
