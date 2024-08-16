"""
Runs the core of the application which sets up the network and starts the monitors and observers.
"""

import logging
import subprocess
import sys
import time

from . import config, frr, models, network_instance, strongswan, vpncmangle

logger = logging.getLogger("vpnc")


def concentrator():
    """
    Creates the CORE and EXTERNAL network instance (Linux namespace) and aliases the DEFAULT network
    instace.
    """
    logger.info("#" * 100)
    logger.info(
        "Starting ncubed VPNC strongSwan daemon in %s mode.",
        config.VPNC_SERVICE_CONFIG.mode.name,
    )

    # Mount the DEFAULT network instance with it's alias. This makes for consistent operation
    # between all network instances
    logger.info("Mounting default namespace as %s", config.DEFAULT_NI)
    subprocess.run(
        f"""
        mkdir -m=755 -p /var/run/netns/
        touch /var/run/netns/{config.DEFAULT_NI}
        mount --bind /proc/1/ns/net /var/run/netns/{config.DEFAULT_NI}
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )

    # Create and mount the EXTERNAL network instance.
    # This provides VPN connectivity
    logger.info("Setting up %s network instance", config.EXTERNAL_NI)
    external_ni = config.VPNC_SERVICE_CONFIG.network_instances[config.EXTERNAL_NI]
    try:
        network_instance.add_network_instance(external_ni)
    except ValueError:
        logger.critical("Setting up the EXTERNAL network instance failed.")
        sys.exit(1)
    network_instance.add_external_iptables(external_ni)

    # Create and mount the CORE network instance. This provides the management connectivity
    # The CORE namespace has no internet connectivity.
    core_ni = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    try:
        network_instance.add_network_instance(core_ni)
    except ValueError:
        logger.critical("Setting up the CORE network instance failed.")
        sys.exit(1)

    # The IPSec process must be started in the EXTERNAL network instance.
    strongswan.start()

    logger.info("Monitoring swantcl config changes.")
    swan_obs = strongswan.observe()
    swan_obs.start()

    # Start the VPNC Security Association monitor to fix duplicate connections.
    logger.info("Monitoring IKE/IPsec security associations for errors.")
    sa_mon = strongswan.Monitor(daemon=True)
    sa_mon.start()

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        # VPNC in hub mode performs NAT64 using Jool. The kernel module must be loaded before it can
        # be used.
        subprocess.run(
            """
            # Load the NAT64 kernel module (jool).
            modprobe jool
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=True,
        )

        # VPNC in hub mode doctors DNS responses so requests are sent via the tunnel.
        # Start the VPNC mangle process in the CORE network instance.
        # This process mangles DNS responses to translate A responses to AAAA responses.
        logger.info("Start vpncmangle.")
        vpncmangle.start()

        # VPNC in hub mode uses FRR to exchange routes. Start FRR to make sure it can load the
        # CORE and EXTERNAL network instances
        logger.info("Start FRR.")
        frr.start()

        logger.info("Monitoring frr config changes.")
        frr_obs = frr.observe()
        frr_obs.start()

    # Start the event handler.
    logger.info("Monitoring CORE config changes.")
    core_obs = network_instance.observe_core()
    core_obs.start()

    # Start the event handler.
    logger.info("Monitoring downlink config changes.")
    downlink_obs = network_instance.observe_downlink()
    downlink_obs.start()

    network_instance.update_core_network_instance()
    network_instance.update_downlink_network_instance()

    while True:
        time.sleep(0.1)
