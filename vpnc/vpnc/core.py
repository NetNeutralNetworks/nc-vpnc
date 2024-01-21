"""
Runs the core of the application which sets up the network and starts the monitors and observers.
"""

import logging
import subprocess
import sys

from . import config, connections, models, monitors
from .network import interface, namespace, route

logger = logging.getLogger("vpnc")


def concentrator():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """
    logger.info("#" * 100)
    logger.info("Starting ncubed VPNC strongSwan daemon in hub mode.")

    # Remove old swanctl config files
    for file in config.VPN_CONFIG_DIR.iterdir():
        file.unlink(missing_ok=True)

    # Mounts the default network namespace with the alias ROOT. This makes for consistent operation
    # between all namespaces
    logger.info("Mounting default namespace as ROOT")
    subprocess.run(
        """
        touch /var/run/netns/ROOT
        mount --bind /proc/1/ns/net /var/run/netns/ROOT
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    logger.info("Setting up %s netns", config.UNTRUSTED_NETNS)
    ns_name = config.UNTRUSTED_NETNS
    ns = namespace.add(ns_name, cleanup=False)

    untrust = config.VPNC_SERVICE_CONFIG.network.untrust
    untrust_if = interface.get(name=untrust.interface, ns_name="*")
    if not untrust_if:
        logger.critical(
            "Untrusted interface not found in any namespace. Please check the name."
        )
        sys.exit(1)
    untrust_if = interface.set(
        inf=untrust_if,
        state="up",
        addresses=untrust.addresses,
        ns_name=ns,
        cleanup=False,
    )
    for i in untrust.routes:
        route.set(
            route=i.to,
            next_hop=i.via,
            ns_name=ns,
            cleanup=True,
            inf_index=untrust_if["index"],
        )

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.ENDPOINT:
        # Enable IPv6 and IPv4 on the default namespace.
        logger.info("Setting up ROOT netns.")
        subprocess.run(
            """
            sysctl -w net.ipv6.conf.all.forwarding=1
            sysctl -w net.ipv4.conf.all.forwarding=1
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )  # .stdout.decode().lower()

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        # The trusted namespace has no internet connectivity.
        logger.info("Setting up %s netns.", config.TRUSTED_NETNS)
        namespace.add(name=config.TRUSTED_NETNS, cleanup=False)
        # IPv6 routing is enabled on the namespace.
        subprocess.run(
            f"""
            ip netns exec {config.TRUSTED_NETNS} sysctl -w net.ipv6.conf.all.forwarding=1
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=True,
        )

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
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

    subprocess.run(
        f"""
        # Run Strongswan in the untrusted namespace.
        ip netns exec {config.UNTRUSTED_NETNS} ipsec start
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    # Start the VPNC Security Association monitor to fix duplicate connections.
    logger.info("Monitoring IKE/IPsec security associations.")
    sa_mon = monitors.VpncMonitor(daemon=True)
    sa_mon.start()

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        # Start the VPNC mangle process in the TRUSTED net namespace.
        # This process mangles DNS responses to translate A responses to AAAA responses.
        sp = subprocess.Popen(  # pylint: disable=consider-using-with
            [
                "ip",
                "netns",
                "exec",
                config.TRUSTED_NETNS,
                f"{config.VPNC_INSTALL_DIR}/bin/vpncmangle",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        logger.info(sp.args)

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        # Reload FRR to make sure it can load the namespaces
        logger.info("Restarting FRR.")
        subprocess.run(
            """
            systemctl reload frr.service
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=True,
        )

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        connections.update_uplink_connection()

        # Start the event handler.
        logger.info("Monitoring uplink config changes.")
        uplink_obs = connections.uplink_observer()
        uplink_obs.start()

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        connections.update_downlink_connection()
    else:
        connections.update_downlink_connection_endpoint()

    # Start the event handler.
    logger.info("Monitoring downlink config changes.")
    downlink_obs = connections.downlink_observer()
    downlink_obs.start()
