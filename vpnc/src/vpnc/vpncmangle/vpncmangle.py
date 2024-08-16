"""
Manages vpncmangle startup and shutdown as well as the configuration
"""

import atexit
import json
import logging
import pathlib
import subprocess
from ipaddress import IPv4Network, IPv6Network

from .. import config, network_instance

logger = logging.getLogger("vpnc")


def generate_config():
    """
    Generates vpncmangle configuration
    """

    output: dict[str, list[tuple[str, str]]] = {}

    for _, tenant in config.VPNC_TENANT_CONFIG.items():
        for _, net_ni in tenant.network_instances.items():
            nat64_scope = network_instance.get_network_instance_nat64_scope(net_ni.name)
            output[net_ni.name] = {}
            output[net_ni.name]["dns64"] = [
                (str(nat64_scope), str(IPv4Network("0.0.0.0/0")))
            ]
            for connection in net_ni.connections:
                output[net_ni.name]["dns66"] = []
                for route6 in connection.routes.ipv6:
                    nptv6_prefix = route6.nptv6_prefix
                    if not nptv6_prefix:
                        nptv6_prefix = route6.to
                    output[net_ni.name]["dns66"].append(
                        (str(nptv6_prefix), str(route6.to))
                    )

    file = pathlib.Path("/opt/ncubed/config/vpncmangle/translations.json")
    file.touch(exist_ok=True)
    with open(file, "w+", encoding="utf-8") as f:
        json.dump(output, f)


def stop(proc: subprocess.Popen[bytes]):
    """
    Shut down the vpncmangle service when terminating the program
    """
    proc.terminate()
    proc.wait()
    logger.info(proc.args)
    logger.debug(proc.stdout)


def start():
    """
    Start the the vpncmangle service in the CORE network instance.
    """

    # VPNC in hub mode doctors DNS responses so requests are sent via the tunnel.
    # Start the VPNC mangle process in the CORE network instance.
    # This process mangles DNS responses to translate A responses to AAAA responses.
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [
            "ip",
            "netns",
            "exec",
            config.CORE_NI,
            f"{config.VPNC_INSTALL_DIR}/bin/vpncmangle",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
    )
    logger.info(proc.args)

    atexit.register(stop, proc)
