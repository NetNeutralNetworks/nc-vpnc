"""Manages vpncmangle startup and shutdown as well as the configuration."""

import atexit
import json
import logging
import pathlib
import subprocess
from ipaddress import IPv4Network
from typing import Any

from vpnc import config, network_instance

logger = logging.getLogger("vpnc")


def generate_config() -> None:
    """Generate vpncmangle configuration."""
    output: dict[str, dict[str, Any]] = {}

    for tenant in config.VPNC_CONFIG_TENANT.values():
        for net_ni in tenant.network_instances.values():
            output[net_ni.id] = {"dns64": [], "dns66": []}
            if nat64_scope := network_instance.get_network_instance_nat64_scope(
                net_ni.id,
            ):
                output[net_ni.id]["dns64"] = [
                    (str(nat64_scope), str(IPv4Network("0.0.0.0/0"))),
                ]
            for connection in net_ni.connections.values():
                for route6 in connection.routes.ipv6:
                    nptv6_prefix = route6.nptv6_prefix
                    if not nptv6_prefix:
                        nptv6_prefix = route6.to
                    output[net_ni.id]["dns66"].append(
                        (str(nptv6_prefix), str(route6.to)),
                    )

    file_path = pathlib.Path("/opt/ncubed/config/vpncmangle/translations.json")
    file_path.touch(exist_ok=True)
    with file_path.open("w+", encoding="utf-8") as f:
        json.dump(output, f)


def stop(proc: subprocess.Popen[bytes]) -> None:
    """Shut down the vpncmangle service when terminating the program."""
    proc.terminate()
    proc.wait()


def start() -> None:
    """Start the the vpncmangle service in the CORE network instance."""
    # VPNC in hub mode doctors DNS responses so requests are sent via the tunnel.
    # Start the VPNC mangle process in the CORE network instance.
    # This process mangles DNS responses to translate A responses to AAAA responses.
    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # noqa: S603
        [
            "/usr/sbin/ip",
            "netns",
            "exec",
            config.CORE_NI,
            f"{config.VPNC_INSTALL_DIR}/bin/vpncmangle",
        ],
        shell=False,
    )
    logger.info(proc.args)

    atexit.register(stop, proc)
