"""Manages vpncmangle startup and shutdown as well as the configuration."""

import atexit
import json
import logging
import pathlib
import subprocess
from ipaddress import IPv4Network
from typing import Any

from vpnc import config, files, helpers, shared
from vpnc.network import namespace
from vpnc.services import configuration

logger = logging.getLogger("vpnc")

CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpncmangle/translations.json")


def generate_config() -> None:
    """Generate vpncmangle configuration."""
    output: dict[str, dict[str, Any]] = {}

    with shared.VPNCMANGLE_LOCK:
        for net_ni in helpers.network_instances().values():
            if net_ni.id in (config.CORE_NI, config.EXTERNAL_NI):
                continue
            output[net_ni.id] = {"dns64": [], "dns66": []}
            if nat64_scope := configuration.get_network_instance_nat64_scope(net_ni):
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

        files.ensure_file(CONFIG_PATH, json.dumps(output))


# The running vpncmangle process.
PROCESS: subprocess.Popen[bytes] | None = None


def stop() -> None:
    """Shut down the vpncmangle service when terminating the program."""
    if PROCESS is None:
        return
    logger.info("Stopping vpncmangle process in network instance %s.", config.CORE_NI)
    PROCESS.terminate()
    PROCESS.wait()


atexit.register(stop)


def start() -> None:
    """Start the the vpncmangle service in the CORE network instance."""
    # VPNC in hub mode doctors DNS responses so requests are sent via the tunnel.
    # Start the VPNC mangle process in the CORE network instance.
    # This process mangles DNS responses to translate A responses to AAAA responses.
    logger.info("Starting vpncmangle process in network instance %s.", config.CORE_NI)
    proc = namespace.popen(
        config.CORE_NI,
        [f"{config.VPNC_INSTALL_DIR}/bin/vpncmangle"],
    )

    global PROCESS  # noqa: PLW0603
    PROCESS = proc


def ensure_running() -> None:
    """Restart vpncmangle if it isn't running."""
    if PROCESS is not None and PROCESS.poll() is None:
        return
    logger.warning("vpncmangle isn't running. Starting it.")
    start()
