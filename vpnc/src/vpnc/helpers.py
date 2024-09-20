"""Miscellaneous functions used throughout the service."""

from __future__ import annotations

import logging
import subprocess
import sys

from vpnc import config, shared

logger = logging.getLogger("vpnc")


def signal_handler(*_: object) -> None:
    """Shut down the program gracefully."""
    logger.info("SIGTERM received. Stopping all threads.")
    shared.STOP_EVENT.set()


def check_system_requirements() -> None:
    """Check if required kernel modules are installed."""
    module_list: list[str] = ["xfrm_interface", "xt_MASQUERADE", "xt_nat", "veth"]
    module: str = ""
    try:
        for module in module_list:
            logger.debug("Verifying kernel module %s is installed", module)
            subprocess.run(  # noqa: S603
                ["/usr/sbin/modinfo", module],
                check=True,
                stdout=subprocess.PIPE,
            )
    except subprocess.CalledProcessError:
        logger.critical("The '%s' kernel module isn't installed. Exiting.", module)
        sys.exit(1)

    if config.VPNC_CONFIG_SERVICE.mode.value != "hub":
        return

    hub_module_list: list[str] = []
    try:
        for module in hub_module_list:
            logger.debug("Verifying kernel module %s is installed", module)
            subprocess.run(  # noqa: S603
                ["/usr/sbin/modinfo", module],
                stdout=subprocess.PIPE,
                check=True,
            )
    except subprocess.CalledProcessError:
        logger.critical("The '%s' kernel module isn't installed. Exiting.", module)
        sys.exit(1)
