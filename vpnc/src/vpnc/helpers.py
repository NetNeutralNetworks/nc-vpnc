"""Miscellaneous functions used throughout the service."""

from __future__ import annotations

import logging
import subprocess
import sys

from vpnc import config, shared
from vpnc.models import enums, tenant

logger = logging.getLogger("vpnc")


def signal_handler(*_: object) -> None:
    """Shut down the program gracefully."""
    logger.info("SIGTERM received. Stopping all threads.")
    shared.STOP_EVENT.set()


def check_system_requirements() -> None:
    """Check if required kernel modules are installed."""
    module_list: list[str] = [
        "xfrm_interface",
        "xt_MASQUERADE",
        "xt_nat",
        "veth",
        "wireguard",
    ]
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

    tenant_config, _ = tenant.load_tenant_config(config.VPNC_A_CONFIG_PATH_SERVICE)
    if not isinstance(tenant_config, (tenant.ServiceHub, tenant.ServiceEndpoint)):
        logger.critical("Service configuration is invalid")
        sys.exit(1)

    if tenant_config.mode != enums.ServiceMode.HUB:
        return

    hub_module_list: list[str] = ["xt_NETMAP", "xt_NFQUEUE"]
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
