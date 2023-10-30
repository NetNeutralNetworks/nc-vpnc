#!/usr/bin/env python3
"""
Starts the service and runs it in either endpoint or hub mode
"""


import logging
import sys
from logging.handlers import RotatingFileHandler

from . import config, helpers, vpnc_endpoint, vpnc_hub

# LOGGER
# Get logger
logger = logging.getLogger("vpnc")


def main():
    """
    Runs the VPNC service.
    """
    # Configure logging
    logger.setLevel(level=logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s(File:%(name)s,Line:%(lineno)d, %(funcName)s) - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %H:%M:%S %p",
    )
    rothandler = RotatingFileHandler(
        "/var/log/ncubed.vpnc.log", maxBytes=100000, backupCount=5
    )
    rothandler.setFormatter(formatter)
    logger.addHandler(rothandler)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    # Load the configuration
    logger.info("Loading configuration from '%s'.", config.VPNC_A_SERVICE_CONFIG_PATH)
    if not config.VPNC_A_SERVICE_CONFIG_PATH.exists():
        logger.critical(
            "Configuration not found at '%s'.", config.VPNC_A_SERVICE_CONFIG_PATH
        )
        sys.exit(1)

    # Load the global configuration from file.
    helpers.load_config(config.VPNC_A_SERVICE_CONFIG_PATH)

    # Start the service
    if config.VPNC_SERVICE_CONFIG.mode.name == "HUB":
        vpnc_hub.main()
    elif config.VPNC_SERVICE_CONFIG.mode.name == "ENDPOINT":
        vpnc_endpoint.main()


if __name__ == "__main__":
    main()
