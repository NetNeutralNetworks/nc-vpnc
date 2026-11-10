#!/usr/bin/env python3
"""Starts the service and runs it in either endpoint or hub mode."""

import logging
import signal
import sys
from logging.handlers import RotatingFileHandler

from vpnc import config, core, helpers

# LOGGER
# Get logger
logger = logging.getLogger()


def main() -> None:
    """Run the VPNC service."""
    # Configure logging
    logger.setLevel(level=logging.INFO)
    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s(File:%(name)s,Line:%(lineno)d,"
            "%(funcName)s) - %(levelname)s - %(message)s"
        ),
        datefmt="%m/%d/%Y %H:%M:%S %p",
    )
    rothandler = RotatingFileHandler(
        "/var/log/ncubed/vpnc/vpnc.log",
        maxBytes=100000,
        backupCount=5,
    )
    rothandler.setFormatter(formatter)
    logger.addHandler(rothandler)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    # Load the configuration
    logger.info("Loading configuration from '%s'.", config.VPNC_A_CONFIG_PATH_SERVICE)
    if not config.VPNC_A_CONFIG_PATH_SERVICE.exists():
        logger.critical(
            "Configuration not found at '%s'.",
            config.VPNC_A_CONFIG_PATH_SERVICE,
        )
        sys.exit(1)

    # check for required kernel modules.
    helpers.check_system_requirements()

    # Used to gracefully shutdown, allows the atexit commands to run when a
    # signal is received.
    signal.signal(signal.SIGINT, helpers.signal_handler)
    signal.signal(signal.SIGTERM, helpers.signal_handler)

    # Start the concentrator
    core.concentrator()


if __name__ == "__main__":
    main()
