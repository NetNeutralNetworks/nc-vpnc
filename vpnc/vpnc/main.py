#!/usr/bin/env python3
"""
Starts the service and runs it in either endpoint or hub mode
"""


import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler

from . import config, vpnc_endpoint, vpnc_hub

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

    # Parse the arguments
    parser = argparse.ArgumentParser(description="Control the VPNC Strongswan daemon")
    parser.set_defaults(func=parser.print_usage)
    subparser = parser.add_subparsers(help="Sub command help")

    parser_start = subparser.add_parser(
        name="hub", help="Starts the VPN service in hub mode"
    )
    parser_start.set_defaults(func=vpnc_hub.main)

    parser_start = subparser.add_parser(
        name="endpoint", help="Starts the VPN service in endpoint mode"
    )
    parser_start.set_defaults(func=vpnc_endpoint.main)

    args = parser.parse_args()

    args.func()


if __name__ == "__main__":
    main()
