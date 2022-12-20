#!/usr/bin/env python3

import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler

from . import consts, vpncendpoint, vpnchub


# LOGGER
# Get logger
logger = logging.getLogger("vpnc")
# Configure logging
logger.setLevel(level=logging.DEBUG)
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
logger.info("Loading configuration from '%s'.", consts.VPNC_A_SERVICE_CONFIG_PATH)
if not consts.VPNC_A_SERVICE_CONFIG_PATH.exists():
    logger.critical(
        "Configuration not found at '%s'.", consts.VPNC_A_SERVICE_CONFIG_PATH
    )
    sys.exit(1)


# Parse the arguments
parser = argparse.ArgumentParser(description="Control the VPNC Strongswan daemon")
parser.set_defaults(func=lambda: parser.print_usage())
subparser = parser.add_subparsers(help="Sub command help")
parser_start = subparser.add_parser("hub", help="Starts the VPN service in hub mode")
parser_start.set_defaults(func=vpnchub.main)
parser_start = subparser.add_parser(
    "endpoint", help="Starts the VPN service in endpoint mode"
)
parser_start.set_defaults(func=vpncendpoint.main)

args = parser.parse_args()

if __name__ == "__main__":
    args.func()
