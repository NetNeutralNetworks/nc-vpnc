#!/usr/bin/env python3

import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler

from . import vpncendpoint, vpnchub


# LOGGER
logger = logging.getLogger("vpncservice")


if __name__ == "__main__":
    # Configure logging if package is run directly
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

    # Parse the arguments
    parser = argparse.ArgumentParser(description="Control the VPNC Strongswan daemon")
    subparser = parser.add_subparsers(help="Sub command help")
    parser_start = subparser.add_parser(
        "hub", help="Starts the VPN service in hub mode"
    )
    parser_start.set_defaults(func=vpnchub.main)
    parser_start = subparser.add_parser(
        "endpoint", help="Starts the VPN service in endpoint mode"
    )
    parser_start.set_defaults(func=vpncendpoint.main)

    args = parser.parse_args()
    args.func()
