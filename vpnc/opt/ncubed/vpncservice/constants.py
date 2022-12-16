#!/usr/bin/env python3

import logging
import pathlib
import re
import sys

import jinja2

logger = logging.getLogger("vpncservice")

# Match only downlink connections
DOWNLINK_RE = re.compile(r"[a-f]\d{4}-\d{3}")

# Configuration file paths/directories
VPN_CONFIG_DIR = pathlib.Path("/etc/swanctl/conf.d")
VPNC_REMOTE_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnc/active/remote")
VPNC_SERVICE_CONFIG_PATH = pathlib.Path(
    "/opt/ncubed/config/vpnc/active/service/config.yaml"
)
VPNC_SERVICE_MODE_PATH = pathlib.Path(
    "/opt/ncubed/config/vpnc/active/service/mode.yaml"
)
# Load the configuration
logger.info("Loading configuration from '%s'.", VPNC_SERVICE_CONFIG_PATH)
if not VPNC_SERVICE_CONFIG_PATH.exists():
    logger.critical("Configuration not found at '%s'.", VPNC_SERVICE_CONFIG_PATH)
    sys.exit(1)

# Load the Jinja templates
VPNC_TEMPLATE_DIR = pathlib.Path(__file__).parent.joinpath("templates")
VPNC_TEMPLATE_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(VPNC_TEMPLATE_DIR)
)

TRUSTED_NETNS = "TRUST"  # name of trusted network namespace
UNTRUSTED_NETNS = "UNTRUST"  # name of outside/untrusted network namespace
