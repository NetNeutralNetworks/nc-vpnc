#!/usr/bin/env python3

import logging
import re
import sys
from pathlib import Path

import jinja2

logger = logging.getLogger("vpncservice")

# Match only downlink connections
DOWNLINK_RE = re.compile(r"[a-f]\d{4}-\d{3}")

# Configuration file paths/directories
VPN_CONFIG_DIR = Path("/etc/swanctl/conf.d")
VPNC_A_REMOTE_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/active/remote")
VPNC_A_SERVICE_CONFIG_PATH = Path("/opt/ncubed/config/vpnc/active/service/config.yaml")
VPNC_A_SERVICE_MODE_PATH = Path("/opt/ncubed/config/vpnc/active/service/mode.yaml")
VPNC_C_REMOTE_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/candidate/remote")
VPNC_C_SERVICE_CONFIG_PATH = Path(
    "/opt/ncubed/config/vpnc/candidate/service/config.yaml"
)

TRUSTED_NETNS = "TRUST"  # name of trusted network namespace
UNTRUSTED_NETNS = "UNTRUST"  # name of outside/untrusted network namespace
