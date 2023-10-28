#!/usr/bin/env python3

import ipaddress
import logging
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from . import models

logger = logging.getLogger("vpnc")

# Type changes to ignore in vpnctl diffs:
DEEPDIFF_IGNORE = [
    (
        None,
        str,
        int,
        ipaddress.IPv4Interface,
        ipaddress.IPv4Address,
        ipaddress.IPv4Network,
    )
]

# Match only downlink connections
DOWNLINK_RE = re.compile(r"[a-fA-F]\d{4}-\d{3}")

# Configuration file paths/directories
VPN_CONFIG_DIR = Path("/etc/swanctl/conf.d")
# Active configuration items
VPNC_A_REMOTE_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/active/remote")
VPNC_A_SERVICE_CONFIG_PATH = Path("/opt/ncubed/config/vpnc/active/service/config.yaml")
VPNC_A_SERVICE_MODE_PATH = Path("/opt/ncubed/config/vpnc/active/service/mode.yaml")
# Candidate configuration items
VPNC_C_REMOTE_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/candidate/remote")
VPNC_C_SERVICE_CONFIG_PATH = Path(
    "/opt/ncubed/config/vpnc/candidate/service/config.yaml"
)

_VPNC_TEMPLATES_DIR = Path("/opt/ncubed/config/vpnc/templates")
VPNC_TEMPLATES_ENV = Environment(loader=FileSystemLoader(_VPNC_TEMPLATES_DIR))

VPNC_INSTALL_DIR = Path("/opt/ncubed/vpnc/")

TRUSTED_NETNS = "TRUST"  # name of trusted network namespace
UNTRUSTED_NETNS = "UNTRUST"  # name of outside/untrusted network namespace

# Variables used for shared configuration
VPNC_SERVICE_MODE: models.ServiceMode
VPNC_SERVICE_CONFIG: models.Service | models.ServiceHub