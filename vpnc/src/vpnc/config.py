#!/usr/bin/env python3

"""
Stores global configuration
"""

import ipaddress
import logging
import re
from pathlib import Path

from . import models

logger = logging.getLogger("vpnc")

# Type changes to ignore in vpnctl diffs:
DEEPDIFF_IGNORE = [
    (
        None,
        str,
        int,
        list,
        dict,
        ipaddress.IPv4Interface,
        ipaddress.IPv4Address,
        ipaddress.IPv4Network,
    )
]

# Match only DOWNLINK connections
DOWNLINK_TEN_RE = re.compile(r"^[2-9a-fA-F]\d{4}$")
DOWNLINK_NI_RE = re.compile(r"^[2-9a-fA-F]\d{4}-\d{2}$")
DOWNLINK_CON_RE = re.compile(r"^[2-9a-fA-F]\d{4}-\d{2}-\d$")

# Configuration file paths/directories for swanctl
VPN_CONFIG_DIR = Path("/etc/swanctl/conf.d/")
# Configuration file paths/directories for FRR
FRR_CONFIG_PATH = Path("/etc/frr/frr.conf")
# Installation directory
VPNC_INSTALL_DIR = Path("/opt/ncubed/vpnc/")
# Active configuration items
VPNC_A_TENANT_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/active/tenant/")
VPNC_A_SERVICE_CONFIG_PATH = Path("/opt/ncubed/config/vpnc/active/service/config.yaml")
# Candidate configuration items
VPNC_C_TENANT_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/candidate/tenant/")
VPNC_C_SERVICE_CONFIG_PATH = Path(
    "/opt/ncubed/config/vpnc/candidate/service/config.yaml"
)

CORE_NI = "TRUST"  # name of the CORE trusted network instance
EXTERNAL_NI = "UNTRUST"  # name of the EXTERNAL untrusted network instance
DEFAULT_NI = "ROOT"  # name of the DEFAULT network instance

# Variables used for shared configuration
VPNC_SERVICE_CONFIG: models.ServiceEndpoint | models.ServiceHub
