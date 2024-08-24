"""Store global configuration."""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vpnc import models

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
    ),
]

DEFAULT_TENANT = "DEFAULT"
DEFAULT_NI = "ROOT"  # name of the DEFAULT network instance
CORE_NI = "CORE"  # name of the CORE trusted network instance
EXTERNAL_NI = "EXTERNAL"  # name of the EXTERNAL untrusted network instance

# Match only non-default tenants
DOWNLINK_TEN_RE = re.compile(r"^[2-9A-F]\d{4}$")
# Match only non-default tenant configuration files
DOWNLINK_TEN_FILE_RE = r"^[2-9A-F]\d{4}.yaml$"
# Match only non-default tenant network instances
DOWNLINK_NI_RE = re.compile(r"^[2-9A-F]\d{4}-\d{2}$")
# Match only non-default tenant network instance connections
DOWNLINK_CON_RE = re.compile(r"^[2-9A-F]\d{4}-\d{2}-\d$")

# Configuration file paths/directories for swanctl
VPN_CONFIG_DIR = Path("/etc/swanctl/conf.d/")
# Configuration file paths/directories for FRR
FRR_CONFIG_PATH = Path("/etc/frr/frr.conf")
# Installation directory
VPNC_INSTALL_DIR = Path("/opt/ncubed/vpnc/")
# Active configuration items
VPNC_A_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/active/")
VPNC_A_CONFIG_PATH_SERVICE = VPNC_A_CONFIG_DIR.joinpath(f"{DEFAULT_TENANT}.yaml")
# Candidate configuration items
VPNC_C_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/candidate/")
VPNC_C_CONFIG_PATH_SERVICE = VPNC_C_CONFIG_DIR.joinpath(f"{DEFAULT_TENANT}.yaml")

# Variables used for shared configuration
VPNC_CONFIG_SERVICE: models.ServiceEndpoint | models.ServiceHub
VPNC_CONFIG_TENANT: dict[str, models.Tenant] = {}
