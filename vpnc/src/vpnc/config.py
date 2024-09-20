"""Store global configuration."""

from __future__ import annotations

import ipaddress
import logging
import pwd
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vpnc.models import tenant

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
CORE_NI = "CORE"  # name of the CORE trusted network instance
DEFAULT_NI = "DEFAULT"  # name of the DEFAULT network instance
ENDPOINT_NI = "ENDPOINT"  # name of the ENDPOINT network instance
EXTERNAL_NI = "EXTERNAL"  # name of the EXTERNAL untrusted network instance

# Match only non-default tenants
DOWNLINK_TEN_RE = re.compile(r"^[2-9A-F]\d{4}$")
# Match only non-default tenant configuration files
DOWNLINK_TEN_FILE_RE = r".+\/[2-9A-F]\d{4}\.yaml$"
# Match only non-default tenant network instances
DOWNLINK_NI_RE = re.compile(r"^[2-9A-F]\d{4}-\d{2}$")
# Match only non-default tenant network instance connections
DOWNLINK_CON_RE = re.compile(r"^[2-9A-F]\d{4}-\d{2}-\d$")

# UID and GID used by strongswan to reduce attack surface
_PWD = list(filter(lambda x: x.pw_name == "swan", pwd.getpwall()))
IPSEC_USER = _PWD[0].pw_uid if _PWD else 0
IPSEC_GROUP = _PWD[0].pw_gid if _PWD else 0
# Configuration file paths/directories for swanctl
IPSEC_CONFIG_DIR = Path("/etc/swanctl/conf.d/")
WIREGUARD_CONFIG_DIR = Path("/etc/wireguard/")
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
VPNC_CONFIG_SERVICE: tenant.ServiceEndpoint | tenant.ServiceHub
VPNC_CONFIG_TENANT: dict[str, tenant.Tenant] = {}
