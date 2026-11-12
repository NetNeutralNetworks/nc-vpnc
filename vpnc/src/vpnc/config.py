"""Store global configuration."""

from __future__ import annotations

import logging
import pwd
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vpnc.models import tenant

logger = logging.getLogger("vpnc")

DEFAULT_TENANT = "DEFAULT"
CORE_NI = "CORE"  # name of the CORE trusted network instance
DEFAULT_NI = "DEFAULT"  # name of the DEFAULT network instance
ENDPOINT_NI = "ENDPOINT"  # name of the ENDPOINT network instance
EXTERNAL_NI = "EXTERNAL"  # name of the EXTERNAL untrusted network instance

# The id of a non-default tenant, e.g. C0001.
TENANT_ID = r"[2-9A-F]\d{4}"
TENANT_ID_PATTERN = rf"^{TENANT_ID}$"
# Match all tenants
TENANT_RE = re.compile(rf"^({TENANT_ID}|{DEFAULT_TENANT})$")
# Match only non-default tenant configuration files
DOWNLINK_TEN_FILE_RE = rf".+\/{TENANT_ID}\.yaml$"
# Match only non-default tenant network instances
DOWNLINK_NI_RE = re.compile(rf"^{TENANT_ID}-\d{{2}}$")
# Match only non-default tenant network instance connections; the groups are the
# network instance, the tenant and the connection's number.
DOWNLINK_CON_RE = re.compile(rf"^(({TENANT_ID})-\d{{2}})-(\d)$")


def split_connection_name(name: str) -> tuple[str, str]:
    """Return the network instance and number of a connection's name."""
    network_instance_id, _, number = name.rpartition("-")
    return network_instance_id, number


# Group of the user charon runs as (swan), to reduce attack surface
_PWD = list(filter(lambda x: x.pw_name == "swan", pwd.getpwall()))
IPSEC_GROUP = _PWD[0].pw_gid if _PWD else 0
# Configuration file paths/directories for swanctl
IPSEC_CONFIG_DIR = Path("/etc/swanctl/conf.d/")
WIREGUARD_CONFIG_DIR = Path("/etc/wireguard/")
# Configuration file paths/directories for FRR
FRR_CONFIG_PATH = Path("/etc/frr/frr.conf")
# Logs of vpnc, vpncmangle and charon (which reopens its log as swan)
LOG_DIR = Path("/var/log/ncubed/vpnc/")
# Installation directory
VPNC_INSTALL_DIR = Path("/opt/ncubed/vpnc/")
# Active configuration items
VPNC_A_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/active/")
VPNC_A_CONFIG_PATH_SERVICE = VPNC_A_CONFIG_DIR.joinpath(f"{DEFAULT_TENANT}.yaml")
# Candidate configuration items
VPNC_C_CONFIG_DIR = Path("/opt/ncubed/config/vpnc/candidate/")
VPNC_C_CONFIG_PATH_SERVICE = VPNC_C_CONFIG_DIR.joinpath(f"{DEFAULT_TENANT}.yaml")
# Earlier active configurations
VPNC_HISTORY_DIR = Path("/opt/ncubed/config/vpnc/history/")
# Files of earlier configuration versions, from before they were converted
VPNC_BACKUP_DIR = Path("/opt/ncubed/config/vpnc/backup/")
# Directories holding secrets (pre-shared and private keys)
SECRET_DIRS = (
    VPNC_A_CONFIG_DIR,
    VPNC_C_CONFIG_DIR,
    VPNC_HISTORY_DIR,
    VPNC_BACKUP_DIR,
    IPSEC_CONFIG_DIR,
    WIREGUARD_CONFIG_DIR,
)

# Variables used for shared configuration
# VPNC_CONFIG_SERVICE: tenant.ServiceEndpoint | tenant.ServiceHub
VPNC_CONFIG_TENANT: dict[
    str,
    tenant.Tenant | tenant.ServiceHub | tenant.ServiceEndpoint,
] = {}
