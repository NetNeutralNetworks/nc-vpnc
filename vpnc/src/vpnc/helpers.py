#!/usr/bin/env python3
"""
Miscellaneous functions used throughout the service
"""


import logging
import pathlib
import subprocess
import sys
from typing import Any

import pydantic_core
import yaml

from . import config, models

logger = logging.getLogger("vpnc")


def kill_handler(*_) -> None:
    """Used to gracefully shut down"""
    sys.exit(0)


def check_system_requirements():
    """
    Checks if required modules are installed
    """

    try:
        subprocess.run(
            ["lsmod"],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError:
        logger.critical("Couldn't get the list of enabled modules. Exiting.")
        sys.exit(1)

    module_list: list[str] = ["xfrm_interface", "xt_MASQUERADE", "xt_nat", "veth"]
    for module in module_list:
        try:
            subprocess.run(
                ["modinfo", module],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError:
            logger.critical("The '%s' kernel module isn't loaded. Exiting.", module)
            sys.exit(1)

    if config.VPNC_SERVICE_CONFIG.mode.value != "hub":
        return

    hub_module_list: list[str] = []
    for module in hub_module_list:
        try:
            subprocess.run(
                ["modinfo", module],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError:
            logger.critical("The '%s' kernel module isn't loaded. Exiting.", module)
            sys.exit(1)


def load_service_config(config_path: pathlib.Path):
    """
    Load the global configuration.
    """

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            try:
                new_cfg_dict = yaml.safe_load(f)
            except (yaml.YAMLError, TypeError):
                logger.critical(
                    "Configuration is not valid '%s'.",
                    config_path,
                    exc_info=True,
                )
                sys.exit(1)
    except FileNotFoundError:
        logger.critical(
            "Configuration file could not be found at '%s'.",
            config_path,
            exc_info=True,
        )
        sys.exit(1)

    try:
        config.VPNC_SERVICE_CONFIG = models.Service(**{"config": new_cfg_dict}).config
    except pydantic_core.ValidationError:
        logger.critical(
            "Configuration '%s' doesn't adhere to the schema",
            config_path,
            exc_info=True,
        )
        sys.exit(1)

    logger.info("Loaded new configuration.")


def parse_downlink_network_instance_name(
    name: str,
) -> dict[str, Any]:
    """
    Parses a connection name into it's components
    """
    if config.DOWNLINK_CON_RE.match(name):
        return {
            "tenant": name[:5],
            "tenant_ext": int(name[0], 16),
            "tenant_ext_str": name[0],
            "tenant_id": int(name[1:5], 16),
            "tenant_id_str": name[1:5],
            "network_instance": name[:8],
            "network_instance_id": int(name[6:8], 16),
            "connection": name,
            "connection_id": int(name[-1], 16),
        }

    elif config.DOWNLINK_NI_RE.match(name):
        return {
            "tenant": name[:5],
            "tenant_ext": int(name[0], 16),
            "tenant_ext_str": name[0],
            "tenant_id": int(name[1:5], 16),
            "tenant_id_str": name[1:5],
            "network_instance": name[:8],
            "network_instance_id": int(name[6:8], 16),
            "connection": None,
            "connection_id": None,
        }
    elif config.DOWNLINK_TEN_RE.match(name):
        return {
            "tenant": name[:5],
            "tenant_ext": int(name[0], 16),
            "tenant_ext_str": name[0],
            "tenant_id": int(name[1:5], 16),
            "tenant_id_str": name[1:5],
            "network_instance": None,
            "network_instance_id": None,
            "connection": None,
            "connection_id": None,
        }

    raise ValueError(
        f"Invalid downlink network instance/connection name '{name}'",
    )


def load_tenant_config(path: pathlib.Path):
    """
    Load tenant configuration
    """

    if not config.DOWNLINK_TEN_RE.match(path.stem):
        logger.error("Invalid filename found in %s. Skipping.", path, exc_info=True)
        return None

    # Open the configuration file and check if it's valid YAML.
    try:
        with open(path, "r", encoding="utf-8") as f:
            try:
                config_yaml = yaml.safe_load(f)
            except yaml.YAMLError:
                logger.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
                return None
    except FileNotFoundError:
        logger.error(
            "Configuration file could not be found at '%s'. Skipping",
            path,
            exc_info=True,
        )
        return None

    # Parse the YAML file to a DOWNLINK object and validate the input.
    try:
        tenant = models.Tenant(**config_yaml)
    except (TypeError, ValueError):
        logger.error(
            "Invalid configuration found in '%s'. Skipping.", path, exc_info=True
        )
        return None

    if tenant.id != path.stem:
        logger.error(
            "VPN identifier '%s' and configuration file name '%s' do not match. Skipping.",
            tenant.id,
            path.stem,
        )
        return None

    config.VPNC_TENANT_CONFIG[tenant.name] = tenant

    return tenant
