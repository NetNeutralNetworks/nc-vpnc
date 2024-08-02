#!/usr/bin/env python3
"""
Miscellaneous functions used throughout the service
"""


import logging
import pathlib
import sys
from typing import Any

import pydantic_core
import yaml

from . import config, models

logger = logging.getLogger("vpnc")


def kill_handler(*_):
    """Used to gracefully shut down"""
    sys.exit(0)


def load_config(config_path: pathlib.Path):
    """
    Load the global configuration.
    """

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
    try:
        config.VPNC_SERVICE_CONFIG = models.Service(**new_cfg_dict)
    except pydantic_core.ValidationError:
        logger.critical(
            "Configuration '%s' doesn't adhere to the schema",
            config_path,
            exc_info=True,
        )
        sys.exit(1)

    logger.info("Loaded new configuration.")


def parse_downlink_network_instance_connection_name(
    connection_name: str,
) -> dict[str, Any]:
    """
    Parses a connection name into it's components
    """
    if not config.DOWNLINK_CON_RE.match(connection_name):
        raise ValueError(
            f"Invalid downlink connection name '{connection_name}'",
        )

    return {
        "tenant": connection_name[:5],
        "tenant_ext": int(connection_name[0], 16),
        "tenant_ext_str": connection_name[0],
        "tenant_id": int(connection_name[1:5], 16),
        "tenant_id_str": connection_name[1:5],
        "network_instance": connection_name[:8],
        "network_instance_id": int(connection_name[6:8], 16),
        "connection": connection_name,
        "connection_id": int(connection_name[-1], 16),
    }


def parse_downlink_network_instance_name(
    network_instance_name: str,
) -> dict[str, Any]:
    """
    Parses a connection name into it's components
    """
    if not config.DOWNLINK_NI_RE.match(network_instance_name):
        raise ValueError(
            f"Invalid downlink network instance name '{network_instance_name}'",
        )

    return {
        "tenant": network_instance_name[:5],
        "tenant_ext": int(network_instance_name[0], 16),
        "tenant_ext_str": network_instance_name[0],
        "tenant_id": int(network_instance_name[1:5], 16),
        "tenant_id_str": network_instance_name[1:5],
        "network_instance": network_instance_name[:8],
        "network_instance_id": int(network_instance_name[6:8], 16),
    }
