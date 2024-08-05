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

    raise ValueError(
        f"Invalid downlink network instance/connection name '{name}'",
    )
