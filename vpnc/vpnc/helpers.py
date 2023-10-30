#!/usr/bin/env python3
"""
Miscellaneous functions used throughout the service
"""


import logging
import pathlib
import subprocess
import sys

import vici
import yaml

from . import config, models

logger = logging.getLogger("vpnc")


def initiate_swanctl_connection(connection: str):
    """Initiate an IKE/IPsec connection"""
    logger.debug("Initiating connection '%s'.", connection)
    vcs = vici.Session()
    output = vcs.initiate({"ike": connection, "child": connection})
    logger.debug(output)


def load_swanctl_all_config():
    """Load all swanctl strongswan configurations. Cannot find a way to do this with vici"""
    logger.debug("Loading all swanctl connections.")
    output = subprocess.run(
        "swanctl --load-all --clear",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    ).stdout
    logger.debug(output)


def terminate_swanctl_connection(connection: str):
    """Terminate an IKE/IPsec connection"""
    logger.debug("Terminating connection '%s'.", connection)
    vcs = vici.Session()
    output = vcs.terminate({"ike": connection, "child": connection})
    logger.debug(output)


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

    config.VPNC_SERVICE_CONFIG = models.Service(**new_cfg_dict)

    logger.info("Loaded new configuration.")
