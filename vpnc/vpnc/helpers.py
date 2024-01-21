#!/usr/bin/env python3
"""
Miscellaneous functions used throughout the service
"""


import logging
import pathlib
import subprocess
import sys
import time

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

    config.VPNC_SERVICE_CONFIG = models.Service(**new_cfg_dict)

    logger.info("Loaded new configuration.")


def generate_frr_cfg(configs: dict[int, models.ConnectionUplink]):
    """
    # Generate dictionaries for the FRR configuration
    """
    routing_cfgs = []
    for connection_id, connection_config in configs.items():
        routing_cfg = {
            "neighbor_interface_name": f"xfrm-uplink{connection_id:03}",
            "neighbor_ip": connection_config.interface_ip.ip + 1,
            "neighbor_asn": connection_config.asn,
            "neighbor_priority": connection_config.priority,
            "prepend": (
                f"{config.VPNC_SERVICE_CONFIG.bgp.asn} " * connection_config.priority
            ).strip(),
        }
        routing_cfgs.append(routing_cfg)

    # FRR/BGP CONFIG
    frr_template = config.VPNC_TEMPLATES_ENV.get_template("frr.conf.j2")
    frr_cfg = {
        "trusted_netns": config.TRUSTED_NETNS,
        "untrusted_netns": config.UNTRUSTED_NETNS,
        "router_id": config.VPNC_SERVICE_CONFIG.bgp.router_id,
        "asn": config.VPNC_SERVICE_CONFIG.bgp.asn,
        "uplinks": routing_cfgs,
        "prefix_uplink": config.VPNC_SERVICE_CONFIG.prefix_uplink,
        "prefix_downlink_v6": config.VPNC_SERVICE_CONFIG.prefix_downlink_v6,
    }

    frr_render = frr_template.render(**frr_cfg)
    logger.info(frr_render)
    frr_path = pathlib.Path("/etc/frr/frr.conf")

    with open(frr_path, "w+", encoding="utf-8") as f:
        f.write(frr_render)


def load_frr_all_config():
    """
    Loads FRR config from file in an idempotent way
    """
    # Wait to make sure the file is written
    time.sleep(1)
    output = subprocess.run(
        "/usr/lib/frr/frr-reload.py /etc/frr/frr.conf --reload --stdout",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout
    logger.debug(output)
    # Wait to make sure the configuration is applied
    time.sleep(1)
