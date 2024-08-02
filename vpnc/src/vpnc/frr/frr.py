"""
Monitors FRR routing changes
"""

import logging
import pathlib
import subprocess
import time
from ipaddress import IPv4Network, IPv6Network

from jinja2 import Environment, FileSystemLoader
from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from .. import config

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR))


def observe() -> BaseObserver:
    """
    Create the observer for FRR configuration changes
    """

    # Define what should happen when the config file with CORE data is modified.
    class FRRHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config()

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config()

        def reload_config(self):
            """
            Loads FRR config from file in an idempotent way
            """
            # Wait to make sure the file is written
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

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()
    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=FRRHandler(patterns=["frr.conf"], ignore_directories=True),
        path=config.FRR_CONFIG_PATH.parent,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def generate_frr_cfg():
    """
    Generate dictionaries for the FRR configuration
    """
    neighbors = []
    net_instance = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    for neighbor in config.VPNC_SERVICE_CONFIG.bgp.neighbors:
        neighbor_cfg = {
            "neighbor_ip": neighbor.neighbor_address,
            "neighbor_asn": neighbor.neighbor_asn,
            "neighbor_priority": neighbor.priority,
        }
        neighbors.append(neighbor_cfg)

    # FRR/BGP CONFIG
    frr_template = TEMPLATES_ENV.get_template("frr.conf.j2")
    # Subnets expected on the CORE side
    prefix_core: list[IPv4Network | IPv6Network] = []
    for connection in net_instance.connections:
        prefix_core = [
            route.to
            for route in connection.routes.ipv6
            if isinstance(route.to, IPv6Network)
        ]

    frr_cfg = {
        "core_ni": config.CORE_NI,
        "external_ni": config.EXTERNAL_NI,
        "router_id": config.VPNC_SERVICE_CONFIG.bgp.globals.router_id,
        "as": config.VPNC_SERVICE_CONFIG.bgp.globals.asn,
        "neighbors": neighbors,
        "prefix_core": prefix_core,
        "prefix_downlink_nat64": config.VPNC_SERVICE_CONFIG.prefix_downlink_nat64,
        "prefix_downlink_natpt": config.VPNC_SERVICE_CONFIG.prefix_downlink_natpt,
    }

    frr_render = frr_template.render(**frr_cfg)
    logger.info(frr_render)

    with open(config.FRR_CONFIG_PATH, "w+", encoding="utf-8") as f:
        f.write(frr_render)
