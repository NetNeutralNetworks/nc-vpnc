"""
Code to manage the CORE network instance specifically.
"""

import logging
import pathlib
import subprocess
import time

from jinja2 import Environment, FileSystemLoader
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from .. import config, frr, helpers, models, strongswan
from . import general

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR))


def observe_core() -> BaseObserver:
    """
    Create the observer for CORE network instance configuration
    """

    # Define what should happen when the config file with CORE data is modified.
    class CoreHandler(FileSystemEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_modified(self, event: FileSystemEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            helpers.load_service_config(config.VPNC_A_SERVICE_CONFIG_PATH)
            time.sleep(0.1)
            update_core_network_instance()

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()
    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=CoreHandler(),
        path=config.VPNC_A_SERVICE_CONFIG_PATH,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


def update_core_network_instance():
    """
    Configures the CORE network instance (Linux namespace).
    """

    # Remove network instance connections that aren't configured
    network_instance = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    general.delete_network_instance_connection(network_instance)

    # Configure connection
    logger.info("Setting up core connections for %s network instance.", config.CORE_NI)

    network_instance = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    interfaces = general.add_network_instance_connection(network_instance)

    # IP(6)TABLES RULES
    add_core_iptables(config.VPNC_SERVICE_CONFIG.mode, config.CORE_NI, interfaces)

    # VPN
    logger.info("Setting up VPN tunnels.")
    strongswan.generate_config(network_instance=network_instance)

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        # FRR
        frr.generate_config()


def add_core_iptables(
    mode: models.ServiceMode,
    network_instance_name: str,
    interfaces,
):
    """
    The CORE network instance blocks all traffic originating from the DOWNLINK network instance
    (Linux namespace), but does accept traffic originating from its uplink.
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-core.conf.j2")
    iptables_configs = {
        "mode": mode,
        "network_instance_name": network_instance_name,
        "interfaces": interfaces,
    }
    iptables_render = iptables_template.render(**iptables_configs)
    logger.info(iptables_render)
    subprocess.run(
        iptables_render,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )
