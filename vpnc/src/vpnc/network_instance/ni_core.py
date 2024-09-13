"""Manage the CORE network instance deployment and configuration."""

from __future__ import annotations

import logging
import pathlib
import subprocess
import time
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from vpnc import config, helpers, models
from vpnc.network_instance import general
from vpnc.services import frr, strongswan

if TYPE_CHECKING:
    from watchdog.observers.api import BaseObserver

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


def observe_core() -> BaseObserver:
    """Create the observer for CORE network instance configuration."""

    # Define what should happen when the config file with CORE data is modified.
    class CoreHandler(FileSystemEventHandler):
        """Handler for the event monitoring."""

        def on_modified(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            set_core_network_instance()

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()
    # Configure the event handler that watches directories. This doesn't start
    # the handler.
    observer.schedule(
        event_handler=CoreHandler(),
        path=config.VPNC_A_CONFIG_PATH_SERVICE,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


def set_core_network_instance(*, startup: bool = False) -> None:
    """Configure the CORE network instance (Linux namespace)."""
    # Remove network instance connections that aren't configured
    tenant, active_tenant = helpers.load_service_config(
        config.VPNC_A_CONFIG_PATH_SERVICE,
    )
    network_instance = tenant.network_instances[config.CORE_NI]
    if active_tenant:
        active_network_instance = active_tenant.network_instances[config.CORE_NI]
    else:
        active_network_instance = None

    if not startup and network_instance == active_network_instance:
        logger.info(
            "Network instance '%s' is already in the correct state",
            network_instance.id,
        )
        return

    # Set the network instance
    general.set_network_instance(
        network_instance,
        active_network_instance,
        cleanup=True,
    )

    # IP(6)TABLES RULES
    connection_names = general.get_network_instance_connections(network_instance)
    add_core_iptables(config.CORE_NI, connection_names)

    # VPN
    logger.info("Setting up VPN tunnels.")
    strongswan.generate_config(network_instance)

    if config.VPNC_CONFIG_SERVICE.mode == models.ServiceMode.HUB:
        # FRR
        frr.generate_config()


def add_core_iptables(
    network_instance_id: str,
    interfaces: list[str],
) -> None:
    """Add ip(6)table rules for the CORE network instance.

    The CORE network instance blocks all traffic originating from the DOWNLINK network
    instance (Linux namespace), but does accept traffic originating from its uplink.
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-core.conf.j2")
    iptables_configs: dict[str, Any] = {
        "mode": config.VPNC_CONFIG_SERVICE.mode,
        "network_instance_name": network_instance_id,
        "interfaces": sorted(interfaces),
    }
    iptables_render = iptables_template.render(**iptables_configs)
    logger.info(
        "Configuring network instance %s iptables rules.",
        network_instance_id,
    )
    logger.debug(iptables_render)
    proc = subprocess.run(  # noqa: S602
        iptables_render,
        stdout=subprocess.PIPE,
        shell=True,
        check=True,
    )
    logger.debug(proc.stdout)
