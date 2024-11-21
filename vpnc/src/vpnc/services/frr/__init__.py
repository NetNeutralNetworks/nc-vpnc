"""Monitors FRR routing changes."""

import atexit
import logging
import pathlib
import subprocess
import time
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader
from watchdog.events import FileSystemEvent, PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from vpnc import config
from vpnc.models import enums, tenant

if TYPE_CHECKING:
    from ipaddress import IPv4Network, IPv6Network

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


def observe() -> BaseObserver:
    """Create the observer for FRR configuration changes."""

    # Define what should happen when the config file with CORE data is modified.
    class FRRHandler(PatternMatchingEventHandler):
        """Handler for the event monitoring."""

        def on_created(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config()

        def on_modified(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config()

        def on_deleted(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config()

        def reload_config(self) -> None:
            """Load FRR config from file in an idempotent way."""
            # Wait to make sure the file is written

            logger.info("Reloading FRR configuration.")
            proc = subprocess.run(  # noqa: S603
                [
                    "/usr/lib/frr/frr-reload.py",
                    "/etc/frr/frr.conf",
                    "--reload",
                ],
                capture_output=True,
                check=True,
            )
            logger.debug(proc.stdout)
            # Wait to make sure the configuration is applied
            time.sleep(1)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()
    # Configure the event handler that watches directories.
    # This doesn't start the handler.
    observer.schedule(
        event_handler=FRRHandler(patterns=["frr.conf"], ignore_directories=True),
        path=config.FRR_CONFIG_PATH.parent,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


def generate_config() -> None:
    """Generate FRR configuration."""
    default_tenant = tenant.get_default_tenant()

    if default_tenant.mode != enums.ServiceMode.HUB:
        return

    neighbors: list[dict[str, Any]] = []
    net_instance = default_tenant.network_instances[config.CORE_NI]
    for neighbor in default_tenant.bgp.neighbors:
        neighbor_cfg: dict[str, Any] = {
            "neighbor_ip": neighbor.neighbor_address,
            "neighbor_asn": neighbor.neighbor_asn,
            "neighbor_priority": neighbor.priority,
        }
        neighbors.append(neighbor_cfg)

    # FRR/BGP CONFIG
    frr_template = TEMPLATES_ENV.get_template("frr.conf.j2")
    # Subnets expected on the CORE side
    prefix_core: list[IPv4Network | IPv6Network] = []
    for connection in net_instance.connections.values():
        prefix_core = [route.to for route in connection.routes.ipv6]

    frr_cfg: dict[str, Any] = {
        "core_ni": config.CORE_NI,
        "external_ni": config.EXTERNAL_NI,
        "router_id": default_tenant.bgp.globals.router_id,
        "as": default_tenant.bgp.globals.asn,
        "bfd": default_tenant.bgp.globals.bfd,
        "neighbors": neighbors,
        "prefix_core": prefix_core,
        "prefix_downlink_nat64": default_tenant.prefix_downlink_nat64,
        "prefix_downlink_nptv6": default_tenant.prefix_downlink_nptv6,
    }

    logger.info("Generating FRR configuration.")
    frr_render = frr_template.render(**frr_cfg)
    logger.debug(frr_render)

    with config.FRR_CONFIG_PATH.open("w+", encoding="utf-8") as f:
        f.write(frr_render)


def stop() -> None:
    """Shut down IPsec when terminating the program."""
    logger.info("Stopping FRR process.")
    proc = subprocess.Popen(  # noqa: S603
        ["/usr/lib/frr/frrinit.sh", "stop"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
    )
    logger.info(proc.args)

    proc.wait()


def start() -> None:
    """Start the IPSec service in the EXTERNAL network instance."""
    # Remove old frr config files
    logger.debug("Unlinking FRR config file %s at startup", config.FRR_CONFIG_PATH)
    config.FRR_CONFIG_PATH.unlink(missing_ok=True)

    logger.info("Starting FRR process.")
    proc = subprocess.Popen(  # noqa: S603
        ["/usr/lib/frr/frrinit.sh", "start"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    logger.debug(proc.args)
    time.sleep(5)
    atexit.register(stop)

    proc.wait()

    # FRR doesn't monitor for file config changes directly, so a file observer is
    # used to auto reload the configuration.
    logger.info("Monitoring FRR configuration changes.")
    obs = observe()
    obs.start()
