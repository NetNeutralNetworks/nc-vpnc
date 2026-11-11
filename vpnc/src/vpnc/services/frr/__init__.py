"""Monitors FRR routing changes."""

import atexit
import logging
import pathlib
import subprocess
import threading
import time
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader
from watchdog.events import FileSystemEvent, PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from vpnc import config, files
from vpnc.models import enums, tenant

if TYPE_CHECKING:
    from ipaddress import IPv4Network, IPv6Network

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
# Config files, not HTML: values must be written as they are.
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=False)  # noqa: S701


# Seconds before a reload is given up; the full check retries it.
RELOAD_TIMEOUT = 120
RELOAD_LOCK = threading.Lock()
# Set when a reload failed, for the full check to retry.
RELOAD_PENDING = threading.Event()


def reload_config() -> bool:
    """Load the FRR config file into FRR idempotently; return whether it worked."""
    with RELOAD_LOCK:
        logger.info("Reloading FRR configuration.")
        try:
            proc = subprocess.run(  # noqa: S603
                ["/usr/lib/frr/frr-reload.py", str(config.FRR_CONFIG_PATH), "--reload"],
                capture_output=True,
                text=True,
                check=False,
                timeout=RELOAD_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired):
            logger.exception("Reloading the FRR configuration failed.")
            RELOAD_PENDING.set()
            return False
        if proc.returncode:
            logger.error(
                "Reloading the FRR configuration failed (rc=%s): %s",
                proc.returncode,
                (proc.stderr or proc.stdout).strip()[-1000:],
            )
            RELOAD_PENDING.set()
            return False
        logger.debug(proc.stdout)
        RELOAD_PENDING.clear()
        # Wait to make sure the configuration is applied
        time.sleep(1)
        return True


def ensure_reloaded() -> None:
    """Retry a failed reload."""
    if RELOAD_PENDING.is_set():
        reload_config()


# The running configuration observer.
OBSERVER: BaseObserver | None = None


def observe() -> BaseObserver:
    """Create the observer for FRR configuration changes."""

    # Define what should happen when the config file with CORE data is modified.
    class FRRHandler(PatternMatchingEventHandler):
        """Handler for the event monitoring."""

        def on_created(self, event: FileSystemEvent) -> None:
            self.reload(event)

        def on_modified(self, event: FileSystemEvent) -> None:
            self.reload(event)

        def on_deleted(self, event: FileSystemEvent) -> None:
            self.reload(event)

        def on_moved(self, event: FileSystemEvent) -> None:
            self.reload(event)

        def reload(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            # Wait to make sure the file is written
            time.sleep(0.1)
            # A failing handler would end the observer thread.
            try:
                reload_config()
            except Exception:
                logger.exception("Reloading the FRR configuration failed.")
                RELOAD_PENDING.set()

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
    # Subnets expected on the CORE side, of all CORE connections.
    prefix_core: list[IPv4Network | IPv6Network] = list(
        dict.fromkeys(
            route.to
            for connection in net_instance.connections.values()
            for route in connection.routes.ipv6
        ),
    )

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

    frr_render = frr_template.render(**frr_cfg)
    if files.ensure_file(config.FRR_CONFIG_PATH, frr_render):
        logger.info("Generated FRR configuration.")


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
    global OBSERVER  # noqa: PLW0603
    OBSERVER = observe()
    OBSERVER.start()
