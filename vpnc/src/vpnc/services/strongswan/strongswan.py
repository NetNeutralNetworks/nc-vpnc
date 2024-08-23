"""Manages VPN connections and observers used to monitor file changes."""

import atexit
import logging
import pathlib
import subprocess
import time
from typing import Any

from jinja2 import Environment, FileSystemLoader
from watchdog.events import FileSystemEvent, PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from vpnc import config, models

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


def observe() -> BaseObserver:
    """Create the observer for swanctl configuration."""

    # Define what should happen when downlink files are created, modified or deleted.
    class SwanctlHandler(PatternMatchingEventHandler):
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
            """Load all swanctl strongswan configurations."""
            logger.debug("Loading all swanctl connections.")
            proc = subprocess.run(  # noqa: S603
                ["/usr/sbin/swanctl", "--load-all", "--clear"],
                stdout=subprocess.PIPE,
                check=True,
            )
            logger.debug(proc.stdout)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories.
    # This doesn't start the handler.
    observer.schedule(
        event_handler=SwanctlHandler(patterns=["*.conf"], ignore_directories=True),
        path=config.VPN_CONFIG_DIR,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


def generate_config(
    network_instance: models.NetworkInstance,
) -> None:
    """Generate swanctl configurations."""
    swanctl_template = TEMPLATES_ENV.get_template("swanctl.conf.j2")
    swanctl_cfgs: list[dict[str, Any]] = []
    vpn_id = int("0x10000000", 16)
    if network_instance.type == models.NetworkInstanceType.DOWNLINK:
        vpn_id = int(f"0x{network_instance.id.replace('-', '')}0", 16)

    for connection in network_instance.connections.values():
        if connection.config.type != models.ConnectionType.IPSEC:
            continue
        swanctl_cfg: dict[str, Any] = {
            "connection": f"{network_instance.id}-{connection.id}",
            "local_id": config.VPNC_SERVICE_CONFIG.local_id,
            "remote_peer_ip": ",".join(
                [str(x) for x in connection.config.remote_addrs],
            ),
            "remote_id": connection.config.remote_addrs[0],
            "xfrm_id": hex(vpn_id + connection.id),
            "ike_version": connection.config.ike_version,
            "ike_proposal": connection.config.ike_proposal,
            "ike_lifetime": connection.config.ike_lifetime,
            "ipsec_proposal": connection.config.ipsec_proposal,
            "ipsec_lifetime": connection.config.ipsec_lifetime,
            "initiation": connection.config.initiation.value,
            "psk": connection.config.psk,
        }

        # Check for the connection specific remote id
        if connection.config.remote_id is not None:
            swanctl_cfg["remote_id"] = connection.config.remote_id
        # Check for the connection specific local id
        if connection.config.local_id is not None:
            swanctl_cfg["local_id"] = connection.config.local_id

        if connection.config.traffic_selectors:
            ts_loc = ",".join(str(x) for x in connection.config.traffic_selectors.local)
            ts_rem = ",".join(
                str(x) for x in connection.config.traffic_selectors.remote
            )
            swanctl_cfg["ts"] = {"local": ts_loc, "remote": ts_rem}

        swanctl_cfgs.append(swanctl_cfg)

    swanctl_path = config.VPN_CONFIG_DIR.joinpath(f"{network_instance.id}.conf")
    # Remove the configuration file if it exists and there is no IPSec connection
    # configured.
    if not swanctl_cfgs:
        swanctl_path.unlink(missing_ok=True)
        return

    swanctl_render = swanctl_template.render(connections=swanctl_cfgs)

    with swanctl_path.open("w", encoding="utf-8") as f:
        f.write(swanctl_render)


def stop() -> None:
    """Shut down IPsec when terminating the program."""
    proc = subprocess.run(  # noqa: S603
        # Stop Strongswan in the EXTERNAL network instance.
        ["/usr/sbin/ip", "netns", "exec", config.EXTERNAL_NI, "ipsec", "stop"],
        capture_output=True,
        check=False,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout, proc.stderr)


def start() -> None:
    """Start the IPSec service in the EXTERNAL network instance."""
    # Remove old strongswan/swanctl config files
    for file in config.VPN_CONFIG_DIR.iterdir():
        logger.debug("Unlinking swanctl config file %s at startup", file)
        file.unlink(missing_ok=True)

    proc = subprocess.run(  # noqa: S603
        # Run Strongswan in the EXTERNAL network instance.
        ["/usr/sbin/ip", "netns", "exec", config.EXTERNAL_NI, "ipsec", "start"],
        stdout=subprocess.PIPE,
        check=True,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout)

    atexit.register(stop)

    # Strongswan doesn't monitor it's configuration files automatically,
    # so a file observer is used to reload the configuration.
    logger.info("Monitoring swantcl config changes.")
    obs = observe()
    obs.start()