"""
Manages VPN connections and observers used to monitor file changes
"""

import atexit
import logging
import pathlib
import subprocess
import time
from typing import Any

from jinja2 import Environment, FileSystemLoader
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from .. import config, models

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR))


def observe() -> BaseObserver:
    """
    Create the observer for swanctl configuration
    """

    # Define what should happen when downlink files are created, modified or deleted.
    class SwanctlHandler(PatternMatchingEventHandler):
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

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config()

        def reload_config(self):
            """Load all swanctl strongswan configurations. Cannot find a way to do this with vici"""
            logger.debug("Loading all swanctl connections.")
            output = subprocess.run(
                "swanctl --load-all --clear",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                check=True,
            ).stdout
            logger.debug(output)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
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
):
    """
    Generates swanctl configurations
    """

    swanctl_template = TEMPLATES_ENV.get_template("swanctl.conf.j2")
    swanctl_cfgs = []
    vpn_id = int("0x10000000", 16)
    if network_instance.type == models.NetworkInstanceType.DOWNLINK:
        vpn_id = int(f"0x{network_instance.name.replace('-', '')}0", 16)

    for idx, connection in enumerate(network_instance.connections):
        if connection.config.type != models.ConnectionType.IPSEC:
            continue
        swanctl_cfg: dict[str, Any] = {
            "connection": f"{network_instance.name}-{idx}",
            "local_id": config.VPNC_SERVICE_CONFIG.local_id,
            "remote_peer_ip": connection.config.remote_peer_ip,
            "remote_id": connection.config.remote_peer_ip,
            "xfrm_id": hex(vpn_id + idx),
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
            ts_loc = ",".join(
                (str(x) for x in connection.config.traffic_selectors.local)
            )
            ts_rem = ",".join(
                (str(x) for x in connection.config.traffic_selectors.remote)
            )
            swanctl_cfg["ts"] = {"local": ts_loc, "remote": ts_rem}

        swanctl_cfgs.append(swanctl_cfg)

    if not swanctl_cfgs:
        return

    swanctl_render = swanctl_template.render(connections=swanctl_cfgs)
    swanctl_path = config.VPN_CONFIG_DIR.joinpath(f"{network_instance.name}.conf")

    with open(swanctl_path, "w", encoding="utf-8") as f:
        f.write(swanctl_render)


def stop():
    """
    Shut down IPsec when terminating the program
    """
    proc = subprocess.run(
        f"""
        # Stop Strongswan in the EXTERNAL network instance.
        ip netns exec {config.EXTERNAL_NI} ipsec stop
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout)


def start():
    """
    Start the IPSec service in the EXTERNAL network instance.
    """

    # Remove old strongswan/swanctl config files
    for file in config.VPN_CONFIG_DIR.iterdir():
        logger.debug("Unlinking swanctl config file %s at startup", file)
        file.unlink(missing_ok=True)

    proc = subprocess.run(
        f"""
        # Run Strongswan in the EXTERNAL network instance.
        ip netns exec {config.EXTERNAL_NI} ipsec start
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout)

    atexit.register(stop)
