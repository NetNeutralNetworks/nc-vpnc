"""Manages VPN connections and observers used to monitor file changes."""

from __future__ import annotations

import logging
import pathlib
import subprocess
import time
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Any

import pyroute2
from jinja2 import Environment, FileSystemLoader
from watchdog.events import FileSystemEvent, PatternMatchingEventHandler
from watchdog.observers import Observer

from vpnc import config
from vpnc.models import enums

if TYPE_CHECKING:
    from watchdog.observers.api import BaseObserver

    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


def observe() -> BaseObserver:
    """Create the observer for wireguard configuration."""

    # Define what should happen when downlink files are created, modified or deleted.
    class WireGuardHandler(PatternMatchingEventHandler):
        """Handler for the event monitoring."""

        def on_created(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config(event.src_path)

        def on_modified(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            self.reload_config(event.src_path)

        # ###########################################################################################
        # def on_deleted(self, event: FileSystemEvent) -> None:
        #     logger.info("File %s: %s", event.event_type, event.src_path)
        #     time.sleep(0.1)
        #     self.reload_config(event.src_path)

        def reload_config(self, file: str) -> None:
            """Load wireguard connection configurations."""
            intf_name = pathlib.Path(file).stem
            logger.info("Loading wireguard connection %s.", intf_name)
            network_instance_name = intf_name[3:-2]
            proc = pyroute2.NSPopen(
                network_instance_name,
                ["/usr/bin/wg", "setconf", intf_name, file],
                stdout=subprocess.PIPE,
            )
            logger.info(proc.stdout)
            proc.wait()
            proc.release()

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories.
    # This doesn't start the handler.
    observer.schedule(
        event_handler=WireGuardHandler(patterns=["wg*.conf"], ignore_directories=True),
        path=config.WIREGUARD_CONFIG_DIR,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


def generate_config(
    network_instance: NetworkInstance,
) -> None:
    """Generate wireguard configurations."""
    wg_template = TEMPLATES_ENV.get_template("wireguard.conf.j2")

    for connection in network_instance.connections.values():
        if connection.config.type != enums.ConnectionType.WIREGUARD:
            continue
        remote_addrs_list: list[str] = []
        for addr in connection.config.remote_addrs:
            if isinstance(addr, IPv4Address):
                remote_addrs_list.append(f"{addr}:{connection.config.remote_port}")
                continue
            remote_addrs_list.append(f"[{addr}]:{connection.config.remote_port}")

        # tunnel_addrs_list: list[str] = []
        # if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(network_instance)
        # for addr in if_ipv4 + if_ipv6:
        #     tunnel_addrs_list.append(f"{addr.ip +1}/{addr.network.prefixlen}")
        routes_list: list[str] = []
        for routes in connection.routes.ipv4 + connection.routes.ipv6:
            routes_list.append(str(routes.to))
        wg_cfg: dict[str, Any] = {
            "local_port": connection.config.local_port,
            # "remote_addrs": ",".join(remote_addrs_list),
            "remote_addrs": f"{connection.config.remote_addrs[0]}:{connection.config.remote_port}",
            "routes": ",".join(routes_list),
            "private_key": connection.config.private_key,
            "public_key": connection.config.public_key,
        }

        wg_render = wg_template.render(**wg_cfg)

        logger.info(
            "Generating network instance %s connection %s WireGuard configuration.",
            network_instance.id,
            connection.id,
        )
        wg_path = config.WIREGUARD_CONFIG_DIR.joinpath(
            f"wg-{network_instance.id}-{connection.id}.conf",
        )
        with wg_path.open("w", encoding="utf-8") as f:
            f.write(wg_render)
