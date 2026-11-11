"""Configures WireGuard interfaces over netlink and writes their files.

The files (wg-*.conf) are for operators; vpnc doesn't read them.
"""

from __future__ import annotations

import ipaddress
import logging
import pathlib
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader
from pyroute2 import WireGuard

from vpnc import config, files
from vpnc.models import enums
from vpnc.network import namespace

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
# Config files, not HTML: values must be written as they are.
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=False)  # noqa: S701


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
            "private_key": connection.config.private_key.get_secret_value(),
            "public_key": connection.config.public_key,
        }

        wg_render = wg_template.render(**wg_cfg)

        wg_path = config.WIREGUARD_CONFIG_DIR.joinpath(
            f"wg-{network_instance.id}-{connection.id}.conf",
        )
        if files.ensure_file(wg_path, wg_render):
            logger.info(
                "Generated network instance %s connection %s WireGuard configuration.",
                network_instance.id,
                connection.id,
            )


KEEPALIVE = 25


def _peer(connection: Connection) -> dict[str, Any]:
    """Return the desired peer of a connection, as pyroute2 sets it."""
    cfg = connection.config
    return {
        "public_key": cfg.public_key,
        "endpoint_addr": str(cfg.remote_addrs[0]),
        "endpoint_port": cfg.remote_port,
        "persistent_keepalive": KEEPALIVE,
        "allowed_ips": [
            str(route.to) for route in connection.routes.ipv4 + connection.routes.ipv6
        ],
        "replace_allowed_ips": True,
    }


def _peers(device: Any) -> dict[str, Any]:  # noqa: ANN401
    return {
        peer.get("WGPEER_A_PUBLIC_KEY").decode(): peer
        for peer in device.get("WGDEVICE_A_PEERS") or []
    }


def _peer_differs(current: Any, desired: dict[str, Any]) -> bool:  # noqa: ANN401
    endpoint = current.get("WGPEER_A_ENDPOINT") or {}
    allowed = {
        ipaddress.ip_network(a["addr"])
        for a in current.get("WGPEER_A_ALLOWEDIPS") or []
    }
    return (
        endpoint.get("port") != desired["endpoint_port"]
        or endpoint.get("addr") is None
        or ipaddress.ip_address(endpoint["addr"])
        != ipaddress.ip_address(desired["endpoint_addr"])
        or current.get("WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL") != KEEPALIVE
        or allowed != {ipaddress.ip_network(a) for a in desired["allowed_ips"]}
    )


def sync(
    network_instance: NetworkInstance, connection: Connection, ifname: str
) -> None:
    """Configure a WireGuard interface as desired, changing only what differs.

    Unchanged peers keep their session.
    """
    cfg = connection.config
    private_key = cfg.private_key.get_secret_value()
    desired = _peer(connection)

    def run() -> None:
        # The socket is opened in this thread's namespace.
        with WireGuard() as wg:
            device = wg.info(ifname)[0]
            settings: dict[str, Any] = {}
            if (device.get("WGDEVICE_A_PRIVATE_KEY") or b"").decode() != private_key:
                settings["private_key"] = private_key
            if device.get("WGDEVICE_A_LISTEN_PORT") != cfg.local_port:
                settings["listen_port"] = cfg.local_port
            peers = _peers(device)
            current = peers.pop(cfg.public_key, None)
            if current is None or _peer_differs(current, desired):
                settings["peer"] = desired
            if settings:
                logger.info("Configuring WireGuard interface %s.", ifname)
                wg.set(ifname, **settings)
            for public_key in peers:
                logger.info("Removing peer %s from %s.", public_key, ifname)
                wg.set(ifname, peer={"public_key": public_key, "remove": True})

    namespace.call(network_instance.id, run)


def peer_status(network_instance_id: str, ifname: str) -> dict[str, Any]:
    """Return the endpoint and last handshake (Unix time) of an interface's peer."""

    def run() -> dict[str, Any]:
        with WireGuard() as wg:
            peers = list(_peers(wg.info(ifname)[0]).values())
        if not peers:
            return {"endpoint": None, "last_handshake": 0}
        endpoint = peers[0].get("WGPEER_A_ENDPOINT") or {}
        handshake = peers[0].get("WGPEER_A_LAST_HANDSHAKE_TIME") or {}
        return {
            "endpoint": endpoint.get("addr"),
            "last_handshake": handshake.get("tv_sec", 0),
        }

    return namespace.call(network_instance_id, run)
