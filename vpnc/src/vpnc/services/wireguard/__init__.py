"""Configures WireGuard interfaces over netlink and writes their files.

The files (<connection>.conf) are for operators; vpnc doesn't read them.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
from typing import TYPE_CHECKING, Any

from pyroute2 import WireGuard
from pyroute2.netlink.exceptions import NetlinkError

from vpnc import config, eventlog, files, helpers
from vpnc.network import namespace

if TYPE_CHECKING:
    import pathlib

    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

TEMPLATES_ENV = files.templates(__file__)


def config_path(connection_name: str) -> pathlib.Path:
    """Return the configuration file of a connection, e.g. C0001-00-0.conf."""
    return config.WIREGUARD_CONFIG_DIR.joinpath(f"{connection_name}.conf")


def remove_files() -> None:
    """Remove the files left from before vpnc started, like strongSwan's."""
    if not config.WIREGUARD_CONFIG_DIR.is_dir():
        return
    for file in config.WIREGUARD_CONFIG_DIR.iterdir():
        logger.debug("Unlinking WireGuard config file %s at startup", file)
        file.unlink(missing_ok=True)


def generate_config(network_instance: NetworkInstance, connection: Connection) -> None:
    """Write the WireGuard configuration file of a connection."""
    cfg = connection.config
    wg_render = TEMPLATES_ENV.get_template("wireguard.conf.j2").render(
        local_port=cfg.local_port,
        remote_addrs=helpers.endpoint(cfg.remote_addrs[0], cfg.remote_port),
        routes=",".join(str(route.to) for route in connection.routes.all),
        private_key=cfg.private_key.get_secret_value(),
        public_key=cfg.public_key,
        preshared_key=cfg.post_quantum.key(),
    )
    wg_path = config_path(connection.name(network_instance))
    if files.ensure_file(wg_path, wg_render, secret=True):
        logger.info(
            "Generated network instance %s connection %s WireGuard configuration.",
            network_instance.id,
            connection.id,
        )


KEEPALIVE = 25
# A peer without a preshared key has this one.
NO_PRESHARED_KEY = base64.b64encode(bytes(32)).decode()


def _peer(connection: Connection) -> dict[str, Any]:
    """Return the desired peer of a connection, as pyroute2 sets it."""
    cfg = connection.config
    return {
        "public_key": cfg.public_key,
        "preshared_key": cfg.post_quantum.key() or NO_PRESHARED_KEY,
        "endpoint_addr": str(cfg.remote_addrs[0]),
        "endpoint_port": cfg.remote_port,
        "persistent_keepalive": KEEPALIVE,
        "allowed_ips": [str(route.to) for route in connection.routes.all],
        "replace_allowed_ips": True,
    }


def _peers(device: Any) -> dict[str, Any]:  # noqa: ANN401
    return {
        peer.get("WGPEER_A_PUBLIC_KEY").decode(): peer
        for peer in device.get("WGDEVICE_A_PEERS") or []
    }


def _preshared_key(peer: Any) -> bytes:  # noqa: ANN401
    """Return a peer's preshared key; zeros without one."""
    key = peer.get("WGPEER_A_PRESHARED_KEY")
    return base64.b64decode(key) if key else bytes(32)


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
        or _preshared_key(current) != base64.b64decode(desired["preshared_key"])
    )


def _changes(
    device: Any,  # noqa: ANN401
    connection: Connection,
) -> tuple[dict[str, Any], list[str], bool]:
    """Return what to set, the peers to remove, and whether the session is reset."""
    cfg = connection.config
    private_key = cfg.private_key.get_secret_value()
    desired = _peer(connection)
    settings: dict[str, Any] = {}
    if (device.get("WGDEVICE_A_PRIVATE_KEY") or b"").decode() != private_key:
        settings["private_key"] = private_key
    if device.get("WGDEVICE_A_LISTEN_PORT") != cfg.local_port:
        settings["listen_port"] = cfg.local_port
    peers = _peers(device)
    current = peers.pop(cfg.public_key, None)
    if not connection.enabled:
        # Removed, like unknown peers.
        return settings, [*peers, *([cfg.public_key] if current else [])], False
    if current is None or _peer_differs(current, desired):
        settings["peer"] = desired
    # Removed first, so it's added without its session.
    reset = current is not None and _preshared_key(current) != base64.b64decode(
        desired["preshared_key"]
    )
    return settings, [*peers, *([cfg.public_key] if reset else [])], reset


def sync(
    network_instance: NetworkInstance, connection: Connection, ifname: str
) -> None:
    """Configure a WireGuard interface as desired, changing only what differs.

    Unchanged peers keep their session. A disabled connection has no peer. A
    changed PPK drops the session, so a wrong one shows now, not at the next
    handshake.
    """
    name = connection.name(network_instance)

    def run() -> bool:
        # The socket is opened in this thread's namespace.
        with WireGuard() as wg:
            settings, removed, reset = _changes(wg.info(ifname)[0], connection)
            for public_key in removed:
                logger.info("Removing peer %s from %s.", public_key, name)
                wg.set(ifname, peer={"public_key": public_key, "remove": True})
            if settings:
                logger.info("Configuring WireGuard interface %s of %s.", ifname, name)
                wg.set(ifname, **settings)
            return reset

    if namespace.call(network_instance.id, run):
        eventlog.record(
            "CONFIG_RESET",
            "reset: its ppk changed",
            connection=name,
            changed=["ppk"],
        )


def listen_port(network_instance_id: str, ifname: str) -> int | None:
    """Return the port an interface listens on; None if it doesn't exist."""

    def run() -> int | None:
        with WireGuard() as wg:
            return wg.info(ifname)[0].get("WGDEVICE_A_LISTEN_PORT")

    try:
        return namespace.call(network_instance_id, run)
    except (OSError, NetlinkError):
        return None


def peer_status(network_instance_id: str, ifname: str) -> dict[str, Any]:
    """Return an interface's listen port and public key, and its peer's state.

    The peer's endpoint, port, public key, allowed IPs and last handshake (Unix
    time, 0 if never).
    """

    def run() -> dict[str, Any]:
        with WireGuard() as wg:
            device = wg.info(ifname)[0]
        public_key = device.get("WGDEVICE_A_PUBLIC_KEY")
        output: dict[str, Any] = {
            "listen_port": device.get("WGDEVICE_A_LISTEN_PORT"),
            "public_key": public_key.decode() if public_key else None,
            "endpoint": None,
            "endpoint_port": None,
            "peer_public_key": None,
            "allowed_ips": [],
            "last_handshake": 0,
            "ppk": False,
        }
        peers = list(_peers(device).items())
        if not peers:
            return output
        peer_key, peer = peers[0]
        endpoint = peer.get("WGPEER_A_ENDPOINT") or {}
        handshake = peer.get("WGPEER_A_LAST_HANDSHAKE_TIME") or {}
        output.update(
            endpoint=endpoint.get("addr"),
            endpoint_port=endpoint.get("port"),
            peer_public_key=peer_key,
            allowed_ips=[
                str(ipaddress.ip_network(a["addr"]))
                for a in peer.get("WGPEER_A_ALLOWEDIPS") or []
            ],
            last_handshake=handshake.get("tv_sec", 0),
            ppk=any(_preshared_key(peer)),
        )
        return output

    return namespace.call(network_instance_id, run)
