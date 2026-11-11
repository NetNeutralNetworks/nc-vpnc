"""Manages SSH tunnels."""

from __future__ import annotations

import atexit
import logging
import pathlib
import subprocess
import threading
import time
from typing import TYPE_CHECKING

import vpnc.models.connections
import vpnc.models.ssh
from vpnc.models import enums

if TYPE_CHECKING:
    import vpnc.models.network_instance


logger = logging.getLogger("vpnc")

SSH_SOCKET_DIR = pathlib.Path("/run/vpnc/ssh/")
SSH_SOCKET_DIR.mkdir(mode=770, parents=True, exist_ok=True)

# Seconds before reconnecting, doubled after each failed attempt.
RESTART_DELAY_MIN = 1
RESTART_DELAY_MAX = 30
# A tunnel that stayed up this long (seconds) resets the delay.
STABLE_AFTER = 60


class SshTunnel(threading.Thread):
    """Run ssh and reconnect whenever it exits, until stopped.

    Replaces autossh, which gives up when ssh exits with 0 (e.g. when the server
    closes the session).
    """

    def __init__(self, name: str, command: list[str]) -> None:
        """Create the tunnel thread; call start() to run it."""
        super().__init__(name=f"ssh-{name}", daemon=True)
        self.connection_name = name
        self.command = command
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[str] | None = None

    def run(self) -> None:
        """Keep ssh running."""
        delay = RESTART_DELAY_MIN
        while True:
            started = time.monotonic()
            with self._lock:
                if self._stop_event.is_set():
                    return
                proc = self._proc = subprocess.Popen(  # noqa: S603
                    self.command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            _, stderr = proc.communicate()
            if self._stop_event.is_set():
                return
            if time.monotonic() - started > STABLE_AFTER:
                delay = RESTART_DELAY_MIN
            logger.warning(
                "SSH tunnel %s exited (rc=%s), reconnecting in %ss: %s",
                self.connection_name,
                proc.returncode,
                delay,
                stderr.strip()[-500:],
            )
            self._stop_event.wait(delay)
            delay = min(delay * 2, RESTART_DELAY_MAX)

    def stop(self) -> None:
        """Stop ssh and the thread."""
        with self._lock:
            self._stop_event.set()
            proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.join(timeout=10)


SSH_CONNECTIONS: dict[str, vpnc.models.connections.Connection] = {}
SSH_TUNNELS: dict[str, SshTunnel] = {}


def start(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Start an SSH tunnel."""
    if connection.config.type != enums.ConnectionType.SSH:
        logger.warning("Invalid module type specified.")
        return

    connection_name = f"{network_instance.id}-{connection.id}"
    ssh_master_socket = SSH_SOCKET_DIR.joinpath(f"{connection_name}.sock")

    tunnel = SSH_TUNNELS.get(connection_name)
    if (
        connection == SSH_CONNECTIONS.get(connection_name)
        and tunnel is not None
        and tunnel.is_alive()
    ):
        logger.debug("No changes detected in connection '%s'.", connection_name)
        return

    stop(network_instance, connection)

    remote_config: str = ""
    if connection.config.remote_config is True:
        if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(
            network_instance,
        )
        remote_tun = f"tun{connection.config.remote_tunnel_id}"
        routes: str = ""
        for i in if_ipv4:
            routes += rf"ip -4 route replace {i.network} dev {remote_tun};"

        for j in if_ipv6:
            routes += rf"ip -6 route replace {j.network} dev {remote_tun};"

        remote_config = rf"""set -e;
sysctl -w net.ipv4.conf.all.forwarding=1;
sysctl -w net.ipv6.conf.all.forwarding=1;
sleep 2;
ip link set dev {remote_tun} up;{routes}
iptables -C INPUT -i {remote_tun} -j ACCEPT &> /dev/null || iptables -A INPUT -i {remote_tun} -j ACCEPT;
ip6tables -C INPUT -i {remote_tun} -j ACCEPT &> /dev/null || ip6tables -A INPUT -i {remote_tun} -j ACCEPT;
iptables -C OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || iptables -A OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;
ip6tables -C OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || ip6tables -A OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"""
        if connection.config.remote_config_interface is not None:
            remote_config = rf"""set -e;
sysctl -w net.ipv4.conf.all.forwarding=1;
sysctl -w net.ipv6.conf.all.forwarding=1;
sleep 2;
ip link set dev {remote_tun} up;{routes}
iptables -C INPUT -i {remote_tun} -j ACCEPT &> /dev/null || iptables -A INPUT -i {remote_tun} -j ACCEPT;
ip6tables -C INPUT -i {remote_tun} -j ACCEPT &> /dev/null || ip6tables -A INPUT -i {remote_tun} -j ACCEPT;
iptables -C OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || iptables -A OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;
ip6tables -C OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || ip6tables -A OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;
iptables -C FORWARD -i {remote_tun} -j ACCEPT &> /dev/null || iptables -A FORWARD -i {remote_tun} -j ACCEPT;
ip6tables -C FORWARD -i {remote_tun} -j ACCEPT &> /dev/null || ip6tables -A FORWARD -i {remote_tun} -j ACCEPT;
iptables -C FORWARD -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || iptables -A FORWARD -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;
ip6tables -C FORWARD -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || ip6tables -A FORWARD -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;
iptables -C -t nat POSTROUTING -o {connection.config.remote_config_interface} -j MASQUERADE &> /dev/null || iptables -t nat -A POSTROUTING -o {connection.config.remote_config_interface} -j MASQUERADE;
ip6tables -C -t nat POSTROUTING -o {connection.config.remote_config_interface} -j MASQUERADE &> /dev/null || ip6tables -t nat -A POSTROUTING -o {connection.config.remote_config_interface} -j MASQUERADE"""

    # A stale socket (e.g. after a kill) would stop ssh from becoming master.
    ssh_master_socket.unlink(missing_ok=True)

    command = [
        "/usr/sbin/ip",
        "netns",
        "exec",
        network_instance.id,
        "/usr/bin/ssh",
        "-o",
        "ControlMaster=yes",
        "-o",
        f"ControlPath={ssh_master_socket}",
        "-o",
        "Tunnel=point-to-point",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-w",
        f"{connection.id}:{connection.config.remote_tunnel_id}",
        f"{connection.config.username}@{connection.config.remote_addrs[0]}",
    ]
    if remote_config:
        command.append(remote_config)
    else:
        command.insert(5, "-N")

    tunnel = SshTunnel(connection_name, command)
    tunnel.start()
    SSH_TUNNELS[connection_name] = tunnel
    SSH_CONNECTIONS[connection_name] = connection


def stop(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Stop an SSH tunnel."""
    connection_name = f"{network_instance.id}-{connection.id}"
    SSH_CONNECTIONS.pop(connection_name, None)
    tunnel = SSH_TUNNELS.pop(connection_name, None)
    if tunnel is not None:
        tunnel.stop()


@atexit.register
def stop_all() -> None:
    """Stop all SSH tunnels."""
    for name in list(SSH_TUNNELS):
        SSH_CONNECTIONS.pop(name, None)
        SSH_TUNNELS.pop(name).stop()
