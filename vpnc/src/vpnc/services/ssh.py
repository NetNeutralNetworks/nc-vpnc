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
from vpnc import helpers, shared
from vpnc.models import enums

if TYPE_CHECKING:
    import vpnc.models.network_instance


logger = logging.getLogger("vpnc")

SSH_SOCKET_DIR = pathlib.Path("/run/vpnc/ssh/")
SSH_SOCKET_DIR.mkdir(mode=0o770, parents=True, exist_ok=True)

# Seconds before reconnecting, doubled after each failed attempt.
RESTART_DELAY_MIN = 1
RESTART_DELAY_MAX = 30
# A tunnel that stayed up this long (seconds) resets the delay.
STABLE_AFTER = 60
# Characters logged of a line ssh prints.
MAX_LINE = 500


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
        # When the running ssh started (Unix time), None if it doesn't run.
        self.started: float | None = None

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
                    errors="replace",
                )
                self.started = time.time()
            # Logged with the connection name, so it shows in its logs.
            last = ""
            for line in proc.stderr or []:
                # From the server: no control characters (e.g. terminal escapes).
                if line := helpers.printable(line.strip())[:MAX_LINE]:
                    logger.info("SSH tunnel %s: %s", self.connection_name, line)
                    last = line
            proc.wait()
            self.started = None
            if self._stop_event.is_set():
                return
            if time.monotonic() - started > STABLE_AFTER:
                delay = RESTART_DELAY_MIN
            logger.warning(
                "SSH tunnel %s exited (rc=%s), reconnecting in %ss: %s",
                self.connection_name,
                proc.returncode,
                delay,
                last[-500:],
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
# The reconciler and the API start and stop tunnels.
LOCK = threading.RLock()


def _remote_script(tun: str, routes: list[str], interface: str | None) -> str:
    """Return the commands that set up the remote side of a tunnel.

    With an interface, traffic from the tunnel is forwarded and masqueraded
    out of it. Rules are only added when missing; it runs in any POSIX shell.
    """
    established = "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    rules = [
        ("", f"INPUT -i {tun} -j ACCEPT"),
        ("", f"OUTPUT -o {tun} {established}"),
    ]
    if interface is not None:
        rules += [
            ("", f"FORWARD -i {tun} -j ACCEPT"),
            ("", f"FORWARD -o {tun} {established}"),
            ("-t nat ", f"POSTROUTING -o {interface} -j MASQUERADE"),
        ]
    commands = [
        "set -e",
        "sysctl -w net.ipv4.conf.all.forwarding=1",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "sleep 2",
        f"ip link set dev {tun} up",
        *(f"{route} dev {tun}" for route in routes),
        *(
            f"{program} {table}-C {rule} >/dev/null 2>&1 || {program} {table}-A {rule}"
            for table, rule in rules
            for program in ("iptables", "ip6tables")
        ),
    ]
    return ";\n".join(commands)


def start(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Start an SSH tunnel."""
    if connection.config.type != enums.ConnectionType.SSH:
        logger.warning("Invalid module type specified.")
        return

    with LOCK:
        _start(network_instance, connection)


def _start(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    connection_name = connection.name(network_instance)
    ssh_master_socket = SSH_SOCKET_DIR.joinpath(f"{connection_name}.sock")
    if connection_name in shared.STOPPED_CONNECTIONS:
        stop(network_instance, connection)
        return

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
        remote_config = _remote_script(
            f"tun{connection.config.remote_tunnel_id}",
            [f"ip -4 route replace {i.network}" for i in if_ipv4]
            + [f"ip -6 route replace {j.network}" for j in if_ipv6],
            connection.config.remote_config_interface,
        )

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
    connection_name = connection.name(network_instance)
    with LOCK:
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
