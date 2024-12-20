"""Manages SSH connections and observers used to monitor file changes."""

from __future__ import annotations

import atexit
import logging
import os
import pathlib
import signal
import subprocess
from typing import TYPE_CHECKING

import pyroute2

import vpnc.models.connections
import vpnc.models.ssh
from vpnc.models import enums

if TYPE_CHECKING:
    import vpnc.models.network_instance


logger = logging.getLogger("vpnc")

SSH_SOCKET_DIR = pathlib.Path("/run/vpnc/ssh/")
SSH_SOCKET_DIR.mkdir(mode=770, parents=True, exist_ok=True)


SSH_CONNECTIONS: dict[str, vpnc.models.connections.Connection] = {}


def start(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Start SSH connections."""
    if connection.config.type != enums.ConnectionType.SSH:
        logger.warning("Invalid module type specified.")
        return

    connection_name = f"{network_instance.id}-{connection.id}"
    ssh_master_socket = SSH_SOCKET_DIR.joinpath(f"{connection_name}.sock")
    ssh_master_pid_file = SSH_SOCKET_DIR.joinpath(f"{connection_name}-master.pid")

    autossh_master_env = os.environ.copy()
    # AUTOSSH_PIDFILE       - write autossh pid to specified file.
    autossh_master_env["AUTOSSH_PIDFILE"] = str(ssh_master_pid_file)
    # AUTOSSH_POLL          - poll time in seconds; default is 600.
    #                       Changing this will also change the first
    #                       poll time, unless AUTOSSH_FIRST_POLL is
    #                       used to set it to something different.
    #                       If the poll time is less than twice the
    #                       network timeouts (default 15 seconds) the
    #                       network timeouts will be adjusted downward
    #                       to 1/2 the poll time.
    autossh_master_env["AUTOSSH_POLL"] = "60"
    # AUTOSSH_GATETIME      - how long ssh must be up before we consider
    #                       it a successful connection. Default is 30
    #                       seconds. If set to 0, then this behaviour
    #                       is disabled, and as well, autossh will retry
    #                       even on failure of first attempt to run ssh.
    autossh_master_env["AUTOSSH_GATETIME"] = "0"
    autossh_master_env["AUTOSSH_DEBUG"] = "1"

    if connection == SSH_CONNECTIONS.get(connection_name):
        logger.info("No changes detected in connection '%s'.", connection_name)
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

        remote_config = rf"""'set -e;
sysctl -w net.ipv4.conf.all.forwarding=1;
sysctl -w net.ipv6.conf.all.forwarding=1;
sleep 2;
ip link set dev {remote_tun} up;{routes}
iptables -C INPUT -i {remote_tun} -j ACCEPT &> /dev/null || iptables -A INPUT -i {remote_tun} -j ACCEPT;
ip6tables -C INPUT -i {remote_tun} -j ACCEPT &> /dev/null || ip6tables -A INPUT -i {remote_tun} -j ACCEPT;
iptables -C OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || iptables -A OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;
ip6tables -C OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &> /dev/null || ip6tables -A OUTPUT -o {remote_tun} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'"""
        if connection.config.remote_config_interface is not None:
            remote_config = rf"""'set -e;
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
ip6tables -C -t nat POSTROUTING -o {connection.config.remote_config_interface} -j MASQUERADE &> /dev/null || ip6tables -t nat -A POSTROUTING -o {connection.config.remote_config_interface} -j MASQUERADE'"""

    master_local_tunnel = rf"""
/usr/sbin/ip netns exec {network_instance.id} \
autossh -f -M 0 \
-o ControlMaster=yes \
-o ControlPath={ssh_master_socket} \
-o Tunnel=point-to-point \
-o ExitOnForwardFailure=yes \
-o ConnectTimeout=10 \
-o ServerAliveInterval=5 \
-o ServerAliveCountMax=5 \
-o StrictHostKeyChecking=accept-new \
-w {connection.id}:{connection.config.remote_tunnel_id} \
{connection.config.username}@{connection.config.remote_addrs[0]} {remote_config}
"""

    master_tunnel_proc = subprocess.run(  # noqa: S602
        master_local_tunnel,
        capture_output=True,
        text=True,
        shell=True,
        check=True,
        env=autossh_master_env,
    )
    logger.info(master_tunnel_proc.args)
    logger.info("%s\n%s", master_tunnel_proc.stdout, master_tunnel_proc.stderr)

    SSH_CONNECTIONS[connection_name] = connection
    atexit.register(stop, network_instance, connection)


def stop(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Stop the long running SSH configuration tasks."""
    connection_name = f"{network_instance.id}-{connection.id}"
    ssh_connection = SSH_CONNECTIONS.pop(connection_name, None)
    if ssh_connection is None or ssh_connection.config.type != enums.ConnectionType.SSH:
        return
    ssh_master_pid_file = SSH_SOCKET_DIR.joinpath(f"{connection_name}-master.pid")
    ssh_master_socket = SSH_SOCKET_DIR.joinpath(f"{connection_name}.sock")
    ssh_master_pid = None
    if ssh_master_pid_file.exists():
        ssh_master_pid = int(ssh_master_pid_file.read_text())

    if ssh_master_pid:
        proc = pyroute2.NSPopen(
            network_instance.id,
            [
                "ssh",
                "-o",
                f"ControlPath={ssh_master_socket}",
                "-O",
                "exit",
                f"{connection.config.username}:{connection.config.remote_addrs[0]}",
            ],
        )
        proc.wait()
        proc.release()
        process_path = pathlib.Path(f"/proc/{ssh_master_pid}/comm")
        if not process_path.exists():
            return
        process_name = process_path.read_text().strip()
        if process_name != "autossh":
            return
        os.kill(ssh_master_pid, signal.SIGTERM)
        ssh_master_pid_file.unlink(missing_ok=True)
