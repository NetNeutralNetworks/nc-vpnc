"""SSH tunnels recover after the server closes them or is unreachable."""

from __future__ import annotations

import subprocess
import time

from . import conftest

HUBS = ["hub00", "hub01"]
NETWORK_INSTANCE = "C0001-00"
# Behind the SSH server; C0001-00 routes it via the SSH tunnel.
TARGET = "172.16.31.1/22"

# Reconnect delay is capped at 30s, plus connect time.
RECOVERY_TIMEOUT = 60


def tunnel_works(host: str) -> bool:
    """Return whether a TCP connection through the SSH tunnel succeeds."""
    try:
        conftest.run_cmd_shell(
            host,
            f"ip netns exec {NETWORK_INSTANCE} timeout 2 bash -c '</dev/tcp/{TARGET}'",
        )
    except subprocess.CalledProcessError:
        return False
    return True


def ssh_pid(host: str) -> str:
    """Return the pid of the SSH tunnel's ssh, or '' if it doesn't run."""
    try:
        return conftest.run_cmd(
            host,
            f"pgrep -f ControlPath=/run/vpnc/ssh/{NETWORK_INSTANCE}-1.sock",
        ).strip()
    except subprocess.CalledProcessError:
        return ""


def wait_for_tunnels() -> None:
    """Wait until the SSH tunnels of all hubs pass traffic."""
    for host in HUBS:
        conftest.wait_until(
            lambda host=host: tunnel_works(host),
            timeout=RECOVERY_TIMEOUT,
            message=f"SSH tunnel on {host} to recover",
        )


class TestSshRecovery:
    """SSH tunnels reconnect."""

    def test_server_closes_sessions(self) -> None:
        """Tunnels reconnect after the server closes the sessions (ssh exits 0)."""
        wait_for_tunnels()
        before = {host: ssh_pid(host) for host in HUBS}
        conftest.close_ssh_sessions()
        for host in HUBS:
            conftest.wait_until(
                lambda host=host: ssh_pid(host) not in ("", before[host])
                and tunnel_works(host),
                timeout=RECOVERY_TIMEOUT,
                message=f"a new ssh on {host}",
            )

    def test_server_unreachable(self) -> None:
        """Tunnels reconnect after the server was unreachable for a while."""
        wait_for_tunnels()
        with conftest.ssh_server_down():
            conftest.wait_until(
                lambda: not any(tunnel_works(host) for host in HUBS),
                timeout=10,
                message="SSH tunnels to go down",
            )
            # Several failed attempts, so the reconnect delay has grown.
            time.sleep(60)
        wait_for_tunnels()
