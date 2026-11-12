"""Connections stuck halfway are reset after a while and come up again."""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any

import pytest

from . import conftest

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"
# An IPsec initiator, the same tunnel on its responder, and an SSH tunnel whose
# server is routed via that tunnel.
IPSEC = ("end00", "CORE-0")
IPSEC_RESPONDER = ("hub00", "C0001-00-0")
SSH = ("hub00", "C0001-00-1")
# Behind the SSH server, routed via the SSH tunnel.
SSH_TARGET = "172.16.31.1/22"
SSH_SERVER = "cli00"
# New SSH connections to the server hang instead of failing.
SSH_DROP_NEW = "INPUT -i eth1 -p tcp --dport 22 -m conntrack --ctstate NEW -j DROP"
UP_TIMEOUT = 90
# ssh reconnects after up to 30s.
SSH_RECONNECT = 45
# The full check, which would fix a connection by itself, runs every 30 seconds.
FULL_CHECK = 35
# Down for 3 minutes, noticed by a full check, plus setting it up again.
RESET_TIMEOUT = 300


def connection(host: str, name: str) -> dict[str, Any]:
    """Return a connection's state and details."""
    return json.loads(
        conftest.run_cmd(host, f"{VPNCTL} -o json connections show {name}"),
    )


def resets(host: str, name: str) -> int:
    """Return how often a connection was reset automatically in the last 24 hours."""
    return connection(host, name)["details"]["auto_resets_24h"]


def ssh_pid() -> str:
    """Return the pid of the SSH tunnel's ssh, or '' if it doesn't run."""
    try:
        return conftest.run_cmd(
            SSH[0],
            f"pgrep -f ControlPath=/run/vpnc/ssh/{SSH[1]}.sock",
        ).strip()
    except subprocess.CalledProcessError:
        return ""


def ssh_tunnel_works() -> bool:
    """Return whether a TCP connection through the SSH tunnel succeeds."""
    try:
        conftest.run_cmd_shell(
            SSH[0],
            f"ip netns exec C0001-00 timeout 2 bash -c '</dev/tcp/{SSH_TARGET}'",
        )
    except subprocess.CalledProcessError:
        return False
    return True


def all_up() -> bool:
    """Return whether the connections are up (and SSH passes traffic)."""
    return (
        all(connection(*c)["state"] == "up" for c in (IPSEC, SSH))
        and ssh_tunnel_works()
    )


@pytest.fixture(autouse=True)
def connections_up() -> Any:  # noqa: ANN401
    """Start and end with the connections up."""
    conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")
    # A full check sees them up, so earlier resets don't delay the next one.
    time.sleep(FULL_CHECK)
    yield
    try:
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")
    except TimeoutError:
        # A failed test leaves them down until the next automatic reset.
        for host, name in (IPSEC, SSH):
            conftest.run_cmd(host, f"{VPNCTL} connections reset {name}")
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")


class TestStuckRecovery:
    """Connections that don't come up by themselves are reset."""

    def test_ike_sa_without_child_sa(self) -> None:
        """An IKE SA without a child SA is replaced by one that is up.

        The SSH tunnel over it goes down too, but isn't reset: that can't help.
        """
        # The IKE SA's id isn't compared: a rekey changes it too.
        ipsec_resets = resets(*IPSEC) + resets(*IPSEC_RESPONDER)
        ssh_resets = resets(*SSH)
        conftest.run_cmd(IPSEC[0], f"swanctl --terminate --child {IPSEC[1]}")

        time.sleep(FULL_CHECK)
        current = connection(*IPSEC)
        assert current["state"] != "up"
        assert current["details"]["child_sas"] == []
        assert resets(*IPSEC) + resets(*IPSEC_RESPONDER) == ipsec_resets

        conftest.wait_until(
            lambda: connection(*IPSEC)["state"] == "up",
            timeout=RESET_TIMEOUT,
            message=f"{IPSEC[1]} to be up after a reset",
        )
        assert resets(*IPSEC) + resets(*IPSEC_RESPONDER) > ipsec_resets
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="SSH to reconnect")
        assert resets(*SSH) == ssh_resets

    def test_hung_ssh(self) -> None:
        """An ssh that hangs before the tunnel is up is replaced."""
        old = ssh_pid()
        before = resets(*SSH)
        server = SSH_SERVER
        conftest.run_cmd_shell(server, f"iptables -I {SSH_DROP_NEW}")
        hung = ""
        try:
            conftest.close_ssh_sessions()
            # The new ssh waits for the server; stopped, it never gives up.
            hung = conftest.wait_until(
                lambda: (pid := ssh_pid()) not in ("", old) and pid,
                timeout=SSH_RECONNECT,
                message="ssh to reconnect",
            )
            conftest.run_cmd(SSH[0], f"kill -STOP {hung}")
        finally:
            conftest.run_cmd_shell(server, f"iptables -D {SSH_DROP_NEW}")

        try:
            time.sleep(FULL_CHECK)
            assert ssh_pid() == hung
            assert connection(*SSH)["state"] == "down"

            conftest.wait_until(
                lambda: ssh_pid() not in ("", hung) and ssh_tunnel_works(),
                timeout=RESET_TIMEOUT,
                message="a new ssh",
            )
            assert resets(*SSH) == before + 1
        finally:
            conftest.run_cmd_shell(SSH[0], f"kill -KILL {hung} || true")
