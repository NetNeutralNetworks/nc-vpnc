"""Connections can be stopped, started and reset with vpnctl, and show their logs."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from typing import Any

import pytest

from . import conftest

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"
# (host, connection): an IPsec initiator, WireGuard and SSH.
IPSEC = ("end00", "CORE-0")
WIREGUARD = ("hub00", "C0001-01-0")
SSH = ("hub00", "C0001-00-1")
CONNECTIONS = [IPSEC, WIREGUARD, SSH]
# Behind the SSH server, routed via the SSH tunnel.
SSH_TARGET = "172.16.31.1/22"
# Reconnect delays are up to 30s (SSH); peers set up IPsec and WireGuard.
UP_TIMEOUT = 90
# The full check, which would set connections up again, runs every 30 seconds.
FULL_CHECK = 35


def vpnctl(host: str, args: str) -> Any:  # noqa: ANN401
    """Run vpnctl with JSON output."""
    return json.loads(conftest.run_cmd(host, f"{VPNCTL} -o json {args}"))


def connection(host: str, name: str) -> dict[str, Any]:
    """Return a connection's state and details."""
    return vpnctl(host, f"connections show {name}")


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


def is_down(host: str, name: str) -> bool:
    """Return whether the connection is really down (no SA, peer or ssh)."""
    details = connection(host, name)["details"]
    if (host, name) == IPSEC:
        return "ike_state" not in details
    if (host, name) == WIREGUARD:
        return details["last_handshake_seconds_ago"] is None
    return not ssh_pid() and not ssh_tunnel_works()


def all_up() -> bool:
    """Return whether the connections are up (and SSH passes traffic)."""
    return (
        all(connection(host, name)["state"] == "up" for host, name in CONNECTIONS)
        and ssh_tunnel_works()
    )


@pytest.fixture(autouse=True)
def connections_up() -> Any:  # noqa: ANN401
    """Start with the connections up, and leave them started."""
    conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")
    yield
    for host, name in CONNECTIONS:
        if connection(host, name)["state"] == "stopped":
            conftest.run_cmd(host, f"{VPNCTL} connections start {name}")
    conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")


class TestConnectionControl:
    """Stop, start and reset."""

    def test_stop_and_start(self) -> None:
        """Stopped connections stay down through a full check, and start again."""
        for host, name in CONNECTIONS:
            assert connection(host, name)["state"] == "up"
            output = conftest.run_cmd(host, f"{VPNCTL} connections stop {name}")
            assert output == f"Stopped {name}; it's stopped.\n"

        for host, name in CONNECTIONS:
            conftest.wait_until(
                lambda host=host, name=name: is_down(host, name),
                timeout=10,
                message=f"{name} on {host} to be down",
            )
        time.sleep(FULL_CHECK)
        for host, name in CONNECTIONS:
            assert is_down(host, name), f"{name} on {host} came up again"
            assert connection(host, name)["state"] == "stopped"

        for host, name in CONNECTIONS:
            conftest.run_cmd(host, f"{VPNCTL} connections start {name}")
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to start")

    def test_reset(self) -> None:
        """A reset sets up a new IKE SA, WireGuard session and ssh process."""
        ike_id = connection(*IPSEC)["details"]["ike_id"]
        pid = ssh_pid()
        started = time.time()

        for host, name in CONNECTIONS:
            conftest.run_cmd(host, f"{VPNCTL} connections reset {name}")

        def reset_done() -> bool:
            handshake = connection(*WIREGUARD)["details"]["last_handshake_seconds_ago"]
            ipsec = connection(*IPSEC)
            return (
                ipsec["state"] == "up"
                and ipsec["details"]["ike_id"] != ike_id
                and handshake is not None
                and handshake <= time.time() - started
                and ssh_pid() not in ("", pid)
            )

        conftest.wait_until(reset_done, timeout=UP_TIMEOUT, message="the resets")
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")

    def test_network_instance(self) -> None:
        """A network instance's VPN connections are restarted; restart is reset."""
        handshake_before = time.time()
        output = conftest.run_cmd("hub00", f"{VPNCTL} connections restart C0001-01")
        assert output.startswith("Reset C0001-01-0;")

        def new_handshake() -> bool:
            ago = connection(*WIREGUARD)["details"]["last_handshake_seconds_ago"]
            return ago is not None and ago <= time.time() - handshake_before

        conftest.wait_until(new_handshake, timeout=UP_TIMEOUT, message="a handshake")

    def test_physical(self) -> None:
        """A physical connection can't be stopped."""
        with pytest.raises(subprocess.CalledProcessError) as err:
            conftest.run_cmd("hub00", f"{VPNCTL} connections stop EXTERNAL-0")

        assert "physical connection" in err.value.stderr


class TestConnectionLogs:
    """A connection's log has its lines from vpnc, ssh and charon."""

    def test_logs(self) -> None:
        """After a reset, the logs show it: charon's IKE lines, vpnc's and ssh's."""
        for host, name in (IPSEC, SSH):
            conftest.run_cmd(host, f"{VPNCTL} connections reset {name}")
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")

        ipsec = vpnctl(IPSEC[0], f"connections logs {IPSEC[1]} -n 200")
        assert any(
            line["source"] == "charon" and "IKE_SA" in line["message"]
            for line in ipsec
        )
        assert any(
            line["source"] == "vpnc"
            and line["message"] == f"Resetting connection {IPSEC[1]}."
            for line in ipsec
        )
        assert [line["time"] for line in ipsec] == sorted(
            line["time"] for line in ipsec
        )

        ssh = vpnctl(SSH[0], f"connections logs {SSH[1]} -n 200")
        assert any(
            line["message"] == f"Resetting connection {SSH[1]}." for line in ssh
        )
        assert all(SSH[1] in line["message"] for line in ssh)

    def test_follow(self) -> None:
        """A followed log shows new lines when they're logged."""
        host, name = IPSEC
        with tempfile.TemporaryFile("w+") as output:

            def lines() -> list[str]:
                output.seek(0)
                return output.read().splitlines()

            command = f"{VPNCTL} connections logs {name} -n 1 -f"
            follower = subprocess.Popen(  # noqa: S603
                ["docker", "exec", f"clab-vpnc-{host}", *command.split()],  # noqa: S607
                stdout=output,
            )
            try:
                conftest.wait_until(lines, timeout=10, message="the last line")
                shown = len(lines())
                conftest.run_cmd(host, f"{VPNCTL} connections reset {name}")
                conftest.wait_until(
                    lambda: any(
                        f"Resetting connection {name}." in line
                        for line in lines()[shown:]
                    ),
                    timeout=10,
                    message="the reset to show in the followed log",
                )
            finally:
                follower.kill()
                follower.wait()
                # Killing docker exec leaves vpnctl running in the container.
                conftest.run_cmd_shell(host, "pkill -f 'connections logs' || true")
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")
