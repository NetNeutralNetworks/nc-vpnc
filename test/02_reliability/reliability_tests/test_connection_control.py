"""Connections can be stopped, started and reset with vpnctl, and show their logs."""

from __future__ import annotations

import datetime
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
# The tenant side of end01.
PHYSICAL = ("end01", "ENDPOINT-0")
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


def enabled(host: str, name: str) -> bool:
    """Return whether the connection is enabled in its active configuration."""
    ni, _, number = name.rpartition("-")
    target, key = ("service", ni) if "-" not in ni else ni.split("-")
    path = f"network_instances.{key}.connections.{number}.enabled"
    return vpnctl(host, f"config show {target} {path}")


def timestamp(text: str) -> float:
    """Return the Unix time of an ISO 8601 time."""
    return datetime.datetime.fromisoformat(text).timestamp()


def physical_link() -> str:
    """Return the link of the physical connection, as ip shows it."""
    return conftest.run_cmd(PHYSICAL[0], "ip -n ENDPOINT link show eth2")


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
        return details["last_handshake"] is None
    return not ssh_pid() and not ssh_tunnel_works()


def all_up() -> bool:
    """Return whether the connections are up (and SSH passes traffic)."""
    return (
        all(
            connection(host, name)["oper_status"] == "UP"
            for host, name in CONNECTIONS
        )
        and ssh_tunnel_works()
    )


@pytest.fixture(autouse=True)
def connections_up() -> Any:  # noqa: ANN401
    """Start with the connections up, and leave them started."""
    conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")
    yield
    for host, name in CONNECTIONS:
        if connection(host, name)["admin_status"] == "DOWN":
            conftest.run_cmd(host, f"{VPNCTL} connections start {name}")
    conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")


class TestConnectionControl:
    """Stop, start and reset."""

    def test_stop_and_start(self) -> None:
        """Stopped connections stay down through a full check, and start again.

        Stopping one disables it in its configuration.
        """
        for host, name in CONNECTIONS:
            assert connection(host, name)["oper_status"] == "UP"
            output = conftest.run_cmd(host, f"{VPNCTL} connections stop {name}")
            assert output == f"Stopped {name}; it's DOWN.\n"
            assert enabled(host, name) is False

        for host, name in CONNECTIONS:
            conftest.wait_until(
                lambda host=host, name=name: is_down(host, name),
                timeout=10,
                message=f"{name} on {host} to be down",
            )
        time.sleep(FULL_CHECK)
        for host, name in CONNECTIONS:
            assert is_down(host, name), f"{name} on {host} came up again"
            current = connection(host, name)
            assert (current["admin_status"], current["oper_status"]) == ("DOWN", "DOWN")

        for host, name in CONNECTIONS:
            conftest.run_cmd(host, f"{VPNCTL} connections start {name}")
            assert enabled(host, name) is True
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to start")

    def test_reset(self) -> None:
        """A reset sets up a new IKE SA, WireGuard session and ssh process."""
        ike_id = connection(*IPSEC)["details"]["ike_id"]
        pid = ssh_pid()
        started = int(time.time())

        for host, name in CONNECTIONS:
            conftest.run_cmd(host, f"{VPNCTL} connections reset {name}")

        def reset_done() -> bool:
            handshake = connection(*WIREGUARD)["details"]["last_handshake"]
            ipsec = connection(*IPSEC)
            return (
                ipsec["oper_status"] == "UP"
                and ipsec["details"]["ike_id"] != ike_id
                and handshake is not None
                and timestamp(handshake) >= started
                and ssh_pid() not in ("", pid)
            )

        conftest.wait_until(reset_done, timeout=UP_TIMEOUT, message="the resets")
        conftest.wait_until(all_up, timeout=UP_TIMEOUT, message="connections to be up")

    def test_network_instance(self) -> None:
        """A network instance's VPN connections are restarted; restart is reset."""
        handshake_before = int(time.time())
        output = conftest.run_cmd("hub00", f"{VPNCTL} connections restart C0001-01")
        assert output.startswith("Reset C0001-01-0;")

        def new_handshake() -> bool:
            handshake = connection(*WIREGUARD)["details"]["last_handshake"]
            return handshake is not None and timestamp(handshake) >= handshake_before

        conftest.wait_until(new_handshake, timeout=UP_TIMEOUT, message="a handshake")

    def test_physical(self) -> None:
        """A physical connection can't be reset; stopped, its interface is down."""
        with pytest.raises(subprocess.CalledProcessError) as err:
            conftest.run_cmd("hub00", f"{VPNCTL} connections reset EXTERNAL-0")
        assert "physical connection" in err.value.stderr

        host, name = PHYSICAL
        conftest.run_cmd(host, f"{VPNCTL} connections stop {name}")
        try:
            conftest.wait_until(
                lambda: "state DOWN" in physical_link(),
                timeout=10,
                message="the interface to be down",
            )
            assert connection(host, name)["oper_status"] == "DOWN"
        finally:
            conftest.run_cmd(host, f"{VPNCTL} connections start {name}")
        conftest.wait_until(
            lambda: connection(host, name)["oper_status"] == "UP",
            timeout=10,
            message="the interface to be up",
        )

    def test_mtu(self) -> None:
        """A connection's MTU is set on its interface; without, it's the default."""
        host, name = WIREGUARD
        path = "network_instances.01.connections.0.mtu"
        default = connection(host, name)["mtu"]
        conftest.run_cmd(host, f"{VPNCTL} config set C0001 {path} 1380")
        conftest.run_cmd(host, f"{VPNCTL} config commit C0001")
        try:
            conftest.wait_until(
                lambda: connection(host, name)["mtu"] == 1380,  # noqa: PLR2004
                timeout=10,
                message="the MTU to be set",
            )
        finally:
            conftest.run_cmd(host, f"{VPNCTL} config delete C0001 {path}")
            conftest.run_cmd(host, f"{VPNCTL} config commit C0001")
        conftest.wait_until(
            lambda: connection(host, name)["mtu"] == default,
            timeout=10,
            message="the default MTU",
        )


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
