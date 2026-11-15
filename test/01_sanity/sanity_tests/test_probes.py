"""Hosts behind hub00's connections are probed; hub01 has no probes."""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from . import conftest

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"
PROBED = "hub00"
NOT_PROBED = "hub01"
# Probed by hub00 through the SSH tunnel of C0001-00: an echo, and a TCP port
# nothing listens on.
NETNS = "ip netns exec C0001-00 "
ECHO_TARGET = "172.16.31.1"
TCP_TARGET = ("2001:db8:c57:31::4", 81)
# A probe of hub00 to an address that isn't in use.
UNUSED = "172.17.30.9"
# The full check tests the probes every 30 seconds.
FULL_CHECK = 45
# The tests kept per probe: 3 minutes.
HISTORY = 6
# What timeout exits with when the command didn't finish.
TIMED_OUT = 124

CONNECTIONS = ["C0001-00-0", "C0001-00-1", "C0001-01-0"]


def probes(host: str, name: str) -> list[dict[str, Any]]:
    """Return a connection's probes with their last test."""
    output = conftest.run_cmd(host, f"{VPNCTL} -o json connections show {name}")
    return json.loads(output)["probes"]


def pings(host: str, address: str) -> bool:
    """Return whether an address answers a ping from C0001-00."""
    try:
        conftest.run_cmd(host, f"{NETNS}ping -c 1 -W 2 {address}")
    except subprocess.CalledProcessError:
        return False
    return True


def tcp_refused(host: str, address: str, port: int) -> bool:
    """Return whether a TCP connection from C0001-00 is refused, not unanswered."""
    try:
        conftest.run_cmd_shell(
            host,
            f"{NETNS}timeout 3 bash -c '</dev/tcp/{address}/{port}'",
        )
    except subprocess.CalledProcessError as err:
        return err.returncode != TIMED_OUT
    return False


class TestProbes:
    """Probes tell whether hosts behind a connection answer."""

    @pytest.mark.parametrize("name", CONNECTIONS)
    def test_answered(self, name: str) -> None:
        """The hosts in use answer, over IPsec, SSH and WireGuard; a refusal too."""

        def tested() -> list[dict[str, Any]]:
            current = probes(PROBED, name)
            return current if all(p["failed"] is not None for p in current) else []

        current = conftest.wait_until(tested, FULL_CHECK, message="tested probes")

        assert {p["address"] for p in current if p["failed"]} <= {UNUSED}
        assert any(not p["failed"] for p in current)

    def test_history(self) -> None:
        """The last tests of a probe are kept, with how long the answer took."""
        output = conftest.run_cmd(
            PROBED,
            f"{VPNCTL} -o json connections probes {CONNECTIONS[0]}",
        )

        for probe in json.loads(output):
            assert 1 <= len(probe["history"]) <= HISTORY
            assert all(
                test["failed"] == (test["avg_delay"] is None)
                for test in probe["history"]
            )

    @pytest.mark.parametrize("name", CONNECTIONS)
    def test_not_configured(self, name: str) -> None:
        """A connection without probes isn't tested."""
        assert probes(NOT_PROBED, name) == []

    def test_firewall(self) -> None:
        """A network instance only sends what its probes send."""
        assert pings(PROBED, ECHO_TARGET)
        assert tcp_refused(PROBED, *TCP_TARGET)

        assert not pings(NOT_PROBED, ECHO_TARGET)
        assert not tcp_refused(NOT_PROBED, *TCP_TARGET)
