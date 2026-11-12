"""Test that vpnc runs on every node."""

from __future__ import annotations

import subprocess

import pytest

from . import conftest

VPNC_NODES = ["hub00", "hub01", "end00", "end01"]


@pytest.mark.parametrize("host", VPNC_NODES)
def test_vpnc_running_without_restarts(host: str) -> None:
    """vpnc is running and never crashed (a crash restarts the container)."""
    restarts = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "inspect",
            "--format",
            "{{.RestartCount}}",
            f"clab-vpnc-{host}",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert restarts == "0", f"{host} restarted {restarts} times"

    processes = conftest.run_cmd_shell(host, "pgrep -fc /opt/ncubed/vpnc/bin/vpnc")
    assert int(processes) >= 1


SECRET_DIRS = (
    "/opt/ncubed/config/vpnc/active /opt/ncubed/config/vpnc/history"
    " /etc/swanctl/conf.d /etc/wireguard"
)


@pytest.mark.parametrize("host", VPNC_NODES)
def test_secrets_only_for_root(host: str) -> None:
    """Pre-shared and private keys, their directories and the logs are root's."""
    entries = conftest.run_cmd_shell(
        host,
        f"find {SECRET_DIRS} -printf '%u %m %y %p\\n'",
    ).splitlines()
    assert entries
    wrong = [
        entry
        for entry in entries
        if entry.split()[:3] not in (["root", "700", "d"], ["root", "600", "f"])
    ]
    assert not wrong

    # charon's user (swan) can't replace the directory vpnc writes in.
    owners = conftest.run_cmd_shell(
        host,
        "stat -c '%U %a' /etc/swanctl /var/log/ncubed/vpnc",
    ).splitlines()
    assert owners == ["root 755", "root 750"]
