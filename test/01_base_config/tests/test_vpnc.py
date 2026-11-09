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
