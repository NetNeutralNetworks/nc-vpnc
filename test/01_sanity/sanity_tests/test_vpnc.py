"""Test that vpnc runs on every node."""

from __future__ import annotations

import pytest

from . import conftest

VPNC_NODES = ["hub00", "hub01", "end00", "end01"]


@pytest.mark.parametrize("host", VPNC_NODES)
def test_vpnc_running_without_restarts(host: str) -> None:
    """Vpnc is running and systemd never had to restart it."""
    show = "systemctl show ncubed-vpnc.service -P"
    assert conftest.run_cmd(host, f"{show} ActiveState").strip() == "active"
    restarts = conftest.run_cmd(host, f"{show} NRestarts").strip()
    assert restarts == "0", f"vpnc on {host} restarted {restarts} times"


@pytest.mark.parametrize("host", ["hub00", "hub01"])
def test_ssh_is_unprivileged(host: str) -> None:
    """The ssh of an SSH connection isn't root and has no capabilities."""
    users = conftest.run_cmd(host, "ps -C ssh -o user:32=").split()

    assert set(users) == {"vpnc-ssh"}
    assert conftest.capabilities(host, "ssh") == set()


SECRET_DIRS = (
    "/opt/ncubed/config/vpnc/active /opt/ncubed/config/vpnc/history"  # noqa: S105
    " /etc/swanctl/conf.d /etc/wireguard"
)


@pytest.mark.parametrize("host", VPNC_NODES)
def test_secrets_only_for_root(host: str) -> None:
    """Pre-shared and private keys and their directories are root's."""
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

    # charon's user (vpnc-swan) can't replace the directory vpnc writes in.
    owners = conftest.run_cmd_shell(host, "stat -c '%U %a' /etc/swanctl")
    assert owners.split() == ["root", "755"]
