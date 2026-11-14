"""WireGuard interfaces use their configured ports."""

from __future__ import annotations

import pytest

from . import conftest

# (host, network instance, interface): local port.
PORTS = {
    ("hub00", "C0001-01", "wg-C0001-01-0"): 51820,
    ("hub01", "C0001-01", "wg-C0001-01-0"): 51820,
    ("end01", "CORE", "wg-CORE-0"): 51820,
    ("end01", "CORE", "wg-CORE-1"): 51821,
}


class TestWireGuard:
    """Test if WireGuard is correctly configured."""

    @pytest.mark.parametrize(("host", "netns", "ifname"), PORTS)
    def test_listen_port(self, host: str, netns: str, ifname: str) -> None:
        """An interface listens on its configured port."""
        port = conftest.run_cmd(
            host,
            f"ip netns exec {netns} wg show {ifname} listen-port",
        )

        assert int(port) == PORTS[host, netns, ifname]
