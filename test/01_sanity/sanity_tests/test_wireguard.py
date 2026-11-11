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

    @pytest.mark.parametrize("host", sorted({host for host, _, _ in PORTS}))
    def test_ports_are_unique(self, host: str) -> None:
        """All interfaces listen in EXTERNAL, so no two share a port."""
        ports = [port for (h, _, _), port in PORTS.items() if h == host]
        sockets = conftest.run_cmd(host, "ip netns exec EXTERNAL ss -Hlun")
        listening = [
            int(line.split()[3].rsplit(":", 1)[1])
            for line in sockets.splitlines()
            if line.split()[3].startswith(("0.0.0.0:", "[::]:", "*:"))
        ]

        # One IPv4 and one IPv6 socket per interface.
        counts = {port: listening.count(port) for port in ports}
        assert counts == dict.fromkeys(ports, 2)
