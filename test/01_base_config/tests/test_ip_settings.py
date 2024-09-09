from __future__ import annotations

import ipaddress
import json
from typing import Any

import pytest

from . import conftest
from .data import data_test_ip_settings_interfaces, data_test_ip_settings_routes

InterfaceName = str
InterfaceState = str
Addresses = frozenset[str]
InterfaceInfo = tuple[InterfaceName, InterfaceState, Addresses]


def get_interfaces(host: str, netns: str) -> list[InterfaceInfo]:
    """Get interface status and IP addresses."""
    output = json.loads(
        conftest.run_cmd(host, f"ip --json --netns {netns} address"),
    )

    results: list[InterfaceInfo] = set()
    for i in output:
        state = i["operstate"]
        if state == "UNKNOWN":
            state = i["flags"][-2]
        addresses: set[str] = set()

        for addr in i["addr_info"]:
            intf_addr = f"{addr['local']}/{addr['prefixlen']}"
            test = ipaddress.ip_interface(intf_addr)
            if (
                isinstance(test, ipaddress.IPv6Interface)
                and test.is_link_local
                and intf_addr not in ("fe80::/64", "fe80::1/64")
            ):
                continue
            addresses.add(intf_addr)
        results.add((i["ifname"], state, frozenset(addresses)))

    return results


class TestInterfaces:
    """Test if the interfaces are configured correctly.

    Specifically interface state and configured IP addresses.
    """

    @pytest.mark.parametrize(
        ("host", "network_instance", "expected"),
        data_test_ip_settings_interfaces.TESTDATA_INTERFACES,
    )
    def test_interfaces(
        self,
        host: str,
        network_instance: str,
        expected: dict[str, list[InterfaceInfo]],
    ) -> None:
        """Tests interface settings for hub devices."""
        interfaces_external = get_interfaces(host, network_instance)

        assert interfaces_external == expected


Destination = str
NextHop = str | None
Device = str | None
Protocol = str | None

Route = tuple[Destination, NextHop, Device, Protocol]


def get_routes(
    host: str,
    netns: str,
) -> set[Route]:
    """Get routes including next-hop and via."""
    output_v4 = json.loads(
        conftest.run_cmd(host, f"ip --json --netns {netns} -4 route"),
    )
    output_v6 = json.loads(
        conftest.run_cmd(host, f"ip --json --netns {netns} -6 route"),
    )

    output = output_v4 + output_v6

    results: set[Route] = set()
    for route in output:
        if route.get("protocol") == "kernel":
            continue
        destination: str = route["dst"]
        gateway: str | None = route.get("gateway")
        device: str | None = route.get("dev")
        protocol: str | None = route.get("protocol")
        if (
            gateway
            and gateway.startswith("fe80:")
            and gateway not in ("fe80::", "fe80::1")
        ):
            gateway = None
        results.add(
            (
                destination,
                gateway,
                device,
                protocol,
            ),
        )

    return results


class TestRoutes:
    """Test if routes are configured correctly.

    Specifically next-hops, devices and protocols.
    """

    @pytest.mark.parametrize(
        ("host", "network_instance", "expected"),
        data_test_ip_settings_routes.TESTDATA_ROUTES,
    )
    def test_routes(
        self,
        host: str,
        network_instance: str,
        expected: dict[str, Any],
    ) -> None:
        """Tests routes for hub devices."""
        routes = get_routes(host, network_instance)

        assert routes == expected
