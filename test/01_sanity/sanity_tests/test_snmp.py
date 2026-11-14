"""SNMP shows the connections and the routes of the network instances."""

from __future__ import annotations

import ipaddress
import json

import pytest

from . import conftest
from .test_vpnctl import CONNECTIONS

IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
ROUTE_IF_INDEX = "1.3.6.1.2.1.10.166.11.1.4.1.1.7"

UP = "1"
HUB_NETWORK_INSTANCES = ["CORE", "EXTERNAL", "C0001-00", "C0001-01"]
NETWORK_INSTANCES = {
    "hub00": HUB_NETWORK_INSTANCES,
    "hub01": HUB_NETWORK_INSTANCES,
    "end00": ["CORE", "EXTERNAL", "ENDPOINT"],
    "end01": ["CORE", "EXTERNAL", "ENDPOINT"],
}

Route = tuple[str, str, str | None]


def kernel_routes(host: str, ni: str) -> dict[Route, str | None]:
    """Return the interface of every route of a network instance's main table."""
    routes: dict[Route, str | None] = {}
    for family in (4, 6):
        output = conftest.run_cmd(host, f"ip -j -n {ni} -{family} route")
        for route in json.loads(output):
            default = "0.0.0.0/0" if family == 4 else "::/0"  # noqa: PLR2004
            dst = default if route["dst"] == "default" else route["dst"]
            for hop in route.get("nexthops") or [route]:
                gateway = hop.get("gateway") or hop.get("via", {}).get("host")
                key = (ni, str(ipaddress.ip_network(dst)), gateway)
                routes[key] = hop.get("dev")
    return routes


class TestSnmp:
    """snmpd answers for the connections and routes, next to its own objects."""

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_connections(self, host: str) -> None:
        """Every connection is an interface that's up; snmpd's own stay."""

        def listed() -> bool:
            names = conftest.snmp_interfaces(host)
            status = conftest.snmp_walk(host, IF_OPER_STATUS)
            descriptions = conftest.snmp_walk(host, IF_DESCR).values()
            assert {"lo", "eth0"} <= set(descriptions)
            return all(
                status.get(names.get(connection, ())) == UP
                for connection in CONNECTIONS[host]
            )

        conftest.wait_until(listed, 90, message=f"the connections in SNMP on {host}")

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_own_interfaces(self, host: str) -> None:
        """What vpnc doesn't have still comes from snmpd, for its own interfaces."""
        names = conftest.snmp_interfaces(host)
        speeds = conftest.snmp_walk(host, IF_SPEED)

        assert names["eth0"] in speeds
        assert all(names[connection] not in speeds for connection in CONNECTIONS[host])

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_counters(self, host: str) -> None:
        """A connection with traffic counts it."""
        index = conftest.snmp_interfaces(host)["CORE-0"]

        assert int(conftest.snmp_walk(host, IF_HC_IN_OCTETS)[index]) > 0

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_routes(self, host: str) -> None:
        """The route table has the routes of every network instance."""

        def same() -> bool:
            expected: set[Route] = set()
            for ni in NETWORK_INSTANCES[host]:
                expected |= set(kernel_routes(host, ni))
            return conftest.snmp_routes(host) == expected

        conftest.wait_until(same, 90, message=f"the routes in SNMP on {host}")

    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_route_interface(self, host: str) -> None:
        """A route through a connection refers to the connection's interface."""
        ifname = CONNECTIONS[host]["C0001-00-0"][1]
        through = {
            route
            for route, dev in kernel_routes(host, "C0001-00").items()
            if dev == ifname
        }
        assert through

        def refers() -> bool:
            (index,) = conftest.snmp_interfaces(host)["C0001-00-0"]
            indexes = {
                conftest.snmp_route(route): value
                for route, value in conftest.snmp_walk(host, ROUTE_IF_INDEX).items()
            }
            return all(indexes.get(route) == str(index) for route in through)

        conftest.wait_until(refers, 90, message=f"the route interfaces on {host}")
