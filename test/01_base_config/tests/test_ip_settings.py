import ipaddress
import json
import subprocess
from typing import Any

import pytest


def run_cmd(host: str, command: str) -> str:
    """Runs a command in the docker container and returns the results"""
    cmd = ["docker", "exec", f"clab-vpnc-{host}"]
    cmd.extend(command.split())

    output = subprocess.run(
        cmd,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.decode()

    return output


def run_cmd_vtysh(host: str, command: str) -> str:
    """Runs a command in the docker container and returns the results"""
    cmd = ["docker", "exec", f"clab-vpnc-{host}", "vtysh", "-c", command]
    cmd.extend(command.split())

    output = subprocess.run(
        cmd,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.decode()

    return output


def get_interfaces(host: str, netns: str) -> dict[str, Any]:
    """Get interface status and IP addresses."""
    output = json.loads(run_cmd(host, f"ip --json --netns {netns} address"))

    results: dict[str, Any] = {}
    for i in output:
        state = i["operstate"]
        if state == "UNKNOWN":
            state = i["flags"][-2]
        if_info: dict[str, Any] = {
            "state": state,
            "address": set(),
        }

        for addr in i["addr_info"]:
            intf_addr = f"{addr['local']}/{addr['prefixlen']}"
            test = ipaddress.ip_interface(intf_addr)
            if (
                isinstance(test, ipaddress.IPv6Interface)
                and test.is_link_local
                and intf_addr not in ["fe80::/64", "fe80::1/64"]
            ):
                continue
            if_info["address"].add(intf_addr)
        results[i["ifname"]] = if_info

    return results


def get_routes(host: str, netns: str) -> set[tuple[str, str | None, str | None]]:
    """Get routes including next-hop and via."""
    output_v4 = json.loads(run_cmd(host, f"ip --json --netns {netns} -4 route"))
    output_v6 = json.loads(run_cmd(host, f"ip --json --netns {netns} -6 route"))

    output = output_v4 + output_v6

    results: set[tuple[str, str | None, str | None]] = set()
    for route in output:
        if route.get("protocol") == "kernel":
            continue
        gateway = route.get("gateway")
        if (
            gateway
            and gateway.startswith("fe80:")
            and gateway not in ["fe80::", "fe80::1"]
        ):
            gateway = None
        results.add(
            (
                route["dst"],
                gateway,
                route.get("dev"),
                route.get("protocol"),
            ),
        )

    return results


class TestInterfaces:
    """Tests if the interfaces are configured correctly, specifically interface state and configured
    IP addresses.
    """

    intf_hub00 = (
        "hub00",
        {
            "EXTERNAL": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::5/64", "192.0.2.5/24"]),
                },
            },
            "CORE": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set(["fd00:1:2::/127"])},
                "xfrm1": {"state": "UP", "address": set(["fd00:1:2::1:0/127"])},
                "C0001-00_C": {"state": "UP", "address": set(["fe80::/64"])},
                "C0001-01_C": {"state": "UP", "address": set(["fe80::/64"])},
            },
            "C0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.99.0.1/28", "fdcc:cbe::/64"]),
                },
                "C0001-00_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
            "C0001-01": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.99.1.1/28", "fdcc:cbe:1::/64"]),
                },
                "C0001-01_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
        },
    )
    intf_hub01 = (
        "hub01",
        {
            "EXTERNAL": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::6/64", "192.0.2.6/24"]),
                },
            },
            "CORE": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set(["fd00:1:2::2/127"])},
                "xfrm1": {"state": "UP", "address": set(["fd00:1:2::1:2/127"])},
                "C0001-00_C": {"state": "UP", "address": set(["fe80::/64"])},
                "C0001-01_C": {"state": "UP", "address": set(["fe80::/64"])},
            },
            "C0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.100.0.1/28", "fdcc:cbf::/64"]),
                },
                "C0001-00_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
            "C0001-01": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.100.1.1/28", "fdcc:cbf:1::/64"]),
                },
                "C0001-01_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
        },
    )
    testdata_interfaces_hub = [intf_hub00, intf_hub01]  # , ("hub01")]

    @pytest.mark.parametrize("host, expected", testdata_interfaces_hub)
    def test_interfaces_hub(self, host, expected: dict[str, Any]):
        """Tests interface settings for hub devices."""
        interfaces_external = get_interfaces(host, "EXTERNAL")
        interfaces_core = get_interfaces(host, "CORE")
        interfaces_C0001_00 = get_interfaces(host, "C0001-00")
        interfaces_C0001_01 = get_interfaces(host, "C0001-01")

        assert interfaces_external == expected["EXTERNAL"]
        assert interfaces_core == expected["CORE"]
        assert interfaces_C0001_00 == expected["C0001-00"]
        assert interfaces_C0001_01 == expected["C0001-01"]

    intf_end00 = (
        "end00",
        {
            "EXTERNAL": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::7/64", "192.0.2.7/24"]),
                },
            },
            "CORE": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set()},
                "xfrm1": {"state": "UP", "address": set()},
                "E0001-00_C": {
                    "state": "UP",
                    "address": set(["169.254.0.1/30", "fe80::/64"]),
                },
            },
            "E0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "eth2": {
                    "state": "UP",
                    "address": set(
                        [
                            "172.16.30.254/24",
                            "2001:db8:c57::ffff/64",
                            "fdff:db8:c57::ffff/64",
                        ],
                    ),
                },
                "E0001-00_D": {
                    "state": "UP",
                    "address": set(["169.254.0.2/30", "fe80::1/64"]),
                },
            },
        },
    )
    intf_end01 = (
        "end01",
        {
            "EXTERNAL": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::8/64", "192.0.2.8/24"]),
                },
            },
            "CORE": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set()},
                "xfrm1": {"state": "UP", "address": set()},
                "E0001-00_C": {
                    "state": "UP",
                    "address": set(["169.254.0.1/30", "fe80::/64"]),
                },
            },
            "E0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "eth2": {
                    "state": "UP",
                    "address": set(
                        [
                            "172.17.30.254/24",
                            "2001:db8:c58::ffff/64",
                            "fdff:db8:c58::ffff/64",
                        ],
                    ),
                },
                "E0001-00_D": {
                    "state": "UP",
                    "address": set(["169.254.0.2/30", "fe80::1/64"]),
                },
            },
        },
    )
    testdata_interfaces_end = [intf_end00, intf_end01]  # , ("end01")]

    @pytest.mark.parametrize("host, expected", testdata_interfaces_end)
    def test_interfaces_end(self, host, expected: dict[str, Any]):
        """Tests interface settings for endpoint devices."""
        interfaces_external = get_interfaces(host, "EXTERNAL")
        interfaces_core = get_interfaces(host, "CORE")
        interfaces_E0001_00 = get_interfaces(host, "E0001-00")

        # print(interfaces_C0001_01)

        assert interfaces_external == expected["EXTERNAL"]
        assert interfaces_core == expected["CORE"]
        assert interfaces_E0001_00 == expected["E0001-00"]


class TestRoutes:
    """Tests if the routes are configured correctly, specifically next-hops, devices and protocols."""

    routes_hub00 = (
        "hub00",
        {
            "EXTERNAL": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ],
            ),
            "CORE": set(
                [
                    # Uplink route via BGP, preferred via xfrm0
                    ("fd00::/16", None, "xfrm0", "bgp"),
                    # routes for C0001-00
                    ("2001:db8:c57::/48", "fe80::1", "C0001-00_C", None),
                    ("fd6c:1::/48", "fe80::1", "C0001-00_C", None),
                    ("fdcc:0:c:1::/96", "fe80::1", "C0001-00_C", None),
                    # routes for C0001-01
                    ("2001:db8:c58::/48", "fe80::1", "C0001-01_C", None),
                    ("fd6c:1:1::/48", "fe80::1", "C0001-01_C", None),
                    ("fdcc:0:c:1:1::/96", "fe80::1", "C0001-01_C", None),
                ],
            ),
            "C0001-00": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "C0001-00_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c57::/48", None, "xfrm0", None),
                    ("fdff:db8:c57::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c57:3000::/52", None, "xfrm0", None),
                ],
            ),
            "C0001-01": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "C0001-01_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c58::/48", None, "xfrm0", None),
                    ("fdff:db8:c58::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c58:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:3000::/52", None, "xfrm0", None),
                ],
            ),
        },
    )
    routes_hub01 = (
        "hub01",
        {
            "EXTERNAL": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ],
            ),
            "CORE": set(
                [
                    # Uplink route via BGP, preferred via xfrm1
                    ("fd00::/16", None, "xfrm1", "bgp"),
                    # routes for C0001-00
                    ("2001:db8:c57::/48", "fe80::1", "C0001-00_C", None),
                    ("fd6c:1::/48", "fe80::1", "C0001-00_C", None),
                    ("fdcc:0:c:1::/96", "fe80::1", "C0001-00_C", None),
                    # routes for C0001-01
                    ("2001:db8:c58::/48", "fe80::1", "C0001-01_C", None),
                    ("fd6c:1:1::/48", "fe80::1", "C0001-01_C", None),
                    ("fdcc:0:c:1:1::/96", "fe80::1", "C0001-01_C", None),
                ],
            ),
            "C0001-00": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "C0001-00_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c57::/48", None, "xfrm0", None),
                    ("fdff:db8:c57::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c57:3000::/52", None, "xfrm0", None),
                ],
            ),
            "C0001-01": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "C0001-01_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c58::/48", None, "xfrm0", None),
                    ("fdff:db8:c58::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c58:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:3000::/52", None, "xfrm0", None),
                ],
            ),
        },
    )
    testdata_routes_hub = [routes_hub00, routes_hub01]

    @pytest.mark.parametrize("host, expected", testdata_routes_hub)
    def test_routes_hub(self, host, expected: dict[str, Any]):
        """Tests routes for hub devices."""
        routes_external = get_routes(host, "EXTERNAL")
        routes_core = get_routes(host, "CORE")
        routes_C0001_00 = get_routes(host, "C0001-00")
        routes_C0001_01 = get_routes(host, "C0001-01")

        assert routes_external == expected["EXTERNAL"]
        assert routes_core == expected["CORE"]
        assert routes_C0001_00 == expected["C0001-00"]
        assert routes_C0001_01 == expected["C0001-01"]

    routes_end00 = (
        "end00",
        {
            "EXTERNAL": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ],
            ),
            "CORE": set(
                [
                    # Uplink IPv4 routes
                    ("100.99.0.0/28", None, "xfrm0", None),
                    ("100.100.0.0/28", None, "xfrm1", None),
                    # Uplink IPv6 routes
                    ("fdcc:cbf::/64", None, "xfrm1", None),
                    ("fdcc:cbe::/64", None, "xfrm0", None),
                    # Downlink routes
                    ("default", "169.254.0.2", "E0001-00_C", None),
                    ("default", "fe80::1", "E0001-00_C", None),
                ],
            ),
            "E0001-00": set(
                [
                    # IPv4 uplink to CORE
                    ("100.99.0.0/28", "169.254.0.1", "E0001-00_D", None),
                    ("100.100.0.0/28", "169.254.0.1", "E0001-00_D", None),
                    # IPv6 uplink to CORE
                    ("fdcc:cbe::/64", "fe80::", "E0001-00_D", None),
                    ("fdcc:cbf::/64", "fe80::", "E0001-00_D", None),
                    # IPv4 routes
                    ("default", "172.16.30.1", "eth2", None),
                    # IPv6 routes
                    ("default", "fdff:db8:c57::1", "eth2", None),
                ],
            ),
        },
    )
    routes_end01 = (
        "end01",
        {
            "EXTERNAL": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ],
            ),
            "CORE": set(
                [
                    # Uplink IPv4 routes
                    ("100.99.1.0/28", None, "xfrm0", None),
                    ("100.100.1.0/28", None, "xfrm1", None),
                    # Uplink IPv6 routes
                    ("fdcc:cbf:1::/64", None, "xfrm1", None),
                    ("fdcc:cbe:1::/64", None, "xfrm0", None),
                    # Downlink routes
                    ("default", "169.254.0.2", "E0001-00_C", None),
                    ("default", "fe80::1", "E0001-00_C", None),
                ],
            ),
            "E0001-00": set(
                [
                    # IPv4 uplink to CORE
                    ("100.99.1.0/28", "169.254.0.1", "E0001-00_D", None),
                    ("100.100.1.0/28", "169.254.0.1", "E0001-00_D", None),
                    # IPv6 uplink to CORE
                    ("fdcc:cbe:1::/64", "fe80::", "E0001-00_D", None),
                    ("fdcc:cbf:1::/64", "fe80::", "E0001-00_D", None),
                    # IPv4 routes
                    ("default", "172.17.30.1", "eth2", None),
                    # IPv6 routes
                    ("default", "fdff:db8:c58::1", "eth2", None),
                ],
            ),
        },
    )
    testdata_routes_end = [routes_end00, routes_end01]

    @pytest.mark.parametrize("host, expected", testdata_routes_end)
    def test_routes_end(self, host, expected: dict[str, Any]):
        """Tests route settings for endpoint devices."""
        routes_external = get_routes(host, "EXTERNAL")
        routes_core = get_routes(host, "CORE")
        routes_E0001_00 = get_routes(host, "E0001-00")

        assert routes_external == expected["EXTERNAL"]
        assert routes_core == expected["CORE"]
        assert routes_E0001_00 == expected["E0001-00"]
