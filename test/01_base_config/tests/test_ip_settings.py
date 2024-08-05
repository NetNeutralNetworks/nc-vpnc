import ipaddress
import json
from typing import Any
import pytest
import subprocess


def run_cmd(host: str, command: str) -> str:
    """
    Runs a command in the docker container and returns the results
    """

    cmd = ["docker", "exec", f"clab-vpnc-{host}"]
    cmd.extend(command.split())

    output = subprocess.run(
        cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, check=True
    ).stdout.decode()

    return output


def run_cmd_vtysh(host: str, command: str) -> str:
    """
    Runs a command in the docker container and returns the results
    """

    cmd = ["docker", "exec", f"clab-vpnc-{host}", "vtysh", "-c", command]
    cmd.extend(command.split())

    output = subprocess.run(
        cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, check=True
    ).stdout.decode()

    return output


def get_interfaces(host: str, netns: str) -> dict[str, Any]:
    """
    Get interface status and IP addresses.
    """
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
    """
    Get routes including next-hop and via.
    """
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
            )
        )

    return results


class TestInterfaces:
    """
    Tests if the interfaces are configured correctly, specifically interface state and configured
    IP addresses.
    """

    intf_hub00 = (
        "hub00",
        {
            "UNTRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::5/64", "192.0.2.5/24"]),
                },
            },
            "TRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set(["fd00:1:2::/127"])},
                "xfrm1": {"state": "UP", "address": set(["fd00:1:2::1:0/127"])},
                "c0001-00_C": {"state": "UP", "address": set(["fe80::/64"])},
                "c0001-01_C": {"state": "UP", "address": set(["fe80::/64"])},
            },
            "c0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.99.0.1/28", "fdcc:cbe::/64"]),
                },
                "c0001-00_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
            "c0001-01": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.99.1.1/28", "fdcc:cbe:1::/64"]),
                },
                "c0001-01_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
        },
    )
    intf_hub01 = (
        "hub01",
        {
            "UNTRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::6/64", "192.0.2.6/24"]),
                },
            },
            "TRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set(["fd00:1:2::2/127"])},
                "xfrm1": {"state": "UP", "address": set(["fd00:1:2::1:2/127"])},
                "c0001-00_C": {"state": "UP", "address": set(["fe80::/64"])},
                "c0001-01_C": {"state": "UP", "address": set(["fe80::/64"])},
            },
            "c0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.100.0.1/28", "fdcc:cbf::/64"]),
                },
                "c0001-00_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
            "c0001-01": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {
                    "state": "UP",
                    "address": set(["100.100.1.1/28", "fdcc:cbf:1::/64"]),
                },
                "c0001-01_D": {"state": "UP", "address": set(["fe80::1/64"])},
            },
        },
    )
    testdata_interfaces_hub = [intf_hub00, intf_hub01]  # , ("hub01")]

    @pytest.mark.parametrize("host, expected", testdata_interfaces_hub)
    def test_interfaces_hub(self, host, expected: dict[str, Any]):
        """
        Tests interface settings for hub devices.
        """

        interfaces_external = get_interfaces(host, "UNTRUST")
        interfaces_core = get_interfaces(host, "TRUST")
        interfaces_c0001_00 = get_interfaces(host, "c0001-00")
        interfaces_c0001_01 = get_interfaces(host, "c0001-01")

        assert interfaces_external == expected["UNTRUST"]
        assert interfaces_core == expected["TRUST"]
        assert interfaces_c0001_00 == expected["c0001-00"]
        assert interfaces_c0001_01 == expected["c0001-01"]

    intf_end00 = (
        "end00",
        {
            "UNTRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::7/64", "192.0.2.7/24"]),
                },
            },
            "TRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set()},
                "xfrm1": {"state": "UP", "address": set()},
                "e0001-00_C": {
                    "state": "UP",
                    "address": set(["169.254.0.1/30", "fe80::/64"]),
                },
            },
            "e0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "eth2": {
                    "state": "UP",
                    "address": set(
                        [
                            "172.16.30.254/24",
                            "2001:db8:c57::ffff/64",
                            "fdff:db8:c57::ffff/64",
                        ]
                    ),
                },
                "e0001-00_D": {
                    "state": "UP",
                    "address": set(["169.254.0.2/30", "fe80::1/64"]),
                },
            },
        },
    )
    intf_end01 = (
        "end01",
        {
            "UNTRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "eth1": {
                    "state": "UP",
                    "address": set(["2001:db8::8/64", "192.0.2.8/24"]),
                },
            },
            "TRUST": {
                "lo": {"state": "DOWN", "address": set()},
                "xfrm0": {"state": "UP", "address": set()},
                "xfrm1": {"state": "UP", "address": set()},
                "e0001-00_C": {
                    "state": "UP",
                    "address": set(["169.254.0.1/30", "fe80::/64"]),
                },
            },
            "e0001-00": {
                "lo": {"state": "DOWN", "address": set()},
                "eth2": {
                    "state": "UP",
                    "address": set(
                        [
                            "172.16.31.254/24",
                            "2001:db8:c58::ffff/64",
                            "fdff:db8:c58::ffff/64",
                        ]
                    ),
                },
                "e0001-00_D": {
                    "state": "UP",
                    "address": set(["169.254.0.2/30", "fe80::1/64"]),
                },
            },
        },
    )
    testdata_interfaces_end = [intf_end00, intf_end01]  # , ("end01")]

    @pytest.mark.parametrize("host, expected", testdata_interfaces_end)
    def test_interfaces_end(self, host, expected: dict[str, Any]):
        """
        Tests interface settings for endpoint devices.
        """

        interfaces_external = get_interfaces(host, "UNTRUST")
        interfaces_core = get_interfaces(host, "TRUST")
        interfaces_e0001_00 = get_interfaces(host, "e0001-00")

        # print(interfaces_c0001_01)

        assert interfaces_external == expected["UNTRUST"]
        assert interfaces_core == expected["TRUST"]
        assert interfaces_e0001_00 == expected["e0001-00"]


class TestRoutes:
    """
    Tests if the routes are configured correctly, specifically next-hops, devices and protocols.
    """

    routes_hub00 = (
        "hub00",
        {
            "UNTRUST": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ]
            ),
            "TRUST": set(
                [
                    # Uplink route via BGP, preferred via xfrm0
                    ("fd00::/16", None, "xfrm0", "bgp"),
                    # routes for c0001-00
                    ("2001:db8:c57::/48", "fe80::1", "c0001-00_C", None),
                    ("fd6c:1::/48", "fe80::1", "c0001-00_C", None),
                    ("fdcc:0:c:1::/96", "fe80::1", "c0001-00_C", None),
                    # routes for c0001-01
                    ("2001:db8:c58::/48", "fe80::1", "c0001-01_C", None),
                    ("fd6c:1:1::/48", "fe80::1", "c0001-01_C", None),
                    ("fdcc:0:c:1:1::/96", "fe80::1", "c0001-01_C", None),
                ]
            ),
            "c0001-00": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "c0001-00_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c57::/48", None, "xfrm0", None),
                    ("fdff:db8:c57::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c57:3000::/52", None, "xfrm0", None),
                ]
            ),
            "c0001-01": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "c0001-01_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c58::/48", None, "xfrm0", None),
                    ("fdff:db8:c58::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c58:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:3000::/52", None, "xfrm0", None),
                ]
            ),
        },
    )
    routes_hub01 = (
        "hub01",
        {
            "UNTRUST": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ]
            ),
            "TRUST": set(
                [
                    # Uplink route via BGP, preferred via xfrm1
                    ("fd00::/16", None, "xfrm1", "bgp"),
                    # routes for c0001-00
                    ("2001:db8:c57::/48", "fe80::1", "c0001-00_C", None),
                    ("fd6c:1::/48", "fe80::1", "c0001-00_C", None),
                    ("fdcc:0:c:1::/96", "fe80::1", "c0001-00_C", None),
                    # routes for c0001-01
                    ("2001:db8:c58::/48", "fe80::1", "c0001-01_C", None),
                    ("fd6c:1:1::/48", "fe80::1", "c0001-01_C", None),
                    ("fdcc:0:c:1:1::/96", "fe80::1", "c0001-01_C", None),
                ]
            ),
            "c0001-00": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "c0001-00_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c57::/48", None, "xfrm0", None),
                    ("fdff:db8:c57::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c57:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c57:3000::/52", None, "xfrm0", None),
                ]
            ),
            "c0001-01": set(
                [
                    # Uplink to CORE
                    ("fd00::/16", "fe80::", "c0001-01_D", None),
                    # IPv4 routes
                    ("default", None, "xfrm0", None),
                    # IPv6 routes
                    ("2001:db8:c58::/48", None, "xfrm0", None),
                    ("fdff:db8:c58::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:2000::/56", None, "xfrm0", None),
                    ("fdff:db8:c58:1000::/52", None, "xfrm0", None),
                    ("fdff:db8:c58:3000::/52", None, "xfrm0", None),
                ]
            ),
        },
    )
    testdata_routes_hub = [routes_hub00, routes_hub01]

    @pytest.mark.parametrize("host, expected", testdata_routes_hub)
    def test_routes_hub(self, host, expected: dict[str, Any]):
        """
        Tests routes for hub devices.
        """

        routes_external = get_routes(host, "UNTRUST")
        routes_core = get_routes(host, "TRUST")
        routes_c0001_00 = get_routes(host, "c0001-00")
        routes_c0001_01 = get_routes(host, "c0001-01")

        assert routes_external == expected["UNTRUST"]
        assert routes_core == expected["TRUST"]
        assert routes_c0001_00 == expected["c0001-00"]
        assert routes_c0001_01 == expected["c0001-01"]

    routes_end00 = (
        "end00",
        {
            "UNTRUST": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ]
            ),
            "TRUST": set(
                [
                    # Uplink IPv4 routes
                    ("100.99.0.0/28", None, "xfrm0", None),
                    ("100.100.0.0/28", None, "xfrm1", None),
                    # Uplink IPv6 routes
                    ("fdcc:cbf::/64", None, "xfrm1", None),
                    ("fdcc:cbe::/64", None, "xfrm0", None),
                    # Downlink routes
                    ("default", "169.254.0.2", "e0001-00_C", None),
                    ("default", "fe80::1", "e0001-00_C", None),
                ]
            ),
            "e0001-00": set(
                [
                    # IPv4 uplink to CORE
                    ("100.99.0.0/28", "169.254.0.1", "e0001-00_D", None),
                    ("100.100.0.0/28", "169.254.0.1", "e0001-00_D", None),
                    # IPv6 uplink to CORE
                    ("fdcc:cbe::/64", "fe80::", "e0001-00_D", None),
                    ("fdcc:cbf::/64", "fe80::", "e0001-00_D", None),
                    # IPv4 routes
                    ("default", "172.16.30.1", "eth2", None),
                    # IPv6 routes
                    ("default", "fdff:db8:c57::1", "eth2", None),
                ]
            ),
        },
    )
    routes_end01 = (
        "end01",
        {
            "UNTRUST": set(
                [
                    ("default", "192.0.2.1", "eth1", None),
                    ("default", "2001:db8::1", "eth1", None),
                ]
            ),
            "TRUST": set(
                [
                    # Uplink IPv4 routes
                    ("100.99.1.0/28", None, "xfrm0", None),
                    ("100.100.1.0/28", None, "xfrm1", None),
                    # Uplink IPv6 routes
                    ("fdcc:cbf:1::/64", None, "xfrm1", None),
                    ("fdcc:cbe:1::/64", None, "xfrm0", None),
                    # Downlink routes
                    ("default", "169.254.0.2", "e0001-00_C", None),
                    ("default", "fe80::1", "e0001-00_C", None),
                ]
            ),
            "e0001-00": set(
                [
                    # IPv4 uplink to CORE
                    ("100.99.1.0/28", "169.254.0.1", "e0001-00_D", None),
                    ("100.100.1.0/28", "169.254.0.1", "e0001-00_D", None),
                    # IPv6 uplink to CORE
                    ("fdcc:cbe:1::/64", "fe80::", "e0001-00_D", None),
                    ("fdcc:cbf:1::/64", "fe80::", "e0001-00_D", None),
                    # IPv4 routes
                    ("default", "172.16.31.1", "eth2", None),
                    # IPv6 routes
                    ("default", "fdff:db8:c58::1", "eth2", None),
                ]
            ),
        },
    )
    testdata_routes_end = [routes_end00, routes_end01]

    @pytest.mark.parametrize("host, expected", testdata_routes_end)
    def test_routes_end(self, host, expected: dict[str, Any]):
        """
        Tests route settings for endpoint devices.
        """

        routes_external = get_routes(host, "UNTRUST")
        routes_core = get_routes(host, "TRUST")
        routes_e0001_00 = get_routes(host, "e0001-00")

        assert routes_external == expected["UNTRUST"]
        assert routes_core == expected["TRUST"]
        assert routes_e0001_00 == expected["e0001-00"]
