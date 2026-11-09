"""Recovery of XFRM interfaces, IPsec and BGP after tunnel failures.

These tests disrupt the running lab. Each test waits until the lab has recovered
before it finishes, so the tests that run after them see a healthy lab.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
from typing import TYPE_CHECKING

import pytest

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

# XFRM interfaces that carry global addresses, with the addresses they must keep.
# The CORE ones hold the BGP peering addresses towards mgt00/mgt01.
XFRM_ADDRESSES = {
    ("hub00", "CORE", "xfrm0"): frozenset({"fd00:1:2::/127"}),
    ("hub00", "CORE", "xfrm1"): frozenset({"fd00:1:2::1:0/127"}),
    ("hub00", "C0001-00", "xfrm0"): frozenset({"100.99.0.1/28", "fdcc:cbe::/64"}),
    ("hub01", "CORE", "xfrm0"): frozenset({"fd00:1:2::2/127"}),
    ("hub01", "CORE", "xfrm1"): frozenset({"fd00:1:2::1:2/127"}),
    ("hub01", "C0001-00", "xfrm0"): frozenset({"100.100.0.1/28", "fdcc:cbf::/64"}),
}

# IKE SA to terminate, and the XFRM interface it is bound to.
IKE_SAS = [
    ("hub00", "CORE", "CORE-0", "xfrm0"),
    ("hub01", "CORE", "CORE-1", "xfrm1"),
    ("hub00", "C0001-00", "C0001-00-0", "xfrm0"),
    ("hub01", "C0001-00", "C0001-00-0", "xfrm0"),
]

SA_RECOVERY_TIMEOUT = 120
BGP_RECOVERY_TIMEOUT = 150


def get_link(host: str, netns: str, ifname: str) -> dict:
    """Return 'ip address' JSON output for a single interface."""
    output = json.loads(
        conftest.run_cmd(host, f"ip --json --netns {netns} address show dev {ifname}"),
    )
    return output[0]


def is_admin_up(host: str, netns: str, ifname: str) -> bool:
    """Return whether the interface is administratively up."""
    return "UP" in get_link(host, netns, ifname)["flags"]


def global_addresses(host: str, netns: str, ifname: str) -> frozenset[str]:
    """Return the non-link-local addresses of an interface."""
    return frozenset(
        f"{addr['local']}/{addr['prefixlen']}"
        for addr in get_link(host, netns, ifname)["addr_info"]
        if not ipaddress.ip_interface(addr["local"]).is_link_local
    )


def connected_prefixes(host: str, netns: str, ifname: str) -> set[str]:
    """Return destinations of kernel (connected) routes via an interface."""
    routes: set[str] = set()
    for family in ("-4", "-6"):
        output = json.loads(
            conftest.run_cmd(
                host,
                f"ip --json --netns {netns} {family} route show"
                f" dev {ifname} proto kernel",
            ),
        )
        routes.update(route["dst"] for route in output)
    return routes


def expected_prefixes(addresses: frozenset[str]) -> set[str]:
    """Return the connected prefixes the kernel adds for a set of addresses."""
    return {str(ipaddress.ip_interface(addr).network) for addr in addresses}


def sa_installed(host: str, ike: str) -> bool:
    """Return whether the IKE SA is established with an installed child SA."""
    output = conftest.run_cmd_shell(host, f"swanctl --list-sas --ike {ike} || true")
    return "ESTABLISHED" in output and "INSTALLED" in output


def bgp_all_established(host: str) -> dict[str, str]:
    """Return the CORE BGP peer states if all are established, else an empty dict."""
    output = json.loads(
        conftest.run_cmd_vtysh(host, "show bgp vrf CORE summary json"),
    )
    states = {
        peer: data["state"] for peer, data in output["ipv6Unicast"]["peers"].items()
    }
    if states and all(state == "Established" for state in states.values()):
        return states
    return {}


def assert_interface_recovered(host: str, netns: str, ifname: str) -> None:
    """Check addresses, connected routes and (for CORE) BGP after recovery."""
    expected = XFRM_ADDRESSES[(host, netns, ifname)]
    assert global_addresses(host, netns, ifname) == expected
    conftest.wait_until(
        lambda: expected_prefixes(expected) <= connected_prefixes(host, netns, ifname),
        timeout=10,
        message=f"connected routes on {host} {netns} {ifname}",
    )
    if netns == "CORE":
        conftest.wait_until(
            lambda: bgp_all_established(host),
            timeout=BGP_RECOVERY_TIMEOUT,
            message=f"BGP on {host} to re-establish",
        )


IKE_BLOCK_RULE = "INPUT -p udp -m multiport --dports 500,4500 -j DROP"


@contextlib.contextmanager
def ike_blocked(host: str) -> Iterator[None]:
    """Drop incoming IKE (and NAT-T) on the host's EXTERNAL network instance.

    Stops either side from re-establishing an SA, like an ISP outage does.
    If a run is interrupted and the rule stays behind, remove it with
    'ip netns exec EXTERNAL ip(6)tables -D <IKE_BLOCK_RULE>'.
    """
    for iptables in ("iptables", "ip6tables"):
        conftest.run_cmd(host, f"ip netns exec EXTERNAL {iptables} -I {IKE_BLOCK_RULE}")
    try:
        yield
    finally:
        for iptables in ("iptables", "ip6tables"):
            conftest.run_cmd_shell(
                host,
                f"ip netns exec EXTERNAL {iptables} -D {IKE_BLOCK_RULE} || true",
            )


class TestXfrmInterfaceDownUp:
    """Setting an XFRM interface down and up must not lose addresses.

    This is what the strongSwan monitor does when an IPsec SA goes away and
    comes back.
    """

    @pytest.mark.parametrize(("host", "netns", "ifname"), list(XFRM_ADDRESSES))
    def test_down_up_keeps_addresses(self, host: str, netns: str, ifname: str) -> None:
        """Addresses and connected routes survive an administrative down/up."""
        expected = XFRM_ADDRESSES[(host, netns, ifname)]
        assert global_addresses(host, netns, ifname) == expected

        try:
            conftest.run_cmd(host, f"ip --netns {netns} link set dev {ifname} down")
            assert global_addresses(host, netns, ifname) == expected
        finally:
            conftest.run_cmd(host, f"ip --netns {netns} link set dev {ifname} up")

        assert_interface_recovered(host, netns, ifname)


class TestIkeSaRecovery:
    """After an IPsec SA is torn down and re-established, everything recovers.

    Simulates the tunnel side of an ISP outage: IKE is blocked and the SA is torn
    down, so the monitor sets the XFRM interface down. Once IKE is unblocked and
    the SA is back, the interface must come up with its addresses so that BGP can
    re-establish.
    """

    @pytest.mark.parametrize(("host", "netns", "ike", "ifname"), IKE_SAS)
    def test_sa_terminate_recovers(
        self,
        host: str,
        netns: str,
        ike: str,
        ifname: str,
    ) -> None:
        """The XFRM interface comes back up with its addresses, and BGP recovers."""
        assert sa_installed(host, ike), f"{ike} on {host} isn't up before the test"

        with ike_blocked(host):
            # --force: don't wait for the peer to confirm the DELETE, which can't
            # arrive while IKE is blocked.
            conftest.run_cmd_shell(
                host,
                f"swanctl --terminate --ike {ike} --force > /dev/null 2>&1 || true",
            )
            # Ensure the down/up path is exercised.
            conftest.wait_until(
                lambda: not is_admin_up(host, netns, ifname),
                timeout=30,
                message=f"{host} {netns} {ifname} to go down",
            )

        conftest.wait_until(
            lambda: sa_installed(host, ike) and is_admin_up(host, netns, ifname),
            timeout=SA_RECOVERY_TIMEOUT,
            message=f"{ike} on {host} to re-establish and {ifname} to come up",
        )
        assert_interface_recovered(host, netns, ifname)
