"""The firewall answers pings and peers' tunnel traffic; nothing else gets an answer."""

from __future__ import annotations

import subprocess

import pytest

from . import conftest

# The provider side: on the external network (in its EXTERNAL namespace) and at
# the other end of the hubs' tunnels.
PROVIDER = "mgt00"
EXTERNAL_NETNS = "ip netns exec EXTERNAL "
# (IPv4, IPv6) of the external interfaces.
EXTERNAL = {
    "hub00": ("192.0.2.5", "2001:db8::5"),
    "hub01": ("192.0.2.6", "2001:db8::6"),
    "end00": ("192.0.2.7", "2001:db8::7"),
    "end01": ("192.0.2.8", "2001:db8::8"),
}
# The hubs' addresses in CORE on their tunnels to mgt00.
CORE = {"hub00": "fd00:1:2::", "hub01": "fd00:1:2::2"}
# Per hub the management nodes' tunnel to it, and their addresses on it.
UPLINKS = {
    "hub00": ("xfrm0", "fd00:1:2::1", "fd00:1:2::1:1"),
    "hub01": ("xfrm1", "fd00:1:2::3", "fd00:1:2::1:3"),
}
# The client behind an endpoint, and the endpoint's address in its network.
ENDPOINT = {"end00": ("cli00", "172.16.30.254"), "end01": ("cli01", "172.17.30.254")}

# A customer's router (the SSH server): its ends of the hubs' SSH tunnels.
CUSTOMER = "cli00"
TUNNEL = {"hub00": "tun0", "hub01": "tun1"}
# The NAT64 prefix of its network instance (C0001-00), and a host in its network.
NAT64 = "fdcc:0:c:1::"
CUSTOMER_HOST = "172.16.30.1"
# Per hub the management node that goes through it, and the hub's address in
# the customer's network that its NAT64 uses for the SSH tunnel's routes.
MANAGEMENT = {"hub00": ("mgt00", "100.99.0.17"), "hub01": ("mgt01", "100.100.0.17")}
# Customer hosts behind the SSH tunnel: one that management pings, and another.
PINGED = "172.16.31.1"
NOT_CONTACTED = "172.16.31.4"

NETWORK_INSTANCES = [
    (host, network_instance)
    for host, network_instances in {
        "hub00": ("EXTERNAL", "CORE", "C0001-00", "C0001-01"),
        "hub01": ("EXTERNAL", "CORE", "C0001-00", "C0001-01"),
        "end00": ("EXTERNAL", "CORE", "ENDPOINT"),
        "end01": ("EXTERNAL", "CORE", "ENDPOINT"),
    }.items()
    for network_instance in network_instances
]

# What timeout exits with when the command didn't finish.
TIMED_OUT = 124


def pings(host: str, address: str, netns: str = "") -> bool:
    """Return whether an address answers a ping from a lab node."""
    try:
        conftest.run_cmd(host, f"{netns}ping -c 1 -W 2 {address}")
    except subprocess.CalledProcessError:
        return False
    return True


def tcp_unanswered(host: str, address: str, netns: str = "") -> bool:
    """Return whether a TCP connection from a lab node isn't answered or refused."""
    try:
        conftest.run_cmd_shell(
            host,
            f"{netns}timeout 3 bash -c '</dev/tcp/{address}/22'",
        )
    except subprocess.CalledProcessError as err:
        return err.returncode == TIMED_OUT
    return False


class TestFirewall:
    """Unsolicited traffic to a node is dropped."""

    @pytest.mark.parametrize("host", list(EXTERNAL))
    def test_external(self, host: str) -> None:
        """An external address answers IPv6 pings only."""
        ipv4, ipv6 = EXTERNAL[host]

        assert pings(PROVIDER, ipv6, EXTERNAL_NETNS)
        assert not pings(PROVIDER, ipv4, EXTERNAL_NETNS)
        assert tcp_unanswered(PROVIDER, ipv4, EXTERNAL_NETNS)
        assert tcp_unanswered(PROVIDER, ipv6, EXTERNAL_NETNS)

    @pytest.mark.parametrize("host", list(EXTERNAL))
    def test_ike_from_peers_only(self, host: str) -> None:
        """IKE is answered from IPsec peers only: mgt00 is the hubs' over IPv6."""
        ipv4, ipv6 = EXTERNAL[host]

        assert conftest.ike_answered(PROVIDER, "EXTERNAL", ipv6) == (host in CORE)
        assert not conftest.ike_answered(PROVIDER, "EXTERNAL", ipv4)

    @pytest.mark.parametrize("host", list(EXTERNAL))
    def test_router_advertisement_ignored(self, host: str) -> None:
        """A router advertisement on the external network adds no route."""
        conftest.advertise_router(PROVIDER, "EXTERNAL", "eth1")

        routes = conftest.run_cmd(
            host,
            "ip netns exec EXTERNAL ip -6 route show proto ra",
        )
        assert not routes.strip()

    @pytest.mark.parametrize("host", list(CORE))
    def test_core(self, host: str) -> None:
        """Over its tunnel a hub answers pings, next to BGP and BFD."""
        assert pings(PROVIDER, CORE[host])
        assert tcp_unanswered(PROVIDER, CORE[host])

    @pytest.mark.parametrize("host", list(UPLINKS))
    def test_no_transit_between_uplinks(self, host: str) -> None:
        """A hub doesn't route from one management node to the other."""
        tunnel, mgt00, mgt01 = UPLINKS[host]

        with (
            conftest.route("mgt00", f"{mgt01}/128 dev {tunnel}"),
            conftest.route("mgt01", f"{mgt00}/128 dev {tunnel}"),
        ):
            assert not pings("mgt00", mgt01)

    @pytest.mark.parametrize("host", list(ENDPOINT))
    def test_endpoint(self, host: str) -> None:
        """In its customer's network an endpoint answers pings only."""
        client, address = ENDPOINT[host]

        assert pings(client, address)
        assert tcp_unanswered(client, address)

    @pytest.mark.parametrize("host", list(TUNNEL))
    def test_nat64_from_management_only(self, host: str) -> None:
        """A customer can't use a hub's NAT64 to get back into its own network."""
        with conftest.route(CUSTOMER, f"{NAT64}/96 dev {TUNNEL[host]}"):
            assert not pings(CUSTOMER, f"{NAT64}{CUSTOMER_HOST}")

    @pytest.mark.parametrize("host", list(MANAGEMENT))
    def test_customer_cant_ping_management(self, host: str) -> None:
        """A customer host can't ping a management host, even one that pings it."""
        management, address = MANAGEMENT[host]

        assert pings(management, f"{NAT64}{PINGED}")
        for source in (PINGED, NOT_CONTACTED):
            assert not conftest.echo_sweep(CUSTOMER, source, address)

    @pytest.mark.parametrize(("host", "network_instance"), NETWORK_INSTANCES)
    def test_no_other_tables(self, host: str, network_instance: str) -> None:
        """Vpnc's table is the only one (e.g. none of its old iptables ones)."""
        tables = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} nft list tables",
        ).splitlines()

        expected = ["table inet vpnc"]
        if host.startswith("hub") and network_instance == "CORE":
            expected.append("table ip6 vpncmangle")
        assert sorted(tables) == expected
