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


class TestIPTables:
    """Tests if IPv4 firewall rules are configured correctly."""

    tables4 = {
        # By default no IPv4 in external, except for IPSec
        "ipv4_external": (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
        ),
        # No IPv4 in CORE
        "ipv4_core": ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n"),
        # No IPv4 in C0001-00, even though we do NAT64. These are handled by Jool before iptables
        # forwards traffic
        "ipv4_C0001_xx": ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n"),
    }

    @pytest.mark.parametrize("tables", [tables4])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_iptables_hub(self, host, tables: dict[str, Any]):
        """Tests firewall rules for the hubs"""
        iptables_external = run_cmd(
            host,
            "ip netns exec EXTERNAL /usr/sbin/iptables -S",
        )
        iptables_core = run_cmd(host, "ip netns exec CORE /usr/sbin/iptables -S")
        iptables_C0001_00 = run_cmd(
            host,
            "ip netns exec C0001-00 /usr/sbin/iptables -S",
        )
        iptables_C0001_01 = run_cmd(
            host,
            "ip netns exec C0001-01 /usr/sbin/iptables -S",
        )

        assert iptables_external == tables["ipv4_external"]
        assert iptables_core == tables["ipv4_core"]
        assert iptables_C0001_00 == tables["ipv4_C0001_xx"]
        assert iptables_C0001_01 == tables["ipv4_C0001_xx"]

    tables6_icmpv6_in_out = (
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 4 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 131 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 132 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j ACCEPT\n"
        "-A icmpv6-in-out -p ipv6-icmp -j DROP\n"
    )

    tables6 = {
        # By default no IPv6 in external, except for IPSec AND the required and recommended ICMPv6
        # according to https://www.rfc-editor.org/rfc/rfc4890
        "ipv6_external": (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            # Filter ICMPv6
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            # Allow IPSec
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            f"{tables6_icmpv6_in_out}"
        ),
        # Allow traffic input/output to/from the uplink, as well as related return traffic.
        "ipv6_core": (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT ACCEPT\n"
            "-N icmpv6-forward\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i xfrm0 -j ACCEPT\n"
            "-A INPUT -i xfrm1 -j ACCEPT\n"
            "-A FORWARD -j icmpv6-forward\n"
            "-A FORWARD -i xfrm0 -j ACCEPT\n"
            "-A FORWARD -i xfrm1 -j ACCEPT\n"
            "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 4 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -j DROP\n"
            f"{tables6_icmpv6_in_out}"
        ),
        # No IPv6 in C0001-xx, except for traffic from the veth uplink and related traffic.
        "ipv6_C0001_00": (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A FORWARD -i C0001-00_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            f"{tables6_icmpv6_in_out}"
        ),
        "ipv6_C0001_01": (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A FORWARD -i C0001-01_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            f"{tables6_icmpv6_in_out}"
        ),
    }

    @pytest.mark.parametrize("tables", [tables6])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ip6tables_hub(self, host, tables: dict[str, Any]):
        """Tests IPv6 firewall rules for the hubs"""
        ip6tables_external = run_cmd(host, "ip netns exec EXTERNAL ip6tables -S")
        ip6tables_core = run_cmd(host, "ip netns exec CORE ip6tables -S")
        ip6tables_C0001_00 = run_cmd(host, "ip netns exec C0001-00 ip6tables -S")
        ip6tables_C0001_01 = run_cmd(host, "ip netns exec C0001-01 ip6tables -S")

        assert ip6tables_external == tables["ipv6_external"]
        assert ip6tables_core == tables["ipv6_core"]
        assert ip6tables_C0001_00 == tables["ipv6_C0001_00"]
        assert ip6tables_C0001_01 == tables["ipv6_C0001_01"]


class TestIPTablesNAT:
    """Tests if NAT/NPTv6 rules have been configured correctly"""

    tables6 = {
        # Perform NPTv6 before doing the masquerade. The masquerade always has to be at the end.
        "ipv6_C0001_00": (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
            "-A PREROUTING -d fd6c:1::/52 -i C0001-00_D -j NETMAP --to fdff:db8:c57::/52\n"
            "-A PREROUTING -d fd6c:1:0:1000::/52 -i C0001-00_D -j NETMAP --to fdff:db8:c57:1000::/52\n"
            "-A PREROUTING -d fd6c:1:0:2000::/56 -i C0001-00_D -j NETMAP --to fdff:db8:c57:2000::/56\n"
            "-A PREROUTING -d fd6c:1:0:3000::/52 -i C0001-00_D -j NETMAP --to fdff:db8:c57:3000::/52\n"
            "-A POSTROUTING -o xfrm0 -j MASQUERADE\n"
        ),
        "ipv6_C0001_01": (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
            "-A PREROUTING -d fd6c:1:1::/52 -i C0001-01_D -j NETMAP --to fdff:db8:c58::/52\n"
            "-A PREROUTING -d fd6c:1:1:1000::/52 -i C0001-01_D -j NETMAP --to fdff:db8:c58:1000::/52\n"
            "-A PREROUTING -d fd6c:1:1:2000::/56 -i C0001-01_D -j NETMAP --to fdff:db8:c58:2000::/56\n"
            "-A PREROUTING -d fd6c:1:1:3000::/52 -i C0001-01_D -j NETMAP --to fdff:db8:c58:3000::/52\n"
            "-A POSTROUTING -o xfrm0 -j MASQUERADE\n"
        ),
    }

    @pytest.mark.parametrize("tables", [tables6])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ip6tables_nat_hub(self, host, tables: dict[str, Any]):
        """Tests IPv6 NAT rules for the hub"""
        ip6tables_C0001_00 = run_cmd(host, "ip netns exec C0001-00 ip6tables -t nat -S")
        ip6tables_C0001_01 = run_cmd(host, "ip netns exec C0001-01 ip6tables -t nat -S")

        assert ip6tables_C0001_00 == tables["ipv6_C0001_00"]
        assert ip6tables_C0001_01 == tables["ipv6_C0001_01"]
        # The masquerade always has to be at the end.
        assert (
            ip6tables_C0001_00.split("\n")[-2]
            == "-A POSTROUTING -o xfrm0 -j MASQUERADE"
        )
        assert (
            ip6tables_C0001_01.split("\n")[-2]
            == "-A POSTROUTING -o xfrm0 -j MASQUERADE"
        )
