import re
import subprocess
from typing import Any

import pytest


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


class TestVpncmangle:
    """
    Tests if the vpncmangle process is running
    """

    # @pytest.mark.parametrize("tables", [tables6_mangle_hub])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_vpncmangle_is_running_hub(self, host):
        """
        Tests if vpncmangle correctly adds the ip6table rule
        """

        running = run_cmd(host, "pgrep --list-name vpncmangle")

        assert re.match(r"^\d+ vpncmangle$", running)

    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_vpncmangle_is_not_running_endpoint(self, host):
        """
        Tests if vpncmangle correctly adds the ip6table rule
        """

        with pytest.raises(subprocess.CalledProcessError):
            x = run_cmd(host, "pgrep --list-name vpncmangle")


class TestIPTablesMangle:
    """
    Tests if netfilter is set up correctly to forward traffic to vpncmangle.
    """

    tables6_mangle_hub = {
        # Perform NPTv6 before doing the masquerade. The masquerade always has to be at the end.
        "ipv6_core_hub": (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P FORWARD ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
            "-A POSTROUTING -p udp -m udp --sport 53 -j NFQUEUE --queue-num 0\n"
        ),
    }

    @pytest.mark.parametrize("tables", [tables6_mangle_hub])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ip6tables_mangle_hub(self, host, tables: dict[str, Any]):
        """
        Tests if vpncmangle correctly adds the ip6table rule
        """

        ip6tables = run_cmd(host, "ip netns exec TRUST ip6tables -t mangle -S")

        assert ip6tables == tables["ipv6_core_hub"]

    tables6_mangle_endpoint = {
        # Perform NPTv6 before doing the masquerade. The masquerade always has to be at the end.
        "ipv6_core_endpoint": (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P FORWARD ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
        ),
    }

    @pytest.mark.parametrize("tables", [tables6_mangle_endpoint])
    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_ip6tables_mangle_disabled_endpoints(self, host, tables: dict[str, Any]):
        """
        Tests if vpncmangle correctly adds the ip6table rule
        """

        ip6tables = run_cmd(host, "ip netns exec TRUST ip6tables -t mangle -S")

        assert ip6tables == tables["ipv6_core_endpoint"]


class TestDNSMangle:
    """
    Tests DNS queries are doctored correctly.
    """

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_with_v4_only_responses(self, host):
        """
        Tests if vpncmangle doctors v4 only responses
        """

        example_00_v4 = run_cmd(
            host, "dig +short v4lonly.example.com @fdcc:0:c:1::172.16.31.1"
        )
        example_01_v4 = run_cmd(
            host, "dig +short v4lonly.example.com @fdcc:0:c:1:1::172.17.31.1"
        )

        assert example_00_v4.strip() == "fdcc:0:c:1::ac10:1f04"
        assert example_01_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f04"

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_with_v64_mixed_responses(self, host):
        """
        Tests if vpncmangle doctors v4 and v6 mixed responses
        """

        example_00_v4 = run_cmd(
            host, "dig +short v64l.example.com @fdcc:0:c:1::172.16.31.1"
        )
        example_01_v4 = run_cmd(
            host, "dig +short v64l.example.com @fdcc:0:c:1:1::172.17.31.1"
        )

        assert example_00_v4.strip() == "fdcc:0:c:1::ac10:1f40"
        assert example_01_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f40"

    # TODO: Anything not NAT64 is broken (NPTv6 and directly reachable v6 DNS servers)

    # @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    # def test_dns_query_v4_only(self, host):
    #     """
    #     Tests if vpncmangle correctly adds the ip6table rule
    #     """

    #     example_00_v4 = run_cmd(host, "dig +short example.com @fdcc:0:c:1::172.16.31.1")
    #     example_00_v6 = run_cmd(host, "dig +short example.com @fd6c:1:0:31::1")
    #     example_01_v4 = run_cmd(
    #         host, "dig +short example.com @fdcc:0:c:1:1::172.17.31.1"
    #     )
    #     example_01_v6 = run_cmd(host, "dig +short example.com @fd6c:1:1:31::1")

    #     assert example_00_v4.strip() == "fdcc:0:c:1::ac10:1f01"
    #     assert example_00_v6.strip() == "fdcc:0:c:1::ac10:1f01"
    #     assert example_01_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f01"
    #     assert example_01_v6.strip() == "fdcc:0:c:1:1:0:ac11:1f01"
