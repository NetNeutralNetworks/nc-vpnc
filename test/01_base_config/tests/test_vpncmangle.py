import re
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


class TestVpncmangle:
    """Tests if the vpncmangle process is running"""

    # @pytest.mark.parametrize("tables", [tables6_mangle_hub])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_vpncmangle_is_running_hub(self, host):
        """Tests if vpncmangle correctly adds the ip6table rule"""
        running = run_cmd(host, "pgrep --list-name vpncmangle")

        assert re.match(r"^\d+ vpncmangle$", running)

    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_vpncmangle_is_not_running_endpoint(self, host):
        """Tests if vpncmangle correctly adds the ip6table rule"""
        with pytest.raises(subprocess.CalledProcessError):
            x = run_cmd(host, "pgrep --list-name vpncmangle")


class TestIPTablesMangle:
    """Tests if netfilter is set up correctly to forward traffic to vpncmangle."""

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
        """Tests if vpncmangle correctly adds the ip6table rule"""
        ip6tables = run_cmd(host, "ip netns exec CORE ip6tables -t mangle -S")

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
        """Tests if vpncmangle correctly adds the ip6table rule"""
        ip6tables = run_cmd(host, "ip netns exec CORE ip6tables -t mangle -S")

        assert ip6tables == tables["ipv6_core_endpoint"]


class TestDNSMangle:
    """Tests DNS queries are doctored correctly."""

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_a_only_record_a_responses(self, host):
        """Tests if vpncmangle doctors v4 only responses"""
        example_00_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com @fdcc:0:c:1::172.16.31.1",
        )
        example_01_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com @fdcc:0:c:1:1::172.17.31.1",
        )
        example_02_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com @2001:db8:c57:31::1",
        )
        example_03_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com @2001:db8:c58:31::1",
        )
        example_04_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com @fd6c:1:0:31::1",
        )
        example_05_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com @fd6c:1:1:31::1",
        )

        assert example_00_v4.strip() == "fdcc:0:c:1::ac10:1f04"
        assert example_01_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f04"
        assert example_02_v4.strip() == "fdcc:0:c:1::ac10:1f04"
        assert example_03_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f04"
        assert example_04_v4.strip() == "fdcc:0:c:1::ac10:1f04"
        assert example_05_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f04"

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_a_only_record_fail_aaaa_responses(self, host):
        """Tests if vpncmangle responds with no answer if AAAA record doesn't exist"""
        example_00_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com AAAA @fdcc:0:c:1::172.16.31.1",
        )
        example_01_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v4lonly.example.com AAAA @fdcc:0:c:1:1::172.17.31.1",
        )
        # example_02_v4 = run_cmd(
        #     host, "dig +short +time=1 +tries=1 v4lonly.example.com @2001:db8:c57:31::1"
        # )
        # example_03_v4 = run_cmd(
        #     host, "dig +short +time=1 +tries=1 v4lonly.example.com @2001:db8:c58:31::1"
        # )
        # example_04_v4 = run_cmd(host, "dig +short +time=1 +tries=1 v4lonly.example.com @fd6c:1:0:31::1")
        # example_05_v4 = run_cmd(host, "dig +short +time=1 +tries=1 v4lonly.example.com @fd6c:1:1:31::1")

        assert example_00_v4.strip() == ""
        assert example_01_v4.strip() == ""
        # assert example_02_v4.strip() == "fdcc:0:c:1::ac10:1f04"
        # assert example_03_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f04"
        # assert example_04_v4.strip() == "fdcc:0:c:1::ac10:1f04"
        # assert example_05_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f04"

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_mixed_record_a_responses(self, host):
        """Tests if vpncmangle doctors A queries when a record has A and AAAA records."""
        example_00_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com @fdcc:0:c:1::172.16.31.1",
        )
        example_01_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com @fdcc:0:c:1:1::172.17.31.1",
        )
        example_02_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com @2001:db8:c57:31::1",
        )
        example_03_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com @2001:db8:c58:31::1",
        )
        example_04_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com @fd6c:1:0:31::1",
        )
        example_05_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com @fd6c:1:1:31::1",
        )

        assert example_00_v4.strip() == "fdcc:0:c:1::ac10:1f40"
        assert example_01_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f40"
        assert example_02_v4.strip() == "fdcc:0:c:1::ac10:1f40"
        assert example_03_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f40"
        assert example_04_v4.strip() == "fdcc:0:c:1::ac10:1f40"
        assert example_05_v4.strip() == "fdcc:0:c:1:1:0:ac11:1f40"

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nptv6_mixed_record_aaaa_responses(self, host):
        """Tests if vpncmangle doctors AAAA queries when a record has A and AAAA records."""
        example_00_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com AAAA @fdcc:0:c:1::172.16.31.1",
        )
        example_01_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com AAAA @fdcc:0:c:1:1::172.17.31.1",
        )
        example_02_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com AAAA @2001:db8:c57:31::1",
        )
        example_03_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com AAAA @2001:db8:c58:31::1",
        )
        example_04_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com AAAA @fd6c:1:0:31::1",
        )
        example_05_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v64l.example.com AAAA @fd6c:1:1:31::1",
        )

        assert example_00_v6.strip() == "fd6c:1:0:31::64"
        assert example_01_v6.strip() == "fd6c:1:1:31::64"
        assert example_02_v6.strip() == "fd6c:1:0:31::64"
        assert example_03_v6.strip() == "fd6c:1:1:31::64"
        assert example_04_v6.strip() == "fd6c:1:0:31::64"
        assert example_05_v6.strip() == "fd6c:1:1:31::64"

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nptv6_aaaa_only_record_aaaa_responses(self, host):
        """Tests if vpncmangle doctors AAAA queries when a record has only AAAA records."""
        example_00_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com AAAA @fdcc:0:c:1::172.16.31.1",
        )
        example_01_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com AAAA @fdcc:0:c:1:1::172.17.31.1",
        )
        example_02_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com AAAA @2001:db8:c57:31::1",
        )
        example_03_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com AAAA @2001:db8:c58:31::1",
        )
        example_04_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com AAAA @fd6c:1:0:31::1",
        )
        example_05_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com AAAA @fd6c:1:1:31::1",
        )

        assert example_00_v6.strip() == "fd6c:1:0:31::6"
        assert example_01_v6.strip() == "fd6c:1:1:31::6"
        assert example_02_v6.strip() == "fd6c:1:0:31::6"
        assert example_03_v6.strip() == "fd6c:1:1:31::6"
        assert example_04_v6.strip() == "fd6c:1:0:31::6"
        assert example_05_v6.strip() == "fd6c:1:1:31::6"

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nptv6_aaaa_only_record_fail_a_responses(self, host):
        """Tests if vpncmangle responds with nxdomain when a record has only AAAA records but A records
        are requested.
        """
        example_00_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com A @fdcc:0:c:1::172.16.31.1",
        )
        example_01_v4 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6lonly.example.com A @fdcc:0:c:1:1::172.17.31.1",
        )

        assert example_00_v4.strip() == ""
        assert example_01_v4.strip() == ""

    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_non_nptv6_aaaa_only_record_fail_aaaa_responses(self, host):
        """Tests if vpncmangle doesn't doctor non-NPTv6 addresses
        are requested.
        """
        example_00_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6gonly.example.com AAAA @fdcc:0:c:1::172.16.31.1",
        )
        example_01_v6 = run_cmd(
            host,
            "dig +short +time=1 +tries=1 v6gonly.example.com AAAA @fdcc:0:c:1:1::172.17.31.1",
        )

        assert example_00_v6.strip() == "2001:db8:c57:31::6"
        assert example_01_v6.strip() == "2001:db8:c58:31::6"
