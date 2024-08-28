import re
import subprocess

import pytest

from . import conftest


class TestVpncmangle:
    """Test the vpncmangle setup/status."""

    # @pytest.mark.parametrize("tables", [tables6_mangle_hub])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_vpncmangle_is_running_hub(self, host: str) -> None:
        """Test if vpncmangle correctly adds the ip6table rule."""
        running = conftest.run_cmd(host, "pgrep --list-name vpncmangle")

        assert re.match(r"^\d+ vpncmangle$", running)

    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_vpncmangle_is_not_running_endpoint(self, host: str) -> None:
        """Test if vpncmangle correctly adds the ip6table rule."""
        with pytest.raises(subprocess.CalledProcessError):
            x = conftest.run_cmd(host, "pgrep --list-name vpncmangle")


class TestIPTablesMangle:
    """Tests if netfilter is set up correctly to forward traffic to vpncmangle."""

    tables6_mangle_hub = (
        # Perform NPTv6 before doing the masquerade. The masquerade always has to be at the end.
        "-P PREROUTING ACCEPT\n"
        "-P INPUT ACCEPT\n"
        "-P FORWARD ACCEPT\n"
        "-P OUTPUT ACCEPT\n"
        "-P POSTROUTING ACCEPT\n"
        "-A POSTROUTING -p udp -m udp --sport 53 -j NFQUEUE --queue-num 0\n"
    )

    @pytest.mark.parametrize("tables", [tables6_mangle_hub])
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ip6tables_mangle_hub(self, host: str, tables: str) -> None:
        """Test if vpncmangle correctly adds the ip6table rule."""
        rules_status = conftest.run_cmd(
            host,
            "ip netns exec CORE ip6tables -t mangle -S",
        )

        assert rules_status == tables

    # Perform NPTv6 before doing the masquerade. The masquerade always has to be at the end.
    tables6_mangle_endpoint = (
        "-P PREROUTING ACCEPT\n"
        "-P INPUT ACCEPT\n"
        "-P FORWARD ACCEPT\n"
        "-P OUTPUT ACCEPT\n"
        "-P POSTROUTING ACCEPT\n"
    )

    @pytest.mark.parametrize("tables", [tables6_mangle_endpoint])
    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_ip6tables_mangle_disabled_endpoints(
        self,
        host: str,
        tables: str,
    ) -> None:
        """Test if vpncmangle correctly adds the ip6table rules."""
        rules_status = conftest.run_cmd(
            host,
            "ip netns exec CORE ip6tables -t mangle -S",
        )

        assert rules_status == tables


class TestDNSMangle:
    """Tests DNS queries are doctored correctly."""

    v4lonly_a_requested = [
        ("fdcc:0:c:1::172.16.31.1", "fdcc:0:c:1::ac10:1f04"),
        ("fdcc:0:c:1:1::172.17.31.1", "fdcc:0:c:1:1:0:ac11:1f04"),
        ("2001:db8:c57:31::1", "fdcc:0:c:1::ac10:1f04"),
        ("2001:db8:c58:31::1", "fdcc:0:c:1:1:0:ac11:1f04"),
        ("fd6c:1:0:31::1", "fdcc:0:c:1::ac10:1f04"),
        ("fd6c:1:1:31::1", "fdcc:0:c:1:1:0:ac11:1f04"),
    ]

    @pytest.mark.parametrize(("server", "answer"), v4lonly_a_requested)
    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_a_only_record_a_responses(
        self,
        host: str,
        server: str,
        answer: str,
    ) -> None:
        """Verify behavior with v4-only record when A-record is requested.

        Verify that vpncmangle doctors v4-only responses to a correct IPv6 address.
        """
        response = conftest.run_cmd(
            host,
            f"dig +short +time=1 +tries=1 v4lonly.example.com @{server}",
        )

        assert response.strip() == answer

    v4lonly_aaaa_requested = [
        ("fdcc:0:c:1::172.16.31.1", ""),
        ("fdcc:0:c:1:1::172.17.31.1", ""),
        ("2001:db8:c57:31::1", ""),
        ("2001:db8:c58:31::1", ""),
        ("fd6c:1:0:31::1", ""),
        ("fd6c:1:1:31::1", ""),
    ]

    @pytest.mark.parametrize(("server", "answer"), v4lonly_aaaa_requested)
    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_a_only_record_fail_aaaa_responses(
        self,
        host: str,
        server: str,
        answer: str,
    ) -> None:
        """Verify behavior with v4-only record when AAAA-record is requested.

        vpncmangle must respond with no answer if AAAA record doesn't exist but
        is requested.
        """
        response = conftest.run_cmd(
            host,
            f"dig +short +time=1 +tries=1 v4lonly.example.com AAAA @{server}",
        )

        assert response.strip() == answer

    v64l_a_requested = [
        ("fdcc:0:c:1::172.16.31.1", "fdcc:0:c:1::ac10:1f40"),
        ("fdcc:0:c:1:1::172.17.31.1", "fdcc:0:c:1:1:0:ac11:1f40"),
        ("2001:db8:c57:31::1", "fdcc:0:c:1::ac10:1f40"),
        ("2001:db8:c58:31::1", "fdcc:0:c:1:1:0:ac11:1f40"),
        ("fd6c:1:0:31::1", "fdcc:0:c:1::ac10:1f40"),
        ("fd6c:1:1:31::1", "fdcc:0:c:1:1:0:ac11:1f40"),
    ]

    @pytest.mark.parametrize(("server", "answer"), v64l_a_requested)
    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nat64_mixed_record_a_responses(
        self,
        host: str,
        server: str,
        answer: str,
    ) -> None:
        """Verify behavior with v64 records when A-record is requested.

        Tests if vpncmangle doctors A queries when a record has A and AAAA records.
        """
        response = conftest.run_cmd(
            host,
            f"dig +short +time=1 +tries=1 v64l.example.com @{server}",
        )

        assert response.strip() == answer

    v64l_aaaa_requested = [
        ("fdcc:0:c:1::172.16.31.1", "fd6c:1:0:31::64"),
        ("fdcc:0:c:1:1::172.17.31.1", "fd6c:1:1:31::64"),
        ("2001:db8:c57:31::1", "fd6c:1:0:31::64"),
        ("2001:db8:c58:31::1", "fd6c:1:1:31::64"),
        ("fd6c:1:0:31::1", "fd6c:1:0:31::64"),
        ("fd6c:1:1:31::1", "fd6c:1:1:31::64"),
    ]

    @pytest.mark.parametrize(("server", "answer"), v64l_aaaa_requested)
    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nptv6_mixed_record_aaaa_responses(
        self,
        host: str,
        server: str,
        answer: str,
    ) -> None:
        """Verify behavior with v64 records when AAAA-record is requested.

        Tests if vpncmangle doctors AAAA queries when a record has A and AAAA records.
        """
        response = conftest.run_cmd(
            host,
            f"dig +short +time=1 +tries=1 v64l.example.com AAAA @{server}",
        )

        assert response.strip() == answer

    v6lonly_aaaa_requested = [
        ("fdcc:0:c:1::172.16.31.1", "fd6c:1:0:31::6"),
        ("fdcc:0:c:1:1::172.17.31.1", "fd6c:1:1:31::6"),
        ("2001:db8:c57:31::1", "fd6c:1:0:31::6"),
        ("2001:db8:c58:31::1", "fd6c:1:1:31::6"),
        ("fd6c:1:0:31::1", "fd6c:1:0:31::6"),
        ("fd6c:1:1:31::1", "fd6c:1:1:31::6"),
    ]

    @pytest.mark.parametrize(("server", "answer"), v6lonly_aaaa_requested)
    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nptv6_aaaa_only_record_aaaa_responses(
        self,
        host: str,
        server: str,
        answer: str,
    ) -> None:
        """Verify behavior with v6-only records when AAAA-record is requested.

        Tests if vpncmangle doctors AAAA queries when a record has only AAAA records.
        """
        response = conftest.run_cmd(
            host,
            f"dig +short +time=1 +tries=1 v6lonly.example.com AAAA @{server}",
        )

        assert response.strip() == answer

    v6lonly_a_requested = [
        ("fdcc:0:c:1::172.16.31.1", ""),
        ("fdcc:0:c:1:1::172.17.31.1", ""),
        ("2001:db8:c57:31::1", ""),
        ("2001:db8:c58:31::1", ""),
        ("fd6c:1:0:31::1", ""),
        ("fd6c:1:1:31::1", ""),
    ]

    @pytest.mark.parametrize(("server", "answer"), v6lonly_a_requested)
    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_nptv6_aaaa_only_record_fail_a_responses(
        self,
        host: str,
        server: str,
        answer: str,
    ) -> None:
        """Verify behavior with v6-only records when A-record is requested.

        Tests if vpncmangle responds with nxdomain when a record has only AAAA records
        but A records are requested.
        """
        record = conftest.run_cmd(
            host,
            f"dig +short +time=1 +tries=1 v6lonly.example.com A @{server}",
        )

        assert record.strip() == answer

    v6gonly_aaaa_requested = [
        ("fdcc:0:c:1::172.16.31.1", "2001:db8:c57:31::6"),
        ("fdcc:0:c:1:1::172.17.31.1", "2001:db8:c58:31::6"),
        ("2001:db8:c57:31::1", "2001:db8:c57:31::6"),
        ("2001:db8:c58:31::1", "2001:db8:c58:31::6"),
        ("fd6c:1:0:31::1", "2001:db8:c57:31::6"),
        ("fd6c:1:1:31::1", "2001:db8:c58:31::6"),
    ]

    @pytest.mark.parametrize(("server", "answer"), v6gonly_aaaa_requested)
    @pytest.mark.parametrize("host", ["mgt00", "mgt01"])
    def test_dns_query_via_non_nptv6_aaaa_only_record_aaaa_responses(
        self,
        host: str,
        server: str,
        answer: str,
    ) -> None:
        """Verify behavior with non-NPTv6 AAAA records..

        Tests if vpncmangle doesn't doctor non-NPTv6 addresses when requested.
        """
        response = conftest.run_cmd(
            host,
            f"dig +short +time=1 +tries=1 v6gonly.example.com AAAA @{server}",
        )

        assert response.strip() == answer
