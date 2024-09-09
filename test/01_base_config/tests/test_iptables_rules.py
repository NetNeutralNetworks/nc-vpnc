import re

import pytest

from . import conftest
from .data import data_test_iptables_nat_rules, data_test_iptables_rules


class TestIPTables:
    """Tests if IPv4 firewall rules are configured correctly."""

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_rules.TABLES4_HUB,
    )
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_iptables_hub(self, host: str, network_instance: str, rules: str) -> None:
        """Test IPv4 firewall rules for hubs."""
        rules_state = conftest.run_cmd(
            host,
            f"/usr/sbin/ip netns exec {network_instance} /usr/sbin/iptables -S",
        ).strip()

        assert rules_state == rules

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_rules.TABLES4_END,
    )
    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_iptables_endpoint(
        self,
        host: str,
        network_instance: str,
        rules: str,
    ) -> None:
        """Test IPv4 firewall rules for endpoints."""
        rules_state = conftest.run_cmd(
            host,
            f"/usr/sbin/ip netns exec {network_instance} /usr/sbin/iptables -S",
        ).strip()

        assert rules_state == rules

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_rules.TABLES6_HUB,
    )
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ip6tables_hub(self, host: str, network_instance: str, rules: str) -> None:
        """Test IPv6 firewall rules for hubs."""
        rules_state = conftest.run_cmd(
            host,
            f"/usr/sbin/ip netns exec {network_instance} /usr/sbin/ip6tables -S",
        ).strip()

        assert rules_state == rules

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_rules.TABLES6_END,
    )
    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_ip6tables_endpoint(
        self,
        host: str,
        network_instance: str,
        rules: str,
    ) -> None:
        """Test IPv6 firewall rules for endpoints."""
        rules_state = conftest.run_cmd(
            host,
            f"/usr/sbin/ip netns exec {network_instance} /usr/sbin/ip6tables -S",
        ).strip()

        assert rules_state == rules


class TestIPTablesNAT:
    """Test if NAT/NPTv6 rules have been configured correctly."""

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_nat_rules.TABLES4_HUB,
    )
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_iptables_nat_hub(
        self,
        host: str,
        network_instance: str,
        rules: str,
    ) -> None:
        """Test IPv4 NAT rules for the hub."""
        rules_state = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} iptables -t nat -S",
        ).strip()

        assert rules_state == rules

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_nat_rules.TABLES4_END,
    )
    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_iptables_nat_endpoint(
        self,
        host: str,
        network_instance: str,
        rules: str,
    ) -> None:
        """Test IPv4 NAT rules for the endpoint."""
        rules_state = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} iptables -t nat -S",
        ).strip()

        assert rules_state == rules

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_nat_rules.TABLES6_HUB,
    )
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ip6tables_nat_hub(
        self,
        host: str,
        network_instance: str,
        rules: str,
    ) -> None:
        """Test IPv6 NAT rules for the hub."""
        rules_state = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} ip6tables -t nat -S",
        ).strip()

        assert rules_state == rules

    @pytest.mark.parametrize(
        ("network_instance"),
        ["C0001-00", "C0001-01"],
    )
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ip6tables_nat_hub_masquerade_must_be_at_the_end(
        self,
        host: str,
        network_instance: str,
    ) -> None:
        """Test if the masquerade call is only at the end.

        If it is anywhere before the end, it will break the session.
        """
        rules_state = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} ip6tables -t nat -S",
        ).strip()

        rules_state_lines = rules_state.split("\n")
        first_masquerade_line = 0
        for idx, line in enumerate(rules_state_lines):
            if "MASQUERADE" in line:
                first_masquerade_line = idx
                break

        masquerades_at_end = all(
            "MASQUERADE" in x for x in rules_state_lines[first_masquerade_line:]
        )

        # The masquerade always has to be at the end.
        assert re.match(
            r"-A POSTROUTING -o \S+ -j MASQUERADE",
            rules_state_lines[-1],
        )

        # Masquerade must not be in the rest of the configuration
        assert masquerades_at_end

    @pytest.mark.parametrize(
        ("network_instance", "rules"),
        data_test_iptables_nat_rules.TABLES6_END,
    )
    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_ip6tables_nat_endpoint(
        self,
        host: str,
        network_instance: str,
        rules: str,
    ) -> None:
        """Test IPv6 NAT rules for the endpoint."""
        rules_state = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} ip6tables -t nat -S",
        ).strip()

        assert rules_state == rules
