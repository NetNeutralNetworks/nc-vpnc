import pytest

from . import conftest
from .data import data_test_nftables_rules


class TestNftables:
    """Tests if the firewall rules (vpnc's nftables table) are configured correctly."""

    @pytest.mark.parametrize(
        ("host", "network_instance", "table"),
        data_test_nftables_rules.TABLES,
    )
    def test_table(self, host: str, network_instance: str, table: str) -> None:
        """Test vpnc's nftables table of a network instance."""
        table_state = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} nft list table inet vpnc",
        ).strip()

        assert table_state == table

    @pytest.mark.parametrize(
        ("host", "network_instance", "tables"),
        data_test_nftables_rules.TABLE_NAMES,
    )
    def test_no_other_tables(
        self,
        host: str,
        network_instance: str,
        tables: list[str],
    ) -> None:
        """Test that no other tables (e.g. vpnc's old iptables ones) are left."""
        tables_state = conftest.run_cmd(
            host,
            f"ip netns exec {network_instance} nft list tables",
        ).splitlines()

        assert sorted(tables_state) == tables
