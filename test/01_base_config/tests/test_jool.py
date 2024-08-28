import re

import pytest

from . import conftest


class TestJool:
    """Test if Jool is correctly configured."""

    @pytest.mark.parametrize("host", [("hub00"), ("hub01")])
    def test_jool_module_is_loaded_hub(self, host: str) -> None:
        """Test if the Jool kernel module is loaded."""
        module_load = conftest.run_cmd_shell(host, "lsmod | grep 'jool '")

        assert re.match(r"^jool\s+\d+\s+\d$", module_load)

    @pytest.mark.parametrize(("network_instance"), ["C0001-00", "C0001-01"])
    @pytest.mark.parametrize(("host"), ["hub00", "hub01"])
    def test_jool_is_running_in_network_instance_hub(
        self,
        host: str,
        network_instance: str,
    ) -> None:
        """Test if jool is running in the network instance."""
        jool_running = conftest.run_cmd_shell(
            host,
            (
                f"ip netns exec {network_instance}"
                f" jool --instance {network_instance} instance status"
            ),
        )

        # Remove trailing newline
        assert jool_running.strip() == "Running"

    @pytest.mark.parametrize("network_instance", [("E0001-00")])
    @pytest.mark.parametrize("host", [("end00"), ("end01")])
    def test_jool_is_not_running_in_network_instance_endpoint(
        self,
        host: str,
        network_instance: str,
    ) -> None:
        """Test if Jool is not running in the network instance."""
        jool_running = conftest.run_cmd_shell(
            host,
            (
                f"ip netns exec {network_instance}"
                f" jool --instance {network_instance} instance status"
            ),
        )

        # Remove trailing newline
        assert (
            jool_running.strip()
            == f"Dead\n(Instance '{network_instance}' does not exist.)"
        )

    @pytest.mark.parametrize(
        ("network_instance", "pool"),
        [("C0001-00", "fdcc:0:c:1::/96"), ("C0001-01", "fdcc:0:c:1:1::/96")],
    )
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_jool_nat64_prefix_is_set_correctly_hub(
        self,
        host: str,
        network_instance: str,
        pool: str,
    ) -> None:
        """Test if the Jool NAT64 pool is set correctly."""
        jool_prefix = conftest.run_cmd_shell(
            host,
            (
                f"ip netns exec {network_instance}"
                f" jool --instance {network_instance} global display | grep pool6"
            ),
        )

        # Remove whitespaces
        assert jool_prefix.strip() == f"pool6: {pool}"
