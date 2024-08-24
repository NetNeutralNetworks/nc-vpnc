import re
import subprocess

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


def run_cmd_shell(host: str, command: str) -> str:
    """Runs a command in the docker container and returns the results"""
    cmd = f"docker exec clab-vpnc-{host} {command}"

    output = subprocess.run(
        cmd,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        check=True,
        shell=True,
    ).stdout.decode()

    return output


class TestJool:
    """Tests if the Jool is correctly configured on the hubs and not running on the endpoints"""

    @pytest.mark.parametrize("host", [("hub00"), ("hub01")])
    def test_jool_module_is_loaded_hub(self, host):
        """Test if the Jool kernel module is loaded"""
        module_load = run_cmd_shell(host, "lsmod | grep 'jool '")

        assert re.match(r"^jool\s+\d+\s+\d$", module_load)

    @pytest.mark.parametrize("netns", [("C0001-00"), ("C0001-01")])
    @pytest.mark.parametrize("host", [("hub00"), ("hub01")])
    def test_jool_is_running_in_network_instance_hub(self, host, netns):
        """Tests if jool is running in the network instance"""
        jool_running = run_cmd_shell(
            host,
            f"ip netns exec {netns} jool --instance {netns} instance status",
        )

        # Remove trailing newline
        assert jool_running.strip() == "Running"

    @pytest.mark.parametrize("netns", [("E0001-00")])
    @pytest.mark.parametrize("host", [("end00"), ("end01")])
    def test_jool_is_not_running_in_network_instance_endpoint(self, host, netns):
        """Tests if Jool is not running in the network instance"""
        jool_running = run_cmd_shell(
            host,
            f"ip netns exec {netns} jool --instance {netns} instance status",
        )

        # Remove trailing newline
        assert jool_running.strip() == f"Dead\n(Instance '{netns}' does not exist.)"

    @pytest.mark.parametrize(
        "netns, pool",
        [("C0001-00", "fdcc:0:c:1::/96"), ("C0001-01", "fdcc:0:c:1:1::/96")],
    )
    @pytest.mark.parametrize("host", [("hub00"), ("hub00")])
    def test_jool_nat64_prefix_is_set_correctly_hub(self, host, netns, pool):
        """Tests if the Jool NAT64 pool is set correctly."""
        jool_prefix = run_cmd_shell(
            host,
            f"ip netns exec {netns} jool --instance {netns} global display | grep pool6",
        )

        # Remove whitespaces
        assert jool_prefix.strip() == f"pool6: {pool}"
