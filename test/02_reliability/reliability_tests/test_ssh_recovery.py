"""SSH tunnels recover after the server closes them and is unreachable."""

from __future__ import annotations

import time

from . import conftest

HUBS = ["hub00", "hub01"]

# The known hosts of ssh's account on a hub, the address the hubs connect to and
# a host key that isn't the server's.
KNOWN_HOSTS = "/var/lib/vpnc-ssh/.ssh/known_hosts"
SERVER_ADDRESS = "172.16.30.1"
OTHER_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPKGIBf6c9wEY6CKQO+ZRByrpFZYm+osZwE+ENrqggJJ"
)

# Reconnect delay is capped at 30s, plus connect time.
RECOVERY_TIMEOUT = 60


def wait_for_tunnels() -> None:
    """Wait until the SSH tunnels of all hubs pass traffic."""
    for host in HUBS:
        conftest.wait_until(
            lambda host=host: conftest.ssh_tunnel_works(host),
            timeout=RECOVERY_TIMEOUT,
            message=f"SSH tunnel on {host} to recover",
        )


class TestSshRecovery:
    """SSH tunnels reconnect."""

    def test_server_unreachable(self) -> None:
        """Tunnels reconnect after the server closed them and was unreachable."""
        wait_for_tunnels()
        with conftest.ssh_server_down():
            conftest.wait_until(
                lambda: not any(conftest.ssh_tunnel_works(host) for host in HUBS),
                timeout=10,
                message="SSH tunnels to go down",
            )
            # Several failed attempts, so the reconnect delay has grown.
            time.sleep(60)
        wait_for_tunnels()

    def test_other_host_key_for_the_address(self) -> None:
        """Tunnels reconnect when ssh's account knows another key for the address.

        E.g. of another tenant's server: tenants use the same addresses.
        """
        wait_for_tunnels()
        for host in HUBS:
            conftest.write_file(host, KNOWN_HOSTS, f"{SERVER_ADDRESS} {OTHER_KEY}\n")
        try:
            conftest.close_ssh_sessions()
            wait_for_tunnels()
        finally:
            for host in HUBS:
                conftest.run_cmd(host, f"rm {KNOWN_HOSTS}")
