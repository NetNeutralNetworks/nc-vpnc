"""SSH tunnels recover after the server closes them and is unreachable."""

from __future__ import annotations

import time

from . import conftest

HUBS = ["hub00", "hub01"]

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
