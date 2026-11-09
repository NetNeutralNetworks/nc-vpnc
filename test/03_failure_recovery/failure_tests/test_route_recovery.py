"""Routes follow the state of all connections after failures.

Each connection's routes must be blackholed while its interface can't pass
traffic, and restored afterwards, independent of the order in which interfaces
fail and recover.

These tests disrupt the running lab. Each test waits until the routes are back
to their healthy state before it finishes.
"""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING

import pytest

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

HUBS = ["hub00", "hub01"]

# C0001-00 has two connections: an IPsec tunnel (xfrm0, connection 0) and an SSH
# tunnel (tun1, connection 1).
NETWORK_INSTANCE = "C0001-00"
XFRM_INTERFACE = "xfrm0"
SSH_INTERFACE = "tun1"
SSH_CONTROL_PATH = "/run/vpnc/ssh/C0001-00-1.sock"
CORE_INTERFACE = f"{NETWORK_INSTANCE}_C"

ROUTE_TIMEOUT = 30
# The strongSwan monitor resyncs XFRM interface states every 30 seconds.
XFRM_RESYNC_TIMEOUT = 60

Route = tuple[str, str, str | None, str | None]


def get_routes(host: str, netns: str) -> frozenset[Route]:
    """Return the routes of a network instance, except kernel and BGP routes.

    Each route is (destination, type, gateway, device).
    """
    routes: set[Route] = set()
    for family in ("-4", "-6"):
        output = json.loads(
            conftest.run_cmd(host, f"ip --json --netns {netns} {family} route"),
        )
        for route in output:
            if route.get("protocol") in ("kernel", "bgp"):
                continue
            routes.add(
                (
                    route["dst"],
                    route.get("type", "unicast"),
                    route.get("gateway"),
                    route.get("dev"),
                ),
            )
    return frozenset(routes)


def get_all_routes(host: str) -> dict[str, frozenset[Route]]:
    """Return the routes of the tested network instance and CORE."""
    return {netns: get_routes(host, netns) for netns in (NETWORK_INSTANCE, "CORE")}


def healthy_routes(host: str) -> dict[str, frozenset[Route]]:
    """Return the current routes after checking that nothing is blackholed."""
    routes = get_all_routes(host)
    blackholed = {
        netns: [r for r in netns_routes if r[1] == "blackhole"]
        for netns, netns_routes in routes.items()
    }
    assert not any(blackholed.values()), f"{host} isn't healthy: {blackholed}"
    return routes


def wait_for_routes(host: str, expected: dict[str, frozenset[Route]]) -> None:
    """Wait until the routes are equal to the expected routes."""
    conftest.wait_until(
        lambda: get_all_routes(host) == expected,
        timeout=ROUTE_TIMEOUT,
        message=f"routes on {host} to be restored",
    )


def set_link(host: str, ifname: str, state: str) -> None:
    """Set an interface in the tested network instance administratively up/down."""
    conftest.run_cmd(
        host,
        f"ip --netns {NETWORK_INSTANCE} link set dev {ifname} {state}",
    )


@contextlib.contextmanager
def ssh_tunnel_broken(host: str) -> Iterator[None]:
    """Break the SSH tunnel so its tun interface loses carrier.

    autossh is paused so it doesn't reconnect right away, then the ssh client is
    killed. On exit autossh is resumed and reconnects.
    """
    autossh = f"autossh .*{SSH_CONTROL_PATH}"
    conftest.run_cmd_shell(host, f"pkill -STOP -f '{autossh}'")
    try:
        conftest.run_cmd_shell(
            host,
            f"pkill -f '^/usr/bin/ssh .*{SSH_CONTROL_PATH} -o Tunnel'",
        )
        yield
    finally:
        conftest.run_cmd_shell(host, f"pkill -CONT -f '{autossh}'")


@pytest.mark.parametrize("host", HUBS)
class TestRouteRecovery:
    """Routes recover regardless of the order of failures."""

    def test_out_of_order_recovery(self, host: str) -> None:
        """Interfaces that fail and recover in a different order restore all routes.

        The SSH tunnel goes down and comes back while the IPsec tunnel is still
        down. Updating only the routes of the interface that changed would leave the
        SSH tunnel's advertisements in CORE blackholed.
        """
        expected = healthy_routes(host)

        try:
            set_link(host, SSH_INTERFACE, "down")
            set_link(host, XFRM_INTERFACE, "down")
            set_link(host, SSH_INTERFACE, "up")
        finally:
            set_link(host, SSH_INTERFACE, "up")
            set_link(host, XFRM_INTERFACE, "up")

        wait_for_routes(host, expected)

    def test_ssh_tunnel_carrier_loss(self, host: str) -> None:
        """Routes via a tun interface without carrier are blackholed.

        The interface stays administratively up when the SSH session is gone, but
        can't pass traffic. Its routes, and the network instance's advertisements in
        CORE, must be blackholed so traffic goes to the other hub.
        """
        expected = healthy_routes(host)
        via_tun = {r[0] for r in expected[NETWORK_INSTANCE] if r[3] == SSH_INTERFACE}
        advertised = {r[0] for r in expected["CORE"] if r[3] == CORE_INTERFACE}
        assert via_tun, f"No routes via {SSH_INTERFACE} on {host}"
        assert advertised, f"No routes via {CORE_INTERFACE} on {host}"

        def blackholed() -> bool:
            routes = get_all_routes(host)
            ni_blackholes = {
                r[0] for r in routes[NETWORK_INSTANCE] if r[1] == "blackhole"
            }
            core_blackholes = {r[0] for r in routes["CORE"] if r[1] == "blackhole"}
            return via_tun <= ni_blackholes and advertised <= core_blackholes

        with ssh_tunnel_broken(host):
            conftest.wait_until(
                blackholed,
                timeout=ROUTE_TIMEOUT,
                message=f"routes via {SSH_INTERFACE} on {host} to be blackholed",
            )

        wait_for_routes(host, expected)

    def test_xfrm_interface_state_resync(self, host: str) -> None:
        """An XFRM interface that is down while its SA is up is brought back up.

        Simulates a missed IKE/child SA event: the strongSwan monitor must correct
        the interface state, after which the routes are restored.
        """
        expected = healthy_routes(host)

        set_link(host, XFRM_INTERFACE, "down")
        try:
            conftest.wait_until(
                lambda: get_all_routes(host) == expected,
                timeout=XFRM_RESYNC_TIMEOUT,
                message=f"{XFRM_INTERFACE} on {host} to be brought up and routes"
                " restored",
            )
        finally:
            # Leave the lab usable if the monitor didn't correct it.
            set_link(host, XFRM_INTERFACE, "up")
