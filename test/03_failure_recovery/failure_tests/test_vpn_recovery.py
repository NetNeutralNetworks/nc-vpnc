"""VPN connections recover after strongSwan failures and unreachable peers."""

from __future__ import annotations

import contextlib
import json
import re
import time
from typing import TYPE_CHECKING

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

HOST = "hub00"
# hub00 initiates CORE-0/CORE-1; end00 initiates C0001-00-0.
UPLINK_UNREACHABLE = "CORE-0"
UPLINK_REACHABLE = "CORE-1"
RESPONDER_CONNECTION = "C0001-00-0"
# IKE source addresses of the peers.
MGT00_ADDRESSES = ("192.0.2.3", "2001:db8::3")
END00_ADDRESSES = ("192.0.2.7", "2001:db8::7")

FULL_CHECK_INTERVAL = 30
# Peers retry with backoff.
PEER_RETRY_TIMEOUT = 240

# "<name>: #<id>, <state>, " in swanctl --list-sas.
SA_RE = re.compile(r"^(\S+): #\d+, (\w+), ")
POLICY_IF_ID_RE = re.compile(r"if_id (0x[0-9a-f]+)")
# "(<mark>|<if_id>)" of a child SA in swanctl --list-sas.
CHILD_IF_ID_RE = re.compile(r"\(-\|(0x[0-9a-f]+)\)")


def get_sas(host: str) -> dict[str, list[str]]:
    """Return per connection the states of its IKE SAs."""
    output = conftest.run_cmd_shell(host, "swanctl --list-sas 2>/dev/null")
    sas: dict[str, list[str]] = {}
    for line in output.splitlines():
        if match := SA_RE.match(line):
            sas.setdefault(match.group(1), []).append(match.group(2))
    return sas


def get_connections(host: str) -> set[str]:
    """Return the connections loaded in charon."""
    output = conftest.run_cmd_shell(host, "swanctl --list-conns 2>/dev/null")
    return {line.split(":")[0] for line in output.splitlines() if line[:1].isalnum()}


def is_established(host: str, *names: str) -> bool:
    """Return whether all named connections have an established IKE SA."""
    sas = get_sas(host)
    return all("ESTABLISHED" in sas.get(name, []) for name in names)


def bgp_all_established(host: str) -> bool:
    """Return whether all BGP peers in the CORE VRF are established."""
    output = json.loads(
        conftest.run_cmd_vtysh(host, "show bgp vrf CORE summary json"),
    )
    peers = output["ipv6Unicast"]["peers"].values()
    return bool(peers) and all(peer["state"] == "Established" for peer in peers)


def wait_for_healthy(host: str, connections: set[str], timeout: float) -> None:
    """Wait until all connections are established and BGP is up."""
    conftest.wait_until(
        lambda: is_established(host, *connections),
        timeout=timeout,
        message=f"all connections on {host} to be established",
    )
    conftest.wait_until(
        lambda: bgp_all_established(host),
        timeout=150,
        message=f"BGP on {host} to be established",
    )


@contextlib.contextmanager
def ike_blocked_from(host: str, addresses: tuple[str, ...]) -> Iterator[None]:
    """Drop incoming IKE from the given peer addresses on the EXTERNAL network."""
    rules = [
        (
            "ip6tables" if ":" in address else "iptables",
            f"INPUT -s {address} -p udp -m multiport --dports 500,4500 -j DROP",
        )
        for address in addresses
    ]
    for iptables, rule in rules:
        conftest.run_cmd(host, f"ip netns exec EXTERNAL {iptables} -I {rule}")
    try:
        yield
    finally:
        for iptables, rule in rules:
            conftest.run_cmd_shell(
                host,
                f"ip netns exec EXTERNAL {iptables} -D {rule} || true",
            )


def sas_appearing(host: str, name: str, seconds: float) -> list[str]:
    """Watch a connection for seconds and return its SAs as soon as it has any."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if sas := get_sas(host).get(name, []):
            return sas
        time.sleep(1)
    return []


def stale_policy_if_ids(host: str) -> set[str]:
    """Return the if_ids of XFRM policies that have no child SA."""
    policies = conftest.run_cmd(
        host,
        "ip netns exec EXTERNAL ip xfrm policy list nosock",
    )
    sas = conftest.run_cmd_shell(host, "swanctl --list-sas 2>/dev/null")
    return set(POLICY_IF_ID_RE.findall(policies)) - set(CHILD_IF_ID_RE.findall(sas))


def force_terminate(host: str, name: str) -> None:
    """Delete an IKE SA without waiting for the peer."""
    conftest.run_cmd_shell(
        host,
        f"swanctl --terminate --ike {name} --force > /dev/null 2>&1 || true",
    )


class TestVpnRecovery:
    """VPN connections are re-established by the right side."""

    def test_charon_restart(self) -> None:
        """After a charon restart, connections are reloaded and re-established."""
        connections = get_connections(HOST)
        assert connections, f"No connections loaded on {HOST}"

        conftest.run_cmd_shell(HOST, "pkill -KILL -x charon")

        conftest.wait_until(
            lambda: get_connections(HOST) == connections,
            timeout=FULL_CHECK_INTERVAL * 3,
            message=f"connections to be loaded on {HOST} after a charon restart",
        )
        wait_for_healthy(HOST, connections, PEER_RETRY_TIMEOUT)

    def test_unreachable_peer_does_not_block_others(self) -> None:
        """An unreachable peer doesn't delay re-establishing other connections."""
        connections = get_connections(HOST)
        with ike_blocked_from(HOST, MGT00_ADDRESSES):
            force_terminate(HOST, UPLINK_UNREACHABLE)
            force_terminate(HOST, UPLINK_REACHABLE)

            conftest.wait_until(
                lambda: is_established(HOST, UPLINK_REACHABLE),
                timeout=FULL_CHECK_INTERVAL * 2,
                message=f"{UPLINK_REACHABLE} to be re-established while"
                f" {UPLINK_UNREACHABLE} is unreachable",
            )
            assert not is_established(HOST, UPLINK_UNREACHABLE)

        wait_for_healthy(HOST, connections, PEER_RETRY_TIMEOUT)

    def test_responder_does_not_initiate(self) -> None:
        """A responder connection is re-established by its peer, not by vpnc."""
        connections = get_connections(HOST)
        with ike_blocked_from(HOST, END00_ADDRESSES):
            force_terminate(HOST, RESPONDER_CONNECTION)

            # Give the full check a chance to (wrongly) initiate.
            sas = sas_appearing(HOST, RESPONDER_CONNECTION, FULL_CHECK_INTERVAL + 5)
            assert not sas, (
                f"{HOST} created an SA for responder connection"
                f" {RESPONDER_CONNECTION}: {sas}"
            )

        conftest.wait_until(
            lambda: is_established(HOST, RESPONDER_CONNECTION),
            timeout=PEER_RETRY_TIMEOUT,
            message=f"end00 to re-establish {RESPONDER_CONNECTION}",
        )
        wait_for_healthy(HOST, connections, PEER_RETRY_TIMEOUT)

    def test_stale_policies_removed(self) -> None:
        """Policies left by a killed charon go when their SA doesn't come back."""
        connections = get_connections(HOST)
        with ike_blocked_from(HOST, END00_ADDRESSES):
            conftest.run_cmd_shell(HOST, "pkill -KILL -x charon")
            conftest.wait_until(
                lambda: is_established(HOST, UPLINK_UNREACHABLE, UPLINK_REACHABLE),
                timeout=PEER_RETRY_TIMEOUT,
                message=f"uplinks on {HOST} to be re-established",
            )
            conftest.wait_until(
                lambda: not stale_policy_if_ids(HOST),
                timeout=FULL_CHECK_INTERVAL * 4,
                message=f"stale XFRM policies on {HOST} to be removed",
            )
            assert not is_established(HOST, RESPONDER_CONNECTION)

        wait_for_healthy(HOST, connections, PEER_RETRY_TIMEOUT)
