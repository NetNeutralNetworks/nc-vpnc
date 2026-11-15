"""A connection that's up but passes no traffic is reset."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from . import conftest

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"
# An IPsec tunnel with probes, its peer, and an SSH tunnel (with probes) whose
# server is routed via that tunnel.
IPSEC = ("hub00", "C0001-00-0")
PEER = "end00"
SSH = ("hub00", "C0001-00-1")
# IKE keeps working, so the tunnel stays up.
DROP_ESP = "meta l4proto esp"
UP_TIMEOUT = 90
# The full check, which tests the probes, runs every 30 seconds.
FULL_CHECK = 45
# Without an answer for 3 minutes, noticed by a full check.
RESET_TIMEOUT = 300


def connection(host: str, name: str) -> dict[str, Any]:
    """Return a connection's state and details."""
    return json.loads(
        conftest.run_cmd(host, f"{VPNCTL} -o json connections show {name}"),
    )


def resets(host: str, name: str) -> int:
    """Return how often a connection was reset automatically in the last 24 hours."""
    return connection(host, name)["details"]["auto_resets_24h"]


def answered(host: str, name: str) -> bool | None:
    """Return whether a probe of an up connection is answered; None if not tested."""
    current = connection(host, name)
    tested = [p["failed"] for p in current["probes"] if p["failed"] is not None]
    if current["oper_status"] != "UP" or not tested:
        return None
    return not all(tested)


def all_answered() -> bool:
    """Return whether both tunnels are up with answered probes."""
    return bool(answered(*IPSEC) and answered(*SSH))


@pytest.fixture(autouse=True)
def probes_answered() -> Any:  # noqa: ANN401
    """Start and end with answered probes."""
    conftest.wait_until(all_answered, UP_TIMEOUT, message="answered probes")
    # A full check sees them answered, so earlier resets don't delay the next one.
    time.sleep(FULL_CHECK)
    yield
    conftest.wait_until(all_answered, UP_TIMEOUT, message="answered probes")


class TestProbeRecovery:
    """Probes that aren't answered reset their connection."""

    def test_no_traffic(self) -> None:
        """A tunnel that's up without traffic is reset; the SSH tunnel over it isn't."""
        ipsec_resets = resets(*IPSEC)
        ssh_resets = resets(*SSH)

        with conftest.nft_drop(PEER, "EXTERNAL", DROP_ESP):
            conftest.wait_until(
                lambda: answered(*IPSEC) is False,
                FULL_CHECK,
                message="probes without an answer",
            )
            assert resets(*IPSEC) == ipsec_resets

            conftest.wait_until(
                lambda: resets(*IPSEC) > ipsec_resets,
                RESET_TIMEOUT,
                message=f"a reset of {IPSEC[1]}",
            )
            # Up again, still without traffic: the next reset takes longer.
            conftest.wait_until(
                lambda: answered(*IPSEC) is False,
                UP_TIMEOUT,
                message=f"{IPSEC[1]} to be up",
            )

        conftest.wait_until(all_answered, UP_TIMEOUT, message="answered probes")
        assert resets(*IPSEC) == ipsec_resets + 1
        assert resets(*SSH) == ssh_resets
