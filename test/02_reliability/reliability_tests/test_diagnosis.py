"""vpnctl tells why a connection is down, and keeps what happened as events."""

from __future__ import annotations

import contextlib
import datetime as dt
import json
from typing import TYPE_CHECKING, Any

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"
# The two sides of one IPsec connection: end00 initiates, hub00 responds.
INITIATOR = ("end00", "CORE-0")
RESPONDER = ("hub00", "C0001-00-0")
BOTH = (INITIATOR, RESPONDER)
# end00's and hub00's configuration of it.
INITIATOR_CONFIG = ("end00", "service", "network_instances.CORE.connections.0.config")
RESPONDER_CONFIG = ("hub00", "C0001", "network_instances.00.connections.0.config")
# hub00's SSH and WireGuard connections.
SSH = ("hub00", "C0001-00-1")
SSH_CONFIG = ("hub00", "C0001", "network_instances.00.connections.1.config")
WIREGUARD = ("hub00", "C0001-01-0")
WIREGUARD_CONFIG = ("hub00", "C0001", "network_instances.01.connections.0.config")
# A valid key that isn't the peer's.
OTHER_PUBLIC_KEY = "6NwLHrFvVqz0dvuWUXKQMo1tUUHEaYuWbpWhw4qDGWM="
# What a connection that works has: nothing, or it went down often (these tests).
WORKS = (None, "FLAPPING")
# A failure is noted when it's tried again: within a minute.
FAIL_TIMEOUT = 100
# Peers set up IPsec again; unanswered requests are retried for up to 165s.
UP_TIMEOUT = 240
# A connection that's reset negotiates anew.
RESET_TIMEOUT = 60


def vpnctl(host: str, args: str) -> Any:  # noqa: ANN401
    """Run vpnctl with JSON output."""
    return json.loads(conftest.run_cmd(host, f"{VPNCTL} -o json {args}"))


def diagnosis(host: str, name: str) -> dict[str, Any]:
    """Return what vpnctl says is wrong with a connection."""
    return vpnctl(host, f"connections diagnose {name}")


def diagnosed(side: tuple[str, str], *problems: str | None) -> dict[str, Any]:
    """Wait for a connection's problem to be one of problems; return the diagnosis."""

    def found() -> dict[str, Any] | None:
        result = diagnosis(*side)
        return result if result["problem"] in problems else None

    return conftest.wait_until(
        found,
        timeout=UP_TIMEOUT if None in problems else FAIL_TIMEOUT,
        interval=3,
        message=f"{side[1]} on {side[0]} to have {' or '.join(map(str, problems))}",
    )


def events_since(side: tuple[str, str], start: dt.datetime) -> list[str]:
    """Return the names of a connection's events since a time, oldest first."""
    events = vpnctl(side[0], f"connections events {side[1]} -n 200")
    return [
        event["event"]
        for event in events
        if dt.datetime.fromisoformat(event["time"]) >= start.replace(microsecond=0)
    ]


def commit(host: str, target: str) -> None:
    """Make the staged changes active."""
    conftest.run_cmd(host, f"{VPNCTL} config commit {target}")


@contextlib.contextmanager
def changed(
    config: tuple[str, str, str],
    key: str,
    value: Any,  # noqa: ANN401
    sides: tuple[tuple[str, str], ...] = BOTH,
) -> Iterator[None]:
    """Commit a value in a connection's configuration; put the old one back after.

    The sides work again before it returns.
    """
    host, target, path = config
    path = f"{path}.{key}"
    old = vpnctl(host, f"config show {target} {path} --reveal-secrets")

    def put(new: Any) -> None:  # noqa: ANN401
        text = json.dumps(new, separators=(",", ":"))
        conftest.run_cmd(host, f"{VPNCTL} config set {target} {path} {text}")
        commit(host, target)

    put(value)
    try:
        yield
    finally:
        if old is None:
            conftest.run_cmd(host, f"{VPNCTL} config delete {target} {path}")
            commit(host, target)
        else:
            put(old)
        for side in sides:
            diagnosed(side, *WORKS)


def child_sa_has(side: tuple[str, str], text: str) -> None:
    """Wait for a connection's child SA to be described with text."""
    conftest.wait_until(
        lambda: text in child_sa(side),
        timeout=RESET_TIMEOUT,
        interval=3,
        message=f"the child SA of {side[1]} on {side[0]} to have {text}",
    )


def child_sa(side: tuple[str, str]) -> str:
    """Return what the diagnosis says of a connection's child SA."""
    checks = diagnosis(*side)["checks"]
    return next((c["detail"] for c in checks if c["name"] == "child SA"), "")


def now(host: str) -> dt.datetime:
    """Return the time on a host, as its events have it."""
    return dt.datetime.fromisoformat(conftest.run_cmd(host, "date -Iseconds").strip())


class TestDiagnosis:
    """A connection that fails has a problem, with what each side sent."""

    def test_id(self) -> None:
        """An id the peer doesn't expect: rejected there, an id mismatch here."""
        start = now("hub00")
        with changed(INITIATOR_CONFIG, "local_id", "wrong.example.com"):
            rejected = diagnosed(INITIATOR, "AUTH_FAILED_REMOTE")
            assert rejected["oper_status"] != "UP"
            assert rejected["details"]["sent_local_id"] == "wrong.example.com"
            assert rejected["hint"]

            mismatch = diagnosed(RESPONDER, "ID_MISMATCH")
            assert mismatch["details"]["received_remote_id"] == "wrong.example.com"
            assert mismatch["details"]["configured_remote_id"] == "192.0.2.7"
            assert any("no matching peer config" in x for x in mismatch["evidence"])
            assert mismatch["count"] >= 1

        # Both sides work again, and the history tells what happened.
        events = events_since(RESPONDER, start)
        assert events.index("OPER_DOWN") < events.index("ID_MISMATCH")
        assert events[-1] == "OPER_UP"
        assert "AUTH_FAILED_REMOTE" in events_since(INITIATOR, start)

    def test_ike_proposal(self) -> None:
        """Proposals without one in common: the responder shows both sides'."""
        with changed(INITIATOR_CONFIG, "ike_proposal", "aes256gcm16-prfsha512-ecp521"):
            assert diagnosed(INITIATOR, "IKE_PROPOSAL_MISMATCH")["details"] == {
                "configured_ike_proposal": "aes256gcm16-prfsha512-ecp521-ke1_mlkem768",
            }
            details = diagnosed(RESPONDER, "IKE_PROPOSAL_MISMATCH")["details"]
            assert "ECP_521" in details["received_proposals"]
            assert "ECP_384" in details["configured_proposals"]

    def test_psk(self) -> None:
        """A wrong PSK: rejected by the peer, a failed authentication there.

        A changed key resets the connection: the SA it had would hide it.
        """
        start = now("end00")
        with changed(INITIATOR_CONFIG, "psk", "not-the-preshared-key"):
            diagnosed(INITIATOR, "AUTH_FAILED_REMOTE")
            diagnosed(RESPONDER, "AUTH_FAILED_LOCAL")
        events = events_since(INITIATOR, start)
        assert events.index("CONFIG_RESET") < events.index("AUTH_FAILED_REMOTE")

    def test_traffic_selectors(self) -> None:
        """Narrowed selectors show as narrowed; without overlap it's a mismatch.

        Changed selectors reset the connection, also as a responder.
        """
        narrow = {"local": ["10.98.0.0/24"], "remote": ["10.99.0.0/24"]}
        with changed(RESPONDER_CONFIG, "traffic_selectors", narrow):
            # Negotiated anew: the responder narrows what the initiator proposes.
            child_sa_has(INITIATOR, "10.99.0.0/24 === 10.98.0.0/24 (narrowed from")
            child_sa_has(RESPONDER, "10.98.0.0/24 === 10.99.0.0/24 (as configured)")

            other = {"local": ["10.1.0.0/24"], "remote": ["10.2.0.0/24"]}
            with changed(INITIATOR_CONFIG, "traffic_selectors", other):
                diagnosed(INITIATOR, "TS_MISMATCH")
                details = diagnosed(RESPONDER, "TS_MISMATCH")["details"]
                # What the peer proposed, and what's configured here.
                assert details["received_local_ts"] == "10.2.0.0/24"
                assert details["received_remote_ts"] == "10.1.0.0/24"
                assert details["configured_local_ts"] == ["10.98.0.0/24"]
                assert details["configured_remote_ts"] == ["10.99.0.0/24"]
        # The responder's wider selectors apply once the initiator starts anew:
        # after the responder's reset it proposes the ones it had.
        conftest.run_cmd("end00", f"{VPNCTL} connections reset CORE-0")
        for side in BOTH:
            child_sa_has(side, "(as configured)")

    def test_no_response(self) -> None:
        """A peer that doesn't answer."""
        with changed(INITIATOR_CONFIG, "remote_addrs", ["192.0.2.250"]):
            silent = diagnosed(INITIATOR, "NO_RESPONSE")
            assert any("retransmit" in line for line in silent["evidence"])

    def test_stopped(self) -> None:
        """A stopped connection is disabled; its peer sees it was closed."""
        start = now("end00")
        conftest.run_cmd("end00", f"{VPNCTL} connections stop CORE-0")
        try:
            stopped = diagnosed(INITIATOR, "ADMIN_DOWN")
            assert "connections start CORE-0" in stopped["hint"]
            diagnosed(RESPONDER, "CLOSED_BY_PEER", "WAITING_FOR_PEER")
        finally:
            conftest.run_cmd("end00", f"{VPNCTL} connections start CORE-0")
        for side in BOTH:
            diagnosed(side, *WORKS)
        events = events_since(INITIATOR, start)
        assert events[:3] == ["ADMIN_DOWN", "OPER_DOWN", "ADMIN_UP"]
        assert events[-1] == "OPER_UP"

    def test_ssh_user(self) -> None:
        """An account the server doesn't let in."""
        with changed(SSH_CONFIG, "username", "nosuchuser", sides=(SSH,)):
            denied = diagnosed(SSH, "PERMISSION_DENIED")
            assert "Permission denied" in denied["details"]["said"]
            assert "ssh-setup" in denied["hint"]

    def test_wireguard_key(self) -> None:
        """A wrong public key: the peer's packets arrive, no handshake completes."""
        with changed(
            WIREGUARD_CONFIG,
            "public_key",
            OTHER_PUBLIC_KEY,
            sides=(WIREGUARD,),
        ):
            mismatch = diagnosed(WIREGUARD, "KEY_MISMATCH")
            packets = [
                c for c in mismatch["checks"] if c["name"] == "packets from peer"
            ]
            assert any(c["result"] == "OK" for c in packets)
