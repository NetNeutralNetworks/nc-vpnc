"""Why connections fail: the last reason per connection, noted as it happens.

The reason comes from what charon or ssh reports (see the strongSwan monitor and
the SSH tunnel). A new reason is an event; repeats of it are only counted, as a
failing connection retries forever. Its details don't make it new, and a reason
is an event again only after a while: anyone who can send from a peer's address
chooses both.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from vpnc import eventlog

# What a reason means, for the event and vpnctl connections diagnose.
REASONS = {
    "NO_RESPONSE": "the peer doesn't answer",
    "NO_RESPONSE_AUTH": "the peer answers at first, but not the authentication",
    "DPD_TIMEOUT": "the peer stopped answering (dead peer detection)",
    "CLOSED_BY_PEER": "the peer closed the session",
    "REJECTED_BY_PEER": "the peer refused the IKE SA",
    "CHILD_REJECTED_BY_PEER": "the peer refused the IPsec (child) SA",
    "AUTH_FAILED_REMOTE": "the peer rejected our authentication (PSK, PPK or our id)",
    "AUTH_FAILED_LOCAL": "the peer's authentication failed here: PSKs or PPKs differ",
    "ID_MISMATCH": "no connection here has the ids the peer uses",
    "PPK_MISMATCH": "only one side uses a PPK, or the PPK ids differ",
    "IKE_PROPOSAL_MISMATCH": "no IKE proposal in common",
    "CHILD_PROPOSAL_MISMATCH": "no IPsec (ESP) proposal in common",
    "TS_MISMATCH": "the traffic selectors don't overlap",
    "IKE_VERSION_MISMATCH": "the peer uses another IKE version",
    "IKE_CONFIG_MISMATCH": "the peer's address and IKE version fit no connection here",
    "AUTH_METHOD_MISMATCH": "the peer doesn't authenticate with a PSK",
    "KERNEL_FAILED": "the kernel refused the IPsec SA or its policy",
    "UNREACHABLE": "the server can't be reached from here: no route or source address",
    "PERMISSION_DENIED": "the server rejected our key or username",
    "HOST_KEY_MISMATCH": "the server's host key isn't the one known for it",
    "REFUSED": "the server refuses connections on the port",
    "NEGOTIATION_FAILED": "no algorithm in common with the server",
    "TUNNEL_REFUSED": "the server refused the tunnel (PermitTunnel, or its tun in use)",
    "EXITED": "ssh exited",
}
# Lines kept as evidence.
EVIDENCE = 8


@dataclass
class Failure:
    """Why a connection failed last, and since when it keeps failing so."""

    reason: str
    details: dict[str, Any]
    # Unix times.
    first: float
    last: float
    count: int = 1
    # What was reported, e.g. charon's lines.
    evidence: list[str] = field(default_factory=list)

    @property
    def message(self) -> str:
        """Return what the reason means."""
        return REASONS.get(self.reason, self.reason)


# By connection name; forgotten once the connection is up.
CURRENT: dict[str, Failure] = {}
# The connections that are up, as last seen.
UP: set[str] = set()
# Why a connection that's still up is about to go down.
WHILE_UP = ("DPD_TIMEOUT", "CLOSED_BY_PEER")
# Noted while the connection was last seen up: its failure if it's down within
# PENDING_SECONDS (a full check), forgotten if it's still up after SETTLE.
PENDING: dict[str, Failure] = {}
PENDING_SECONDS = 35
SETTLE = 2
# Seconds before a reason is an event of a connection again, unless it was set
# up in between.
EVENT_INTERVAL = 600
# When a connection's reasons were last an event.
RECORDED: dict[str, dict[str, float]] = {}
_LOCK = threading.Lock()


def _keep(name: str, failure: Failure) -> bool:
    """Make a failure the connection's last (lock held); return whether it's an event."""
    current = CURRENT.get(name)
    if current and current.reason == failure.reason:
        # The latest details: what diagnose shows.
        current.details, current.evidence = failure.details, failure.evidence
        current.last = failure.last
        current.count += 1
        return False
    CURRENT[name] = failure
    recorded = RECORDED.setdefault(name, {})
    if failure.last - recorded.get(failure.reason, 0) < EVENT_INTERVAL:
        return False
    recorded[failure.reason] = failure.last
    return True


def _record(name: str, failure: Failure) -> None:
    said = f": {failure.details['said']}" if "said" in failure.details else ""
    eventlog.record(
        failure.reason,
        failure.message + said,
        connection=name,
        level=logging.WARNING,
        **failure.details,
    )


def note(
    name: str,
    reason: str,
    evidence: list[str] | None = None,
    **details: object,
) -> None:
    """Note why a connection just failed; an event if it's not the same again.

    While it's up only once it goes down: it may be a second try next to the
    one that succeeded.
    """
    now = time.time()
    failure = Failure(reason, details, now, now, evidence=(evidence or [])[-EVIDENCE:])
    with _LOCK:
        if name in UP and reason not in WHILE_UP:
            PENDING[name] = failure
            return
        new = _keep(name, failure)
    if new:
        _record(name, failure)


def clear(name: str) -> None:
    """Forget a connection's failure: it's set up."""
    with _LOCK:
        CURRENT.pop(name, None)
        PENDING.pop(name, None)
        RECORDED.pop(name, None)


def seen(name: str, *, up: bool) -> None:
    """Take whether a connection is up now; one that is hasn't failed."""
    now = time.time()
    failed = None
    with _LOCK:
        pending = PENDING.get(name)
        if up:
            UP.add(name)
            CURRENT.pop(name, None)
            RECORDED.pop(name, None)
            if pending and now - pending.last > SETTLE:
                del PENDING[name]
            return
        UP.discard(name)
        if pending:
            del PENDING[name]
            if now - pending.last <= PENDING_SECONDS and _keep(name, pending):
                failed = pending
    if failed:
        _record(name, failed)


def keep(names: set[str]) -> None:
    """Forget the failures of connections that aren't among names."""
    with _LOCK:
        for failed in (CURRENT, PENDING, RECORDED):
            for name in failed.keys() - names:
                del failed[name]
        UP.intersection_update(names)


def get(name: str) -> Failure | None:
    """Return why a connection failed last, if it did since it was set up."""
    with _LOCK:
        return CURRENT.get(name)
