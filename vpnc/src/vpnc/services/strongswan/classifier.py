"""Tell why an IKE or child SA wasn't set up, from charon's log lines.

Fed the lines of the IKE and CFG subsystems, per IKE SA. Lines before a
failure give its details: the peer, the ids and what each side proposed. vici
can send charon's lines out of order, so details after a failure update it.
"""

from __future__ import annotations

import re
from collections import OrderedDict, deque
from dataclasses import dataclass, field

# IKE SAs remembered: those being set up.
CONTEXTS = 2048
# The lines of an IKE SA kept as evidence.
LINES = 8

# What a line tells about its IKE SA (the named groups), and the failure it is.
DETAILS = [
    (re.compile(r"^(?P<peer>\S+) is initiating an IKE_SA"), None),
    (re.compile(r"^initiating IKE_SA \S+ to (?P<peer>\S+)"), None),
    (re.compile(r"^IKE_SA \S+ (?P<established>established) between"), None),
    (re.compile(r"^(?P<deleting>deleting) IKE_SA"), None),
    (re.compile(r"^received proposals: (?P<received_proposals>.+)"), None),
    (re.compile(r"^configured proposals: (?P<configured_proposals>.+)"), None),
    (
        # The ids the peer uses: the one it expects of us, and its own.
        re.compile(
            r"^looking for peer configs matching \S+\[(?P<requested_local_id>.*)\]"
            r"\.\.\.(?P<peer>\S+)\[(?P<received_remote_id>.*)\]$",
        ),
        None,
    ),
    (re.compile(r"^authentication of '(?P<sent_local_id>.*)' \(myself\)"), None),
    (
        # The peer answered with another id than remote_id.
        re.compile(
            r"^IDir '(?P<received_remote_id>.*)' does not match to "
            r"'(?P<expected_remote_id>.*)'",
        ),
        "ID_MISMATCH",
    ),
    (
        # What the peer proposed, as charon narrowed it to ours: local === remote.
        re.compile(
            r"^traffic selectors (?P<received_local_ts>.*) === "
            r"(?P<received_remote_ts>.*) (?:un|in)acceptable",
        ),
        "TS_MISMATCH",
    ),
    (re.compile(r"^received AUTHENTICATION_FAILED notify"), "AUTH_FAILED_REMOTE"),
    (re.compile(r"^received NO_PROPOSAL_CHOSEN notify error"), "IKE_PROPOSAL_MISMATCH"),
    (re.compile(r"^received proposals unacceptable"), "IKE_PROPOSAL_MISMATCH"),
    (
        re.compile(r"^received NO_PROPOSAL_CHOSEN notify, no CHILD_SA built"),
        "CHILD_PROPOSAL_MISMATCH",
    ),
    # Of the IKE SA or a child SA: see the proposals before it.
    (re.compile(r"^no acceptable proposal found"), "PROPOSAL_MISMATCH"),
    (re.compile(r"^no matching peer config found"), "ID_MISMATCH"),
    (re.compile(r"but MAC mismatched|^no shared key found for"), "AUTH_FAILED_LOCAL"),
    (
        re.compile(r"constraint check failed|^no trusted .* public key"),
        "AUTH_METHOD_MISMATCH",
    ),
    (re.compile(r"^received TS_UNACCEPTABLE notify"), "TS_MISMATCH"),
    (re.compile(r"PPK.*(?:required|not found|didn't use)|no PPK"), "PPK_MISMATCH"),
    (re.compile(r"^received INVALID_MAJOR_VERSION notify"), "IKE_VERSION_MISMATCH"),
    (
        re.compile(r"^no IKE config found for \S+\.\.\.(?P<peer>\S+),"),
        "IKE_CONFIG_MISMATCH",
    ),
    (
        re.compile(r"unable to install .* in kernel|^unable to (?:add|install) "),
        "KERNEL_FAILED",
    ),
    (re.compile(r"^received DELETE for IKE_SA"), "CLOSED_BY_PEER"),
    # Which request isn't answered tells what: see _unanswered().
    (
        re.compile(r"^retransmit [3-9] of request with message ID (?P<message_id>\d+)"),
        "NO_RESPONSE",
    ),
    (
        re.compile(r"^giving up after \d+ retransmits|peer not responding"),
        "NO_RESPONSE",
    ),
    # Anything else the peer refuses with.
    (re.compile(r"^received (?P<notify>[A-Z_]+) notify error"), "REJECTED_BY_PEER"),
    (
        re.compile(r"^received (?P<notify>[A-Z_]+) notify, no CHILD_SA built"),
        "CHILD_REJECTED_BY_PEER",
    ),
]
# The details that say something about a failure.
RELEVANT = {
    "AUTH_FAILED_REMOTE": ("sent_local_id",),
    "AUTH_FAILED_LOCAL": ("requested_local_id", "received_remote_id"),
    "ID_MISMATCH": ("requested_local_id", "received_remote_id", "expected_remote_id"),
    "REJECTED_BY_PEER": ("notify",),
    "CHILD_REJECTED_BY_PEER": ("notify",),
    "IKE_PROPOSAL_MISMATCH": ("received_proposals", "configured_proposals"),
    "CHILD_PROPOSAL_MISMATCH": ("received_proposals", "configured_proposals"),
    "TS_MISMATCH": ("received_local_ts", "received_remote_ts"),
}
# A child SA is set up: the connection works.
ESTABLISHED = re.compile(r"CHILD_SA \S+ established")


def _unanswered(known: dict[str, str]) -> str:
    """Return what it means that the peer doesn't answer, by the request it's about."""
    if "established" in known:
        # It did answer before: dead peer detection, or a rekey.
        return "DPD_TIMEOUT"
    # The first request (IKE_SA_INIT) is answered, a later one (IKE_AUTH) isn't.
    return "NO_RESPONSE" if known.get("message_id", "0") == "0" else "NO_RESPONSE_AUTH"


def _precise(reason: str, known: dict[str, str]) -> str | None:
    """Return the reason more precisely, by what's known of the IKE SA; None: none."""
    if reason == "NO_RESPONSE":
        # A delete that isn't answered: the SA is gone either way.
        return None if "deleting" in known else _unanswered(known)
    if reason == "PROPOSAL_MISMATCH":
        child = known.get("received_proposals", "").startswith("ESP")
        return "CHILD_PROPOSAL_MISMATCH" if child else "IKE_PROPOSAL_MISMATCH"
    return reason


def _details(reason: str, known: dict[str, str]) -> dict[str, str]:
    """Return what's known of an IKE SA that says something about its failure."""
    details = {k: known[k] for k in RELEVANT.get(reason, ()) if k in known}
    kind = "ESP" if reason.startswith("CHILD") else "IKE"
    if "PROPOSAL" in reason and not all(p.startswith(kind) for p in details.values()):
        # Of another step, e.g. the IKE SA's while a child SA failed.
        return {}
    return details


@dataclass
class Context:
    """What's known of an IKE SA that's being set up."""

    details: dict[str, str] = field(default_factory=dict)
    lines: deque[str] = field(default_factory=lambda: deque(maxlen=LINES))
    # The failure of its last failure line, and the details reported for it;
    # None: not reported for a connection (no name or peer known yet).
    failure: str | None = None
    noted: dict[str, str] | None = None


@dataclass
class Result:
    """What a line means for its connection: it failed (reason), or it's set up."""

    # The connection as charon names it; None: an SA of the peer, not yet named.
    name: str | None
    peer: str | None
    # None: set up.
    reason: str | None
    details: dict[str, str]
    lines: list[str]
    # New details of the failure reported before.
    update: bool = False


class Classifier:
    """Follow charon's lines per IKE SA and report failures and set up connections."""

    def __init__(self) -> None:
        """Start without IKE SAs."""
        self.contexts: OrderedDict[str, Context] = OrderedDict()

    def _context(self, key: str) -> Context:
        if (context := self.contexts.get(key)) is None:
            context = self.contexts[key] = Context()
            if len(self.contexts) > CONTEXTS:
                self.contexts.popitem(last=False)
        return context

    def feed(self, name: str | None, sa_id: str | None, line: str) -> Result | None:
        """Take a line of an IKE SA (its name and unique id); return what it means."""
        if name == "(unnamed)":
            name = None
        key = sa_id or name
        if key is None:
            return None
        context = self._context(key)
        context.lines.append(line)
        if name and ESTABLISHED.search(line):
            context.lines.clear()
            context.failure = context.noted = None
            return Result(name, None, None, {}, [])
        reason = None
        for pattern, failure in DETAILS:
            if match := pattern.search(line):
                context.details.update(
                    {k: v for k, v in match.groupdict().items() if v is not None},
                )
                reason = failure
                break
        known = context.details
        late = reason is None
        if late:
            if context.failure is None:
                return None
            reason = context.failure
        else:
            context.failure = reason
        if (reason := _precise(reason, known)) is None:
            return None
        details = _details(reason, known)
        if late and details == context.noted:
            return None
        update = late and context.noted is not None
        context.noted = details if name or "peer" in known else None
        return Result(
            name,
            known.get("peer"),
            reason,
            details,
            list(context.lines),
            update=update,
        )
