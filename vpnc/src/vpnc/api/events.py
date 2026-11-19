"""The event history, read from the journal: all, or of one subject."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from vpnc import eventlog
from vpnc.api import logs


class Event(BaseModel):
    """Something that happened to a connection, network instance or tenant."""

    time: str
    # E.g. OPER_DOWN.
    event: str
    # What it happened to, with what that's part of; the service is DEFAULT.
    tenant: str | None
    network_instance: str | None
    connection: str | None
    message: str
    details: dict[str, Any]


@dataclass(frozen=True)
class Query:
    """The events to return: of a tenant, network instance or connection, or all."""

    tenant: str | None = None
    network_instance: str | None = None
    connection: str | None = None
    event: str | None = None
    # Not older than this many seconds.
    since: int | None = None

    def entries(self, *args: str) -> list[logs.Entry]:
        """Return the events' journal entries, oldest first."""
        fields = {
            "MESSAGE_ID": eventlog.MESSAGE_ID,
            "VPNC_TENANT": self.tenant,
            "VPNC_NETWORK_INSTANCE": self.network_instance,
            "VPNC_CONNECTION": self.connection,
            "VPNC_EVENT": self.event,
        }
        matches = [f"{field}={value}" for field, value in fields.items() if value]
        since = [f"--since=-{self.since}s"] if self.since else []
        return logs.journal(*matches, *since, *args)

    def selected(self, entries: list[logs.Entry]) -> list[tuple[int, Event]]:
        """Return entries as events with their seqnum."""
        return [(logs.seqnum(entry), _event(entry)) for entry in entries]

    def last(self, count: int) -> list[tuple[int, Event]]:
        """Return the last count events with their seqnum, oldest first."""
        return self.selected(self.entries(f"--lines={count}"))


def _event(entry: logs.Entry) -> Event:
    subject = [
        entry.get(field)
        for field in ("VPNC_TENANT", "VPNC_NETWORK_INSTANCE", "VPNC_CONNECTION")
    ]
    name = next((item for item in reversed(subject) if item), "vpnc")
    try:
        details = json.loads(entry.get("VPNC_DETAILS") or "{}")
    except ValueError:
        details = {}
    return Event(
        time=logs.local_time(entry).isoformat(timespec="seconds"),
        event=str(entry.get("VPNC_EVENT", "")),
        tenant=subject[0],
        network_instance=subject[1],
        connection=subject[2],
        message=logs.message_of(entry).removeprefix(f"{name}: "),
        details=details if isinstance(details, dict) else {},
    )
