"""Log lines: vpnc's own (incl. SSH), vpncmangle's and charon's, also per connection.

All three log to the journal, read with journalctl: a request reads only the
last lines, a follower only what's added.
"""

from __future__ import annotations

import asyncio
import datetime
import functools
import json
import re
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
# Each source is also its journal's SYSLOG_IDENTIFIER.
Source = Literal["vpnc", "vpncmangle", "charon"]
Level = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
# Python's levels as syslog priorities, and back.
PRIORITIES = {"DEBUG": 7, "INFO": 6, "WARNING": 4, "ERROR": 3, "CRITICAL": 2}
LEVEL_NAMES = {7: "DEBUG", 6: "INFO", 5: "INFO", 4: "WARNING", 3: "ERROR"}

# Charon's messages: thread, subsystem, IKE SA, e.g. 13[IKE] <C0001-00-0|5> text
CHARON_LINE_RE = re.compile(r"^\d+\[(\w+)\] (?:<([^|>]+)\|\d+> )?(.*)$", re.DOTALL)

# Seconds a journalctl run may take.
JOURNALCTL_TIMEOUT = 10
# Seconds between reads of a followed log.
FOLLOW_INTERVAL = 0.5
# Seconds without lines before an empty line is sent: a follower that left is
# only noticed when sending.
KEEPALIVE = 15

Entry = dict[str, Any]


class LogLine(BaseModel):
    """A log line."""

    time: str
    source: str
    level: str
    message: str


def journal(*args: str) -> list[Entry]:
    """Return journal entries, oldest first."""
    command = ["journalctl", "--no-pager", "--output=json", *args]
    try:
        result = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=JOURNALCTL_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    entries = [json.loads(line) for line in result.stdout.splitlines() if line]
    # With --grep and --lines, journalctl gives the newest first.
    return sorted(entries, key=_seqnum)


def _seqnum(entry: Entry) -> int:
    return int(entry.get("__SEQNUM", 0))


def _message(entry: Entry) -> str:
    # journalctl gives a message that isn't UTF-8 as a list of bytes.
    message = entry.get("MESSAGE", "")
    if isinstance(message, list):
        return bytes(cast("list[int]", message)).decode(errors="replace")
    return str(message)


def _time(entry: Entry) -> str:
    """Return an entry's local time, e.g. 2026-11-11 07:29:01."""
    seconds = int(entry["__REALTIME_TIMESTAMP"]) / 1e6
    time = datetime.datetime.fromtimestamp(seconds, datetime.UTC).astimezone()
    return time.strftime("%Y-%m-%d %H:%M:%S")


@dataclass(frozen=True)
class Query:
    """The lines to return of a source.

    vpnc's and vpncmangle's lines are selected by level and name_re. Charon's,
    which have a subsystem instead of a level, by their IKE SA's name.
    """

    source: Source
    level: str = "INFO"
    # vpnc and vpncmangle: the message must match.
    name_re: re.Pattern[str] | None = None
    # Charon: the regex the name of a line's IKE SA must match; also lines
    # naming it in quotes, e.g. no config found for 'C0001-00-0'. None: all
    # lines, with the name of their IKE SA.
    ike: str | None = None

    @property
    def charon(self) -> bool:
        """Return whether this is charon's log."""
        return self.source == "charon"

    @functools.cached_property
    def _ike_res(self) -> tuple[re.Pattern[str], re.Pattern[str]]:
        return re.compile(self.ike or ""), re.compile(f"'{self.ike}'")

    def entries(self, *args: str) -> list[Entry]:
        """Return the source's journal entries, oldest first; line() selects."""
        filters = [f"--identifier={self.source}"]
        if self.charon:
            if self.ike is not None:
                filters.append(f"--grep=<({self.ike})\\||'({self.ike})'")
        else:
            filters.append(f"--priority={PRIORITIES[self.level]}")
            if self.name_re is not None:
                filters.append(f"--grep={self.name_re.pattern}")
        return journal(*filters, *args)

    def line(self, entry: Entry) -> LogLine | None:
        """Return an entry as a line, if selected."""
        message = _message(entry)
        if self.charon:
            return self._charon_line(entry, message)
        if self.name_re is not None and not self.name_re.search(message):
            return None
        return LogLine(
            time=_time(entry),
            source=(
                # vpnc logs what ssh prints, with the connection's name.
                "ssh"
                if self.name_re is not None and message.startswith("SSH tunnel")
                else self.source
            ),
            level=LEVEL_NAMES.get(int(entry.get("PRIORITY", 6)), "CRITICAL"),
            message=message,
        )

    def _charon_line(self, entry: Entry, message: str) -> LogLine | None:
        if not (match := CHARON_LINE_RE.match(message)):
            return None
        message = match[3]
        if self.ike is None:
            message = (f"<{match[2]}> " if match[2] else "") + message
        elif not (
            self._ike_res[0].fullmatch(match[2] or "")
            or self._ike_res[1].search(message)
        ):
            return None
        return LogLine(
            time=_time(entry),
            source=self.source,
            level=match[1],
            message=message,
        )

    def last(self, count: int) -> list[tuple[int, LogLine]]:
        """Return the last count selected lines with their seqnum, oldest first."""
        return self.selected(self.entries(f"--lines={count}"))

    def selected(self, entries: list[Entry]) -> list[tuple[int, LogLine]]:
        """Return the selected lines of entries with their seqnum."""
        return [(_seqnum(e), line) for e in entries if (line := self.line(e))]


def _merge(
    lines: list[tuple[int, LogLine]],
    count: int | None = None,
) -> list[LogLine]:
    """Return the lines of several queries in journal order, the last count."""
    merged = [line for _, line in sorted(lines, key=lambda pair: pair[0])]
    return merged if count is None else merged[-count:]


def last(queries: list[Query], count: int) -> list[LogLine]:
    """Return the last count lines of the logs together, oldest first."""
    return _merge([line for query in queries for line in query.last(count)], count)


class Follower:
    """Read what's added to the journal for a query."""

    def __init__(self, query: Query, cursor: str | None) -> None:
        """Start after cursor; None: at the journal's start."""
        self.query = query
        self.cursor = cursor

    def read(self) -> list[tuple[int, LogLine]]:
        """Return the selected lines added since the last read."""
        after = [f"--after-cursor={self.cursor}"] if self.cursor else []
        entries = self.query.entries(*after)
        if entries:
            self.cursor = str(entries[-1]["__CURSOR"])
        return self.query.selected(entries)


def _start(queries: list[Query], count: int) -> tuple[list[Follower], list[LogLine]]:
    """Return followers from the journal's end, and the last count lines up to it."""
    tail = journal("--lines=1")
    cursor = str(tail[-1]["__CURSOR"]) if tail else None
    end = _seqnum(tail[-1]) if tail else -1
    lines = [
        pair for query in queries for pair in query.last(count) if pair[0] <= end
    ]
    return [Follower(query, cursor) for query in queries], _merge(lines, count)


async def follow(queries: list[Query], count: int) -> AsyncIterator[LogLine | None]:
    """Yield the last count lines of the logs, then the lines added to them.

    None when there were none for KEEPALIVE seconds.
    """
    # Up to where the followers start, so no line is skipped or doubled.
    followers, initial = await run_in_threadpool(lambda: _start(queries, count))
    for line in initial:
        yield line
    idle = 0.0
    while True:
        await asyncio.sleep(FOLLOW_INTERVAL)
        lines = await run_in_threadpool(
            lambda: _merge([line for f in followers for line in f.read()]),
        )
        for line in lines:
            yield line
        idle = 0.0 if lines else idle + FOLLOW_INTERVAL
        if idle >= KEEPALIVE:
            idle = 0.0
            yield None


def connection_queries(name: str, *, ipsec: bool, level: Level) -> list[Query]:
    """Return the queries for the log lines of a connection (e.g. C0001-00-0)."""
    # C0001-00-1 but not C0001-00-10; also in names like wg-C0001-00-1.
    name_re = re.compile(rf"(?<![\w]){re.escape(name)}(?![\w])")
    queries = [Query("vpnc", level, name_re)]
    if ipsec:
        queries.append(Query("charon", ike=re.escape(name)))
    return queries


def network_instance_queries(ni_id: str, *, level: Level) -> list[Query]:
    """Return the queries for the lines of a network instance and its connections."""
    # C0001-00, C0001-00-1, C0001-00_C, wg-C0001-00-1; not C0001-001.
    name_re = re.compile(rf"(?<![\w]){re.escape(ni_id)}(?!\d)")
    return [
        Query("vpnc", level, name_re),
        # Its IKE SAs are named after it, e.g. C0001-00-0.
        Query("charon", ike=rf"{re.escape(ni_id)}-\d+"),
    ]


def daemon_queries(source: Source, level: Level) -> list[Query]:
    """Return the query for vpnc's, vpncmangle's or charon's log."""
    return [Query(source, level)]
