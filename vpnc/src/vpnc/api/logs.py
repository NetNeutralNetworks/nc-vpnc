"""Log lines: vpnc's own (incl. SSH), vpncmangle's and charon's, also per connection.

The last lines are read from the end of the files, so a request doesn't read
whole logs. Following a log only reads what's appended.
"""

from __future__ import annotations

import asyncio
import datetime
import functools
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from vpnc import config

if TYPE_CHECKING:
    import pathlib
    from collections.abc import AsyncIterator, Iterator

LOG_DIR = config.LOG_DIR
VPNC_LOG = LOG_DIR / "vpnc.log"
# Written by charon, see config/strongswan/vpnc.conf.
CHARON_LOG = LOG_DIR / "charon.log"
VPNCMANGLE_LOG = LOG_DIR / "vpncmangle.log"
LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
Source = Literal["vpnc", "vpncmangle", "charon"]
Level = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# 11/11/2026 07:29:01 AM(File:vpnc,Line:1,func) - INFO - message
VPNC_LINE_RE = re.compile(
    r"^(\d\d/\d\d/\d{4} \d\d:\d\d:\d\d) [AP]M\(File:[^)]*\) - (\w+) - (.*)$",
)
# 2026-11-11 07:29:01 13[IKE] <C0001-00-0|5> message
CHARON_LINE_RE = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \d+\[(\w+)\] (?:<([^|>]+)\|\d+> )?(.*)$",
)

# Bytes read at a time from the end of a file.
BLOCK = 1 << 16
# Seconds between reads of a followed log.
FOLLOW_INTERVAL = 0.5
# Seconds without lines before an empty line is sent: a follower that left is
# only noticed when sending.
KEEPALIVE = 15


class LogLine(BaseModel):
    """A log line."""

    time: str
    source: str
    level: str
    message: str


@dataclass(frozen=True)
class Query:
    """The lines to return of a log file.

    A Python log (vpnc's or vpncmangle's) is selected by level and name_re; lines
    that don't start a message (tracebacks) are added to it. Charon's log, which
    has a subsystem instead of a level, is selected by its lines' IKE SA name.
    """

    path: pathlib.Path
    source: str
    level: str = "INFO"
    # Python log: the message must match.
    name_re: re.Pattern[str] | None = None
    # Charon's log: the regex the name of a line's IKE SA must match; also lines
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

    def python_line(self, match: re.Match[str], extra: list[str]) -> LogLine | None:
        """Return a Python log message (extra: its further lines), if selected."""
        level = match[2]
        if level in LEVELS and LEVELS.index(level) < LEVELS.index(self.level):
            return None
        message = "\n".join([match[3], *extra])
        if self.name_re is not None and not self.name_re.search(message):
            return None
        time = datetime.datetime.strptime(match[1], "%m/%d/%Y %H:%M:%S")
        return LogLine(
            time=time.isoformat(sep=" "),
            source=(
                # vpnc logs what ssh prints, with the connection's name.
                "ssh"
                if self.name_re is not None and message.startswith("SSH tunnel")
                else self.source
            ),
            level=level,
            message=message,
        )

    def charon_line(self, line: str) -> LogLine | None:
        """Return a line of charon's log, if selected."""
        if not (match := CHARON_LINE_RE.match(line)):
            return None
        message = match[4]
        if self.ike is None:
            message = (f"<{match[3]}> " if match[3] else "") + message
        elif not (
            self._ike_res[0].fullmatch(match[3] or "")
            or self._ike_res[1].search(message)
        ):
            return None
        return LogLine(
            time=match[1],
            source=self.source,
            level=match[2],
            message=message,
        )

    def parse(self, lines: list[str], previous: LogLine | None) -> list[LogLine]:
        """Return the selected lines of lines appended to the log, oldest first.

        previous is the last one returned before: a message's further lines can
        arrive later.
        """
        if self.charon:
            return [line for raw in lines if (line := self.charon_line(raw))]
        output: list[LogLine] = []
        start: re.Match[str] | None = None
        extra: list[str] = []
        for raw in [*lines, None]:
            match = VPNC_LINE_RE.match(raw) if raw is not None else None
            if raw is not None and match is None:
                if raw:
                    extra.append(raw)
                continue
            if start is not None:
                if line := self.python_line(start, extra):
                    output.append(line)
            elif extra and previous is not None:
                output.append(previous.model_copy(update={"message": "\n".join(extra)}))
            start, extra = match, []
        return output

    def last(self, count: int, end: int | None = None) -> list[LogLine]:
        """Return the last count selected lines, oldest first.

        Of the file up to end (bytes), and of its rotated files.
        """
        output: list[LogLine] = []
        extra: list[str] = []
        for raw in _reversed_lines(self.path, end):
            if len(output) >= count:
                break
            if self.charon:
                if line := self.charon_line(raw):
                    output.append(line)
            elif match := VPNC_LINE_RE.match(raw):
                if line := self.python_line(match, extra[::-1]):
                    output.append(line)
                extra = []
            elif raw:
                extra.append(raw)
        return output[::-1]


def _files(path: pathlib.Path) -> list[pathlib.Path]:
    """Return a log file and its rotated files, newest first."""
    # vpnc.log.1 etc.; compressed ones (charon.log.2.gz) are skipped.
    rotated = [
        p for p in path.parent.glob(f"{path.name}.*") if p.suffix[1:].isdigit()
    ]
    return [path, *sorted(rotated, key=lambda p: int(p.suffix[1:]))]


def _reversed_lines(path: pathlib.Path, end: int | None = None) -> Iterator[str]:
    """Yield the lines of a log and its rotated files, last first.

    Of the log itself only up to end (bytes), if given.
    """
    for file in _files(path):
        try:
            handle = file.open("rb")
        except (FileNotFoundError, IsADirectoryError):
            continue
        with handle:
            position = handle.seek(0, os.SEEK_END)
            if file == path and end is not None:
                position = min(position, end)
            rest = b""
            while position > 0:
                size = min(BLOCK, position)
                position -= size
                handle.seek(position)
                # The first line may start in the block before.
                rest, *lines = (handle.read(size) + rest).split(b"\n")
                for line in reversed(lines):
                    yield line.decode(errors="replace")
            yield rest.decode(errors="replace")


class Follower:
    """Read what's appended to a log, also when it's rotated or emptied."""

    def __init__(self, query: Query) -> None:
        """Start at the end of the log."""
        self.query = query
        self.inode: int | None = None
        self.offset = 0
        self.rest = b""
        self.previous: LogLine | None = None
        try:
            stat = query.path.stat()
        except FileNotFoundError:
            return
        self.inode, self.offset = stat.st_ino, stat.st_size

    def _read(self, path: pathlib.Path) -> bytes:
        try:
            with path.open("rb") as handle:
                handle.seek(self.offset)
                data = handle.read()
        except FileNotFoundError:
            return b""
        self.offset += len(data)
        return data

    def read(self) -> list[LogLine]:
        """Return the selected lines appended since the last read."""
        path = self.query.path
        try:
            stat = path.stat()
        except FileNotFoundError:
            return []
        data = b""
        if stat.st_ino != self.inode:
            # Rotated: first the rest of the file it was.
            rotated = path.with_name(f"{path.name}.1")
            if self.inode is not None and _inode(rotated) == self.inode:
                data = self._read(rotated)
            self.inode, self.offset = stat.st_ino, 0
        elif stat.st_size < self.offset:
            # Emptied (logrotate's copytruncate).
            self.offset, self.rest = 0, b""
        if stat.st_size > self.offset:
            data += self._read(path)
        if not data:
            return []
        *lines, self.rest = (self.rest + data).split(b"\n")
        output = self.query.parse(
            [line.decode(errors="replace") for line in lines],
            self.previous,
        )
        if output:
            self.previous = output[-1]
        return output


def _inode(path: pathlib.Path) -> int | None:
    try:
        return path.stat().st_ino
    except FileNotFoundError:
        return None


def _merge(lines: list[LogLine], count: int | None = None) -> list[LogLine]:
    # Stable: lines with the same time stay in order per source.
    merged = sorted(lines, key=lambda line: line.time)
    return merged if count is None else merged[-count:]


def last(queries: list[Query], count: int) -> list[LogLine]:
    """Return the last count lines of the logs together, oldest first."""
    return _merge([line for query in queries for line in query.last(count)], count)


async def follow(queries: list[Query], count: int) -> AsyncIterator[LogLine | None]:
    """Yield the last count lines of the logs, then the lines appended to them.

    None when there were none for KEEPALIVE seconds.
    """
    followers = [Follower(query) for query in queries]
    # Up to where the followers start, so no line is skipped or doubled.
    initial = await run_in_threadpool(
        lambda: _merge(
            [
                line
                for follower in followers
                for line in follower.query.last(count, follower.offset)
            ],
            count,
        ),
    )
    for line in initial:
        yield line
    idle = 0.0
    while True:
        await asyncio.sleep(FOLLOW_INTERVAL)
        lines = _merge([line for follower in followers for line in follower.read()])
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
    queries = [Query(VPNC_LOG, "vpnc", level, name_re)]
    if ipsec:
        queries.append(Query(CHARON_LOG, "charon", ike=re.escape(name)))
    return queries


def network_instance_queries(ni_id: str, *, level: Level) -> list[Query]:
    """Return the queries for the lines of a network instance and its connections."""
    # C0001-00, C0001-00-1, C0001-00_C, wg-C0001-00-1; not C0001-001.
    name_re = re.compile(rf"(?<![\w]){re.escape(ni_id)}(?!\d)")
    return [
        Query(VPNC_LOG, "vpnc", level, name_re),
        # Its IKE SAs are named after it, e.g. C0001-00-0.
        Query(CHARON_LOG, "charon", ike=rf"{re.escape(ni_id)}-\d+"),
    ]


def daemon_queries(source: Source, level: Level) -> list[Query]:
    """Return the query for vpnc's, vpncmangle's or charon's log."""
    path = {"vpnc": VPNC_LOG, "vpncmangle": VPNCMANGLE_LOG, "charon": CHARON_LOG}
    return [Query(path[source], source, level)]
