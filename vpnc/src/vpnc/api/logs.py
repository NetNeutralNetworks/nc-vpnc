"""Log lines: vpnc's own (incl. SSH), vpncmangle's and charon's, also per connection."""

from __future__ import annotations

import collections
import datetime
import pathlib
import re
from collections.abc import Iterator
from typing import Literal

from pydantic import BaseModel

LOG_DIR = pathlib.Path("/var/log/ncubed/vpnc")
VPNC_LOG = LOG_DIR / "vpnc.log"
# Written by charon, see config/strongswan/vpnc.conf.
CHARON_LOG = LOG_DIR / "charon.log"
VPNCMANGLE_LOG = LOG_DIR / "vpncmangle.log"
LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
Source = Literal["vpnc", "vpncmangle", "charon"]
Level = Literal["debug", "info", "warning", "error", "critical"]

# 11/11/2026 07:29:01 AM(File:vpnc,Line:1,func) - INFO - message
VPNC_LINE_RE = re.compile(
    r"^(\d\d/\d\d/\d{4} \d\d:\d\d:\d\d) [AP]M\(File:[^)]*\) - (\w+) - (.*)$",
)
# 2026-11-11 07:29:01 13[IKE] <C0001-00-0|5> message
CHARON_LINE_RE = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \d+\[(\w+)\] (?:<([^|>]+)\|\d+> )?(.*)$",
)


class LogLine(BaseModel):
    """A log line."""

    time: str
    source: str
    level: str
    message: str


def _files(path: pathlib.Path) -> list[pathlib.Path]:
    """Return a log file and its rotated files, oldest first."""
    # vpnc.log.1 etc.; compressed ones (charon.log.2.gz) are skipped.
    rotated = [
        p for p in path.parent.glob(f"{path.name}.*") if p.suffix[1:].isdigit()
    ]
    return [*sorted(rotated, key=lambda p: int(p.suffix[1:]), reverse=True), path]


def _lines(path: pathlib.Path) -> Iterator[str]:
    for file in _files(path):
        try:
            with file.open(encoding="utf-8", errors="replace") as handle:
                yield from handle
        except (FileNotFoundError, IsADirectoryError):
            continue


def _python_log(path: pathlib.Path, source: str, level: str) -> Iterator[LogLine]:
    """Yield a Python log's lines; lines that don't start one (tracebacks) are added."""
    minimum = LEVELS.index(level.upper())
    current: LogLine | None = None
    for line in _lines(path):
        line = line.rstrip("\n")
        if match := VPNC_LINE_RE.match(line):
            if current is not None:
                yield current
            current = None
            if match[2] in LEVELS and LEVELS.index(match[2]) < minimum:
                continue
            time = datetime.datetime.strptime(match[1], "%m/%d/%Y %H:%M:%S")
            current = LogLine(
                time=time.isoformat(sep=" "),
                source=source,
                level=match[2],
                message=match[3],
            )
        elif current is not None and line:
            current.message += "\n" + line
    if current is not None:
        yield current


def _vpnc(name_re: re.Pattern[str], level: str, count: int) -> list[LogLine]:
    output: collections.deque[LogLine] = collections.deque(maxlen=count)
    for line in _python_log(VPNC_LOG, "vpnc", level):
        if name_re.search(line.message):
            if line.message.startswith("SSH tunnel"):
                line.source = "ssh"
            output.append(line)
    return list(output)


def _charon(ike: str, count: int) -> list[LogLine]:
    """Return charon's lines of IKE SAs whose name matches ike (a regex).

    Also lines naming them in quotes, e.g. no config found for 'C0001-00-0'.
    """
    ike_re = re.compile(ike)
    quoted_re = re.compile(f"'{ike}'")
    output: collections.deque[LogLine] = collections.deque(maxlen=count)
    for line in _lines(CHARON_LOG):
        match = CHARON_LINE_RE.match(line.rstrip("\n"))
        if match and (
            ike_re.fullmatch(match[3] or "") or quoted_re.search(match[4])
        ):
            output.append(
                LogLine(
                    time=match[1],
                    source="charon",
                    level=match[2],
                    message=match[4],
                ),
            )
    return list(output)


def _merge(lines: list[LogLine], count: int) -> list[LogLine]:
    # Stable: lines with the same time stay in order per source.
    return sorted(lines, key=lambda line: line.time)[-count:]


def connection_logs(
    name: str,
    *,
    ipsec: bool,
    level: Level = "info",
    count: int,
) -> list[LogLine]:
    """Return the last log lines of a connection (e.g. C0001-00-0), oldest first."""
    # C0001-00-1 but not C0001-00-10; also in names like wg-C0001-00-1.
    name_re = re.compile(rf"(?<![\w]){re.escape(name)}(?![\w])")
    lines = _vpnc(name_re, level, count)
    if ipsec:
        lines += _charon(re.escape(name), count)
    return _merge(lines, count)


def network_instance_logs(ni_id: str, *, level: Level, count: int) -> list[LogLine]:
    """Return the last log lines of a network instance and its connections."""
    # C0001-00, C0001-00-1, C0001-00_C, wg-C0001-00-1; not C0001-001.
    name_re = re.compile(rf"(?<![\w]){re.escape(ni_id)}(?!\d)")
    lines = _vpnc(name_re, level, count)
    # Its IKE SAs are named after it, e.g. C0001-00-0.
    lines += _charon(rf"{re.escape(ni_id)}-\d+", count)
    return _merge(lines, count)


def daemon_logs(source: Source, level: Level, count: int) -> list[LogLine]:
    """Return the last lines of vpnc's, vpncmangle's or charon's log."""
    output: collections.deque[LogLine] = collections.deque(maxlen=count)
    if source == "charon":
        for line in _lines(CHARON_LOG):
            if match := CHARON_LINE_RE.match(line.rstrip("\n")):
                name = f"<{match[3]}> " if match[3] else ""
                output.append(
                    LogLine(
                        time=match[1],
                        source=source,
                        level=match[2],
                        message=name + match[4],
                    ),
                )
    else:
        path = VPNC_LOG if source == "vpnc" else VPNCMANGLE_LOG
        output.extend(_python_log(path, source, level))
    return list(output)
