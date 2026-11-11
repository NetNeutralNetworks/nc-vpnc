"""The log lines of a connection, from vpnc's log (incl. SSH) and charon's log."""

from __future__ import annotations

import collections
import datetime
import pathlib
import re
from collections.abc import Iterator

from pydantic import BaseModel

LOG_DIR = pathlib.Path("/var/log/ncubed/vpnc")
VPNC_LOG = LOG_DIR / "vpnc.log"
# Written by charon, see config/strongswan/vpnc.conf.
CHARON_LOG = LOG_DIR / "charon.log"

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


def _vpnc(name_re: re.Pattern[str], count: int) -> list[LogLine]:
    output: collections.deque[LogLine] = collections.deque(maxlen=count)
    for line in _lines(VPNC_LOG):
        if (match := VPNC_LINE_RE.match(line.rstrip("\n"))) and name_re.search(
            match[3],
        ):
            time = datetime.datetime.strptime(match[1], "%m/%d/%Y %H:%M:%S")
            output.append(
                LogLine(
                    time=time.isoformat(sep=" "),
                    source="ssh" if match[3].startswith("SSH tunnel") else "vpnc",
                    level=match[2],
                    message=match[3],
                ),
            )
    return list(output)


def _charon(name: str, count: int) -> list[LogLine]:
    output: collections.deque[LogLine] = collections.deque(maxlen=count)
    for line in _lines(CHARON_LOG):
        match = CHARON_LINE_RE.match(line.rstrip("\n"))
        if match and (match[3] == name or f"'{name}'" in match[4]):
            output.append(
                LogLine(
                    time=match[1],
                    source="charon",
                    level=match[2],
                    message=match[4],
                ),
            )
    return list(output)


def connection_logs(name: str, *, ipsec: bool, count: int) -> list[LogLine]:
    """Return the last log lines of a connection (e.g. C0001-00-0), oldest first."""
    # C0001-00-1 but not C0001-00-10; also in names like wg-C0001-00-1.
    name_re = re.compile(rf"(?<![\w]){re.escape(name)}(?![\w])")
    lines = _vpnc(name_re, count)
    if ipsec:
        lines += _charon(name, count)
    # Stable: lines with the same time stay in order per source.
    return sorted(lines, key=lambda line: line.time)[-count:]
