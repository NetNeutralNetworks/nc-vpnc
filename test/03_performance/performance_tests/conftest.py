"""Lab helpers used by this suite; see test/lab_helpers.py."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

# test/ holds lab_helpers.py. Add it explicitly so the suite also works when
# pytest is started from inside the suite directory.
TEST_DIR = str(Path(__file__).resolve().parents[2])
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)

from lab_helpers import (  # noqa: E402
    key_exchanges,
    nft_drop,
    run_cmd,
    run_cmd_shell,
    run_cmd_vtysh,
    wait_until,
    write_file,
)

# Measurements of the run, reported at its end.
MEASUREMENTS: list[str] = []


def measured(text: str) -> None:
    """Add a measurement to the report."""
    MEASUREMENTS.append(text)


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """Report the measurements."""
    if MEASUREMENTS:
        terminalreporter.section("measurements")
        for line in MEASUREMENTS:
            terminalreporter.line(line)


__all__ = [
    "key_exchanges",
    "nft_drop",
    "run_cmd",
    "run_cmd_shell",
    "run_cmd_vtysh",
    "wait_until",
    "write_file",
]
