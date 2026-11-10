"""Test the strongSwan connections."""

from __future__ import annotations

import re

import pytest

from . import conftest

# Expected IPsec connections per node (end01 uses WireGuard only).
TESTDATA_CONNECTIONS = [
    ("hub00", {"CORE-0", "CORE-1", "C0001-00-0"}),
    ("hub01", {"CORE-0", "CORE-1", "C0001-00-0"}),
    ("end00", {"CORE-0", "CORE-1"}),
    ("end01", set()),
]

# "<name>: #<id>, <state>, " in swanctl --list-sas.
SA_RE = re.compile(r"^(\S+): #\d+, (\w+), ")


def get_established_connections(host: str) -> set[str]:
    """Return the connections that have an established IKE SA."""
    output = conftest.run_cmd_shell(host, "swanctl --list-sas 2>/dev/null")
    return {
        match.group(1)
        for line in output.splitlines()
        if (match := SA_RE.match(line)) and match.group(2) == "ESTABLISHED"
    }


class TestConnections:
    """IPsec connections."""

    @pytest.mark.parametrize(("host", "expected"), TESTDATA_CONNECTIONS)
    def test_connections_established(self, host: str, expected: set[str]) -> None:
        """Exactly the expected connections are established."""
        assert get_established_connections(host) == expected
