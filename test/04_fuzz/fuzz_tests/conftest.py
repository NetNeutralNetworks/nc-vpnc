"""Helpers of the fuzz tests; see also test/lab_helpers.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# test/ holds lab_helpers.py. Add it explicitly so the suite also works when
# pytest is started from inside the suite directory.
TEST_DIR = str(Path(__file__).resolve().parents[2])
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)

# Always the fuzz lab. Unless another suite imported lab_helpers first: then
# the tests are skipped (see FUZZ_LAB).
os.environ["VPNC_LAB"] = "vpnc-fuzz"

from lab_helpers import (  # noqa: E402
    CONTAINER_PREFIX,
    run_cmd,
    run_cmd_shell,
    wait_until,
    write_file,
)

FUZZ_LAB = CONTAINER_PREFIX == "clab-vpnc-fuzz-"

HOST = "hub00"
API_SOCKET = "/run/vpnc/api.sock"
ACTIVE_DIR = "/opt/ncubed/config/vpnc/active"
CANDIDATE_DIR = "/opt/ncubed/config/vpnc/candidate"
HISTORY_DIR = "/opt/ncubed/config/vpnc/history"
# An answer slower than this is a hang.
API_TIMEOUT = 60


class ApiError(AssertionError):
    """The API failed: no answer, or a server error."""


def api(
    method: str,
    path: str,
    body: Any = None,  # noqa: ANN401
    host: str = HOST,
) -> tuple[int, Any]:
    """Call vpnc's API on a node; return the status and the (JSON) answer."""
    cmd = [
        "docker", "exec", "-i", f"{CONTAINER_PREFIX}{host}",
        "curl", "-s", "-g", "-w", "\n%{http_code}", "-X", method,
        "--unix-socket", API_SOCKET, f"http://localhost{path}",
    ]  # fmt: skip
    data = None
    if body is not None:
        cmd[-1:-1] = ["-H", "Content-Type: application/json", "--data-binary", "@-"]
        data = body if isinstance(body, str) else json.dumps(body)
    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            input=data,
            capture_output=True,
            text=True,
            check=False,
            timeout=API_TIMEOUT,
        )
    except subprocess.TimeoutExpired as err:
        msg = f"{method} {path}: no answer in {API_TIMEOUT}s"
        raise ApiError(msg) from err
    text, _, status = result.stdout.rpartition("\n")
    if not status.isdigit() or status == "000":
        msg = f"{method} {path}: no answer ({result.stderr.strip()})"
        raise ApiError(msg)
    try:
        answer = json.loads(text)
    except json.JSONDecodeError:
        answer = text
    if int(status) >= 500:  # noqa: PLR2004
        msg = f"{method} {path}: {status} {answer}"
        raise ApiError(msg)
    return int(status), answer


def restarts(host: str = HOST) -> int:
    """Return how often a node restarted, which it does when vpnc exits."""
    container = f"{CONTAINER_PREFIX}{host}"
    return int(
        subprocess.run(  # noqa: S603
            ["docker", "inspect", "--format", "{{.RestartCount}}", container],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout,
    )


# Per network instance its links, addresses and routes, as JSON.
SNAPSHOT_SCRIPT = r"""
for ns in $(ip netns list | cut -d' ' -f1 | sort); do
    echo "$ns"
    ip -n "$ns" -j link
    ip -n "$ns" -j addr
    ip -n "$ns" -j -4 route show table all
    ip -n "$ns" -j -6 route show table all
done
"""


def _routes(routes: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
    return {
        (r.get("table"), r.get("type"), r["dst"], r.get("dev"), r.get("gateway"))
        for r in routes
        # The kernel's own: per address and link, and multicast.
        if r.get("table") != "local" and not r["dst"].startswith(("ff00::", "fe80::"))
    }


def snapshot(host: str = HOST) -> dict[str, Any]:
    """Return what a node has per network instance: links, addresses and routes."""
    lines = subprocess.run(  # noqa: S603
        ["docker", "exec", f"{CONTAINER_PREFIX}{host}", "bash", "-c", SNAPSHOT_SCRIPT],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    state = {}
    for index in range(0, len(lines), 5):
        ns, links, addrs, routes_4, routes_6 = lines[index : index + 5]
        state[ns] = {
            "links": {
                (link["ifname"], "UP" in link["flags"]) for link in json.loads(links)
            },
            "addresses": {
                (link["ifname"], a["local"], a["prefixlen"])
                for link in json.loads(addrs)
                for a in link.get("addr_info", [])
                if a.get("scope") != "link"
            },
            "routes": _routes(json.loads(routes_4) + json.loads(routes_6)),
        }
    # Not a network instance: what vpnc says of its connections.
    state["(vpnc)"] = {
        "admin_status": {
            (c["id"], c["admin_status"])
            for c in api("GET", "/v1/connections", host=host)[1]
        },
    }
    return state


def diff(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Return what differs between two snapshots, readable."""
    lines = []
    for ns in sorted(before.keys() | after.keys()):
        if ns not in after:
            lines.append(f"- netns {ns}")
            continue
        if ns not in before:
            lines.append(f"+ netns {ns}")
            continue
        for what in before[ns]:
            lines += [f"- {ns} {what} {x}" for x in before[ns][what] - after[ns][what]]
            lines += [f"+ {ns} {what} {x}" for x in after[ns][what] - before[ns][what]]
    return lines


def not_loaded(host: str = HOST) -> list[str]:
    """Return what vpnc applied only partly: charon or nftables refused it.

    Each enabled IPsec connection is loaded in charon, and each network instance
    but DEFAULT has vpnc's nftables table.
    """
    container = f"{CONTAINER_PREFIX}{host}"
    conns = subprocess.run(  # noqa: S603
        ["docker", "exec", container, "swanctl", "--list-conns"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    loaded = {line.split(":")[0] for line in conns.splitlines() if line[:1].strip()}
    problems = [
        f"IPsec connection {c['id']} isn't loaded in charon"
        for c in api("GET", "/v1/connections", host=host)[1]
        if c["type"] == "IPSEC" and c["admin_status"] == "UP" and c["id"] not in loaded
    ]
    for ni in api("GET", "/v1/network-instances", host=host)[1]:
        if ni["id"] == "DEFAULT":
            continue
        tables = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker", "exec", container,
                "ip", "netns", "exec", ni["id"], "nft", "list", "tables",
            ],
            capture_output=True,
            text=True,
            check=False,
        ).stdout  # fmt: skip
        if "table inet vpnc" not in tables:
            problems.append(f"network instance {ni['id']} has no nftables table")
    return problems


def check_loaded(host: str = HOST) -> None:
    """Check that what vpnc applied, charon and nftables took."""
    problems = not_loaded(host)
    assert not problems, "\n".join(["applied only partly:", *problems])


def stable(host: str = HOST, interval: float = 3) -> dict[str, Any]:
    """Return a node's snapshot once two in a row, interval apart, are the same."""
    previous: dict[str, Any] = {}

    def same() -> dict[str, Any] | None:
        nonlocal previous
        current = snapshot(host)
        if current == previous:
            return current
        previous = current
        return None

    return wait_until(same, timeout=120, interval=interval, message="a stable state")


CONFIG_DIR = "/opt/ncubed/config/vpnc"
# Restoring the deployed configuration: back to the same state within this time.
RESET_TIMEOUT = 300
# What a reset puts back: configuration, history (and pending confirms), and the
# SSH connections' keys and servers' host keys.
DEPLOYED_DIRS = [
    f"{CONFIG_DIR}/active",
    f"{CONFIG_DIR}/candidate",
    f"{CONFIG_DIR}/history",
    f"{CONFIG_DIR}/known_hosts",
    "/var/lib/vpnc-ssh/.ssh",
]
# Unpacks the saved directories over the node's, and removes what wasn't saved;
# a tenant that's in both isn't removed in between.
RESET_SCRIPT = """
set -e
saved=$(mktemp -d)
tar -C "$saved" -xpf -
for dir in "$@"; do
    mkdir -p "$dir"
    for path in "$dir"/* "$dir"/.[!.]*; do
        [ -e "$path" ] && [ ! -e "$saved$path" ] && rm -rf "$path"
    done
    cp -a "$saved$dir"/. "$dir"/
done
rm -rf "$saved"
"""


class Deployed:
    """A node's configuration files and state as deployed."""

    def __init__(self, host: str = HOST) -> None:
        """Read them once the state is stable; the lab must be sound."""
        self.host = host
        self.state = stable(host)
        disabled = sorted(
            c for c, admin in self.state["(vpnc)"]["admin_status"] if admin != "UP"
        )
        assert not disabled, f"redeploy the fuzz lab: {', '.join(disabled)} disabled"
        check_loaded(host)
        self.files = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker", "exec", f"{CONTAINER_PREFIX}{host}",
                "tar", "-C", "/", "-cpf", "-",
                *(directory.lstrip("/") for directory in DEPLOYED_DIRS),
            ],
            capture_output=True,
            check=True,
        ).stdout  # fmt: skip

    def reset(self) -> None:
        """Put the deployed files back; the state must follow."""
        container = f"{CONTAINER_PREFIX}{self.host}"
        subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker", "exec", "-i", container,
                "bash", "-c", RESET_SCRIPT, "reset", *DEPLOYED_DIRS,
            ],
            input=self.files,
            check=True,
        )  # fmt: skip
        try:
            wait_until(
                lambda: snapshot(self.host) == self.state,
                timeout=RESET_TIMEOUT,
                interval=3,
                message="the deployed state",
            )
        except TimeoutError:
            changes = diff(self.state, snapshot(self.host))
            msg = "\n".join(["not as deployed after restoring the files:", *changes])
            raise AssertionError(msg) from None
        check_loaded(self.host)


@pytest.fixture(scope="session")
def deployed() -> Deployed:
    """Return hub00 as deployed, to reset it to."""
    return Deployed()


__all__ = [
    "ACTIVE_DIR",
    "CANDIDATE_DIR",
    "CONFIG_DIR",
    "FUZZ_LAB",
    "HISTORY_DIR",
    "HOST",
    "ApiError",
    "Deployed",
    "api",
    "check_loaded",
    "diff",
    "not_loaded",
    "restarts",
    "run_cmd",
    "run_cmd_shell",
    "snapshot",
    "stable",
    "wait_until",
    "write_file",
]
