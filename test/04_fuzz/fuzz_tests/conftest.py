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


# Restarts the tests caused on purpose (killing vpnc), by node.
EXPECTED_RESTARTS: dict[str, int] = {}


def expect_restart(host: str = HOST) -> None:
    """Note that a node restarts on purpose."""
    EXPECTED_RESTARTS[host] = EXPECTED_RESTARTS.get(host, 0) + 1


def restarts(host: str = HOST) -> int:
    """Return how often a node restarted (vpnc exited), but on purpose."""
    container = f"{CONTAINER_PREFIX}{host}"
    return -EXPECTED_RESTARTS.get(host, 0) + int(
        subprocess.run(  # noqa: S603
            ["docker", "inspect", "--format", "{{.RestartCount}}", container],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout,
    )


# Per network instance its links, addresses, routes and nftables rules (without
# counters), as JSON.
SNAPSHOT_SCRIPT = r"""
for ns in $(ip netns list | cut -d' ' -f1 | sort); do
    echo "$ns"
    ip -n "$ns" -j link
    ip -n "$ns" -j addr
    ip -n "$ns" -j -4 route show table all
    ip -n "$ns" -j -6 route show table all
    ip netns exec "$ns" nft -s -j list ruleset 2> /dev/null || echo '{"nftables": []}'
done
"""
# The daemons next to vpnc: a new process id means one exited (vpnc restarts
# vpncmangle, and watchfrr FRR's, only when they did).
DAEMONS = "charon|vpncmangle|watchfrr|mgmtd|zebra|bfdd|bgpd|staticd"


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
    for index in range(0, len(lines), 6):
        ns, links, addrs, routes_4, routes_6, rules = lines[index : index + 6]
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
            "nftables": _nftables(json.loads(rules)),
        }
    # Not network instances: what vpnc says of its connections, the daemons'
    # processes and FRR's BGP sessions.
    state["(vpnc)"] = {
        "admin_status": {
            (c["id"], c["admin_status"])
            for c in api("GET", "/v1/connections", host=host)[1]
        },
    }
    state["(daemons)"] = {"processes": _daemons(host)}
    state["(frr)"] = {"bgp": _bgp(host)}
    return state


def _nftables(ruleset: dict[str, Any]) -> set[str]:
    """Return the tables, chains, sets and rules, without their handles."""
    items = set()
    for item in ruleset.get("nftables", []):
        for kind, value in item.items():
            if kind != "metainfo":
                fields = {k: v for k, v in value.items() if k != "handle"}
                items.add(f"{kind} {json.dumps(fields, sort_keys=True)}")
    return items


def _daemons(host: str) -> set[tuple[str, int]]:
    """Return the daemons' names and process ids."""
    lines = subprocess.run(  # noqa: S603
        ["docker", "exec", f"{CONTAINER_PREFIX}{host}", "pgrep", "-l", "-x", DAEMONS],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split("\n")
    return {(name, int(pid)) for pid, name in (line.split() for line in lines if line)}


def _bgp(host: str) -> set[tuple[str, str, int]]:
    """Return CORE's BGP sessions as FRR has them: peer, state, prefixes sent."""
    output = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker", "exec", f"{CONTAINER_PREFIX}{host}",
            "vtysh", "-c", "show bgp vrf CORE ipv6 unicast summary json",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout  # fmt: skip
    try:
        peers = json.loads(output).get("peers", {})
    except json.JSONDecodeError:
        return {("(vtysh)", "no answer", 0)}
    return {
        (peer, info.get("state"), info.get("pfxSnt")) for peer, info in peers.items()
    }


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


# What frr-reload.py finds different between vpnc's FRR configuration and FRR's
# as deployed (e.g. the hostname): set by Deployed.
FRR_DEPLOYED_DIFFERENCES: set[str] = set()


def frr_differences(host: str = HOST) -> set[str]:
    """Return the lines frr-reload.py would change for FRR to run vpnc's config."""
    output = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker", "exec", f"{CONTAINER_PREFIX}{host}",
            "/usr/lib/frr/frr-reload.py", "--test", "/etc/frr/frr.conf",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout  # fmt: skip
    return {
        line
        for line in output.splitlines()
        if line.strip() and not line.startswith(("Lines To", "==="))
    }


def not_loaded(host: str = HOST) -> list[str]:
    """Return what vpnc applied only partly: charon, nftables, FRR or vpncmangle.

    Each enabled IPsec connection is loaded in charon, each network instance but
    DEFAULT has vpnc's nftables table, FRR runs vpnc's configuration (but what
    differed as deployed), and vpncmangle loaded the translations vpnc wrote.
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
    problems += [
        f"FRR doesn't run: {line}"
        for line in sorted(frr_differences(host) - FRR_DEPLOYED_DIFFERENCES)
    ]
    mangle = api("GET", "/v1/status", host=host)[1]["vpncmangle"]
    if not mangle["translations_loaded"]:
        problems.append(
            f"vpncmangle didn't load the translations: {mangle['translations_error']}",
        )
    return problems


def check_loaded(host: str = HOST) -> None:
    """Check that what vpnc applied, charon and nftables took."""
    problems = not_loaded(host)
    assert not problems, "\n".join(["applied only partly:", *problems])


# A tenant's DNS server through hub00 (C0001-00's NAT64), from mgt00: vpncmangle
# translates the A record of an IPv4-only name.
DNS_QUERY = ("mgt00", "fdcc:0:c:1::172.16.31.1", "v4lonly.example.com")
DNS_ANSWER = "fdcc:0:c:1::ac10:1f04"
SERVICE_TIMEOUT = 10


def not_answering(host: str = HOST) -> list[str]:
    """Return the daemons next to vpnc that don't answer: charon, FRR, vpncmangle."""
    container = f"{CONTAINER_PREFIX}{host}"
    problems = []
    for name, command in (
        ("charon", ["swanctl", "--stats"]),
        ("FRR", ["vtysh", "-c", "show bgp vrf CORE summary"]),
    ):
        try:
            subprocess.run(  # noqa: S603
                ["docker", "exec", container, *command],  # noqa: S607
                capture_output=True,
                check=True,
                timeout=SERVICE_TIMEOUT,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as err:
            problems.append(f"{name} doesn't answer: {err}")
    client, server, name = DNS_QUERY
    answer = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker", "exec", f"{CONTAINER_PREFIX}{client}",
            "dig", "+short", "+time=1", "+tries=3", name, f"@{server}",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()  # fmt: skip
    if answer != DNS_ANSWER:
        problems.append(f"vpncmangle answered {name} with {answer!r}, not {DNS_ANSWER}")
    return problems


def check_answering(host: str = HOST) -> None:
    """Check that charon, FRR and vpncmangle answer."""
    problems = not_answering(host)
    assert not problems, "\n".join(problems)


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
        FRR_DEPLOYED_DIFFERENCES.update(frr_differences(host))
        disabled = sorted(
            c for c, admin in self.state["(vpnc)"]["admin_status"] if admin != "UP"
        )
        assert not disabled, f"redeploy the fuzz lab: {', '.join(disabled)} disabled"
        check_loaded(host)
        check_answering(host)
        self.files = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker", "exec", f"{CONTAINER_PREFIX}{host}",
                "tar", "-C", "/", "-cpf", "-",
                *(directory.lstrip("/") for directory in DEPLOYED_DIRS),
            ],
            capture_output=True,
            check=True,
        ).stdout  # fmt: skip

    def restarted(self) -> None:
        """Take the daemons' new processes, once all run, after a restart."""
        names = set(DAEMONS.split("|"))

        def processes() -> set[tuple[str, int]] | None:
            found = _daemons(self.host)
            return found if {name for name, _ in found} == names else None

        self.state["(daemons)"] = {
            "processes": wait_until(
                processes, timeout=RESET_TIMEOUT, message="daemons"
            ),
        }

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
        check_answering(self.host)


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
    "check_answering",
    "check_loaded",
    "diff",
    "expect_restart",
    "not_loaded",
    "restarts",
    "run_cmd",
    "run_cmd_shell",
    "snapshot",
    "stable",
    "wait_until",
    "write_file",
]
