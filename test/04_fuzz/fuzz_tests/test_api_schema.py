"""Generated requests to every route of hub00's API (Schemathesis).

No server errors, answers as the OpenAPI schema says, invalid input refused, no
hangs; valid input accepted where the schema says what's valid: adding a tenant
(not configurations, which have rules between their fields). Generated ids are
of nothing that exists, so the routes of a connection, network instance or BGP
neighbor are also run with the lab's. The runs go at the same time. Afterwards
hub00 is reset to as deployed. A network instance's ping, traceroute and TCP
test run on their own (Hypothesis), with the smallest settings.
"""

from __future__ import annotations

import concurrent.futures
import os
import subprocess
import warnings
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

SCHEMATHESIS = "docker.io/schemathesis/schemathesis:4.33.4"
SOCAT = "docker.io/alpine/socat:1.8.0.3"
# hub00's /run/vpnc on the host (fuzz.clab.yaml).
SOCKET_DIR = "/run/vpnc-fuzz-hub00"
PROXY = "fuzz-api-socat"
CONTAINER = f"{conftest.CONTAINER_PREFIX}{conftest.HOST}"
# What would change the service or vpnc itself.
EXCLUDED = r"^/v1/(config/commit|config/service/commit|service/)"
# Followed logs and events stream until closed: these routes are tested without.
CONFIG = """
[[operations]]
include-path-regex = "/logs$|^/v1/events$"
parameters = { follow = false }
"""
# The same, with ids of the lab in every route that takes one.
KNOWN = (
    CONFIG
    + """
[parameters]
connection_id = "C0001-00-0"
ni_id = "C0001-00"
neighbor = "fd00:1:2::1"
"""
)
WITH_ID = "connection_id|ni_id|neighbor"
# Not a network instance's ping, traceroute and TCP test: with a destination
# that doesn't answer they take as long as asked, up to 2 minutes.
SLOW = r"/(ping|traceroute|tcp)$"
CHECKS = (
    "not_a_server_error,response_schema_conformance,negative_data_rejection,"
    "ensure_resource_availability"
)
# Not use_after_free: DELETE of a configuration stages its removal, which a
# commit applies and a discard drops.
# Only where the schema says what's valid; on its own, as the stateful phase
# follows ids (e.g. DEFAULT from /v1/tenants) into routes that don't take them.
ACCEPTED = (
    "--checks",
    "not_a_server_error,response_schema_conformance,positive_data_acceptance",
    # POST /v1/config/tenants (filters of a path and a method add up).
    "--include-operation-id", "add_config_v1_config_tenants_post",
    "--phases", "examples,coverage,fuzzing",
)  # fmt: skip
TIMEOUT = 3600


@pytest.fixture
def api_on_tcp() -> Iterator[None]:
    """Make hub00's API socket reachable on its 127.0.0.1:8080."""
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "podman", "run", "-d", "--rm", "--name", PROXY,
            "--network", f"container:{CONTAINER}",
            "-v", f"{SOCKET_DIR}:/vpnc", SOCAT,
            "TCP-LISTEN:8080,bind=127.0.0.1,fork,reuseaddr",
            "UNIX-CONNECT:/vpnc/api.sock",
        ],
        capture_output=True,
        check=True,
    )  # fmt: skip
    yield
    subprocess.run(["podman", "rm", "-f", PROXY], capture_output=True, check=False)  # noqa: S603, S607


def schemathesis(config: Path, *options: str) -> subprocess.CompletedProcess[str]:
    """Run Schemathesis against hub00's API."""
    return subprocess.run(  # noqa: S603
        [  # noqa: S607
            "podman", "run", "--rm", "--network", f"container:{CONTAINER}",
            "-v", f"{config}:/schemathesis.toml:ro",
            SCHEMATHESIS, "--config-file", "/schemathesis.toml",
            "run", "http://127.0.0.1:8080/openapi.json",
            "--max-examples", os.environ.get("FUZZ_EXAMPLES", "100"),
            "--request-timeout", "10",
            "--no-color",
            *options,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT,
    )  # fmt: skip


def summary(output: str) -> str:
    """Return the end of Schemathesis' output: its warnings and summary."""
    start = output.find(" WARNINGS ")
    return output[output.rfind("\n", 0, start) + 1 :] if start >= 0 else output[-3000:]


@pytest.mark.usefixtures("api_on_tcp")
def test_api_schema(deployed: conftest.Deployed, tmp_path: Path) -> None:
    """Every route answers generated requests as its schema says."""
    # Readable for Schemathesis' own user in its container.
    tmp_path.chmod(0o755)
    configs = []
    for name, text in (("random.toml", CONFIG), ("known.toml", KNOWN)):
        configs.append(tmp_path / name)
        configs[-1].write_text(text)
        configs[-1].chmod(0o644)
    every = ("--checks", CHECKS, "--exclude-path-regex", EXCLUDED)
    try:
        with concurrent.futures.ThreadPoolExecutor(3) as pool:
            runs = [
                pool.submit(schemathesis, configs[0], *every),
                pool.submit(
                    schemathesis,
                    configs[1],
                    "--checks",
                    CHECKS,
                    "--include-path-regex",
                    WITH_ID,
                    "--exclude-path-regex",
                    f"{EXCLUDED}|{SLOW}",
                ),
                pool.submit(schemathesis, configs[0], *ACCEPTED),
            ]
            results = [run.result() for run in runs]
    finally:
        deployed.reset()
    assert conftest.restarts() == 0, "vpnc exited"
    for result in results:
        assert result.returncode == 0, result.stdout[-20000:]
    # Of the run with the lab's ids, e.g. routes that only answered 404: an id
    # isn't the lab's any more, and nothing behind it was tested.
    if " WARNINGS " in results[1].stdout:
        warnings.warn(summary(results[1].stdout), stacklevel=1)


# A network instance's ping, traceroute and TCP test, which the runs above leave
# out with the lab's ids: with the smallest settings, to any destination.
DIAGNOSTICS = settings(
    max_examples=max(2, int(os.environ.get("FUZZ_EXAMPLES", "100")) // 2),
    deadline=None,
    database=conftest.DATABASE,
)
DIAGNOSTICS_URL = "/v1/network-instances/C0001-00"
destinations = st.one_of(
    st.ip_addresses().map(str),
    st.sampled_from(["2001:db8:c57::1", "172.16.30.1", "fd00::3", "fdcc:cbe::"]),
)
NUMBER = (int, float, type(None))
RESULTS = {
    "ping": {
        "destination": str,
        "transmitted": int,
        "received": int,
        "rtt_min_ms": NUMBER,
        "rtt_avg_ms": NUMBER,
        "rtt_max_ms": NUMBER,
        "output": str,
    },
    "traceroute": {"destination": str, "hops": list, "output": str},
    "tcp": {
        "address": str,
        "port": int,
        "connected": bool,
        "time_ms": NUMBER,
        "error": (str, type(None)),
    },
}


def diagnosed(test: str, body: dict[str, Any]) -> None:
    """Run a diagnostic: it answers 200, in its schema (unanswered is a result)."""
    status, result = conftest.api("POST", f"{DIAGNOSTICS_URL}/{test}", body)
    event(f"{test}: {status}")
    assert status == 200, f"{test} {body}: {status} {result}"  # noqa: PLR2004
    fields = RESULTS[test]
    assert set(result) == set(fields), f"{test}: fields {sorted(result)}"
    wrong = {k: v for k, v in result.items() if not isinstance(v, fields[k])}
    assert not wrong, f"{test}: of the wrong type: {wrong}"


@DIAGNOSTICS
@given(destination=destinations)
def test_ping(deployed: conftest.Deployed, destination: str) -> None:  # noqa: ARG001
    """A ping from C0001-00 answers in its schema."""
    diagnosed("ping", {"destination": destination, "count": 1, "timeout": 0.2})


@DIAGNOSTICS
@given(destination=destinations)
def test_traceroute(deployed: conftest.Deployed, destination: str) -> None:  # noqa: ARG001
    """A traceroute from C0001-00 answers in its schema."""
    diagnosed("traceroute", {"destination": destination, "max_hops": 1})


@DIAGNOSTICS
@given(destination=destinations, port=st.integers(1, 65535))
def test_tcp(deployed: conftest.Deployed, destination: str, port: int) -> None:  # noqa: ARG001
    """A TCP test from C0001-00 answers in its schema."""
    diagnosed("tcp", {"address": destination, "port": port, "timeout": 0.2})
