"""Generated requests to every route of hub00's API (Schemathesis).

No server errors, answers as the OpenAPI schema says, invalid input refused, no
hangs; valid input accepted where the schema says what's valid: adding a tenant
(not configurations, which have rules between their fields). Generated ids are
of nothing that exists, so the routes of a connection, network instance or BGP
neighbor are also run with the lab's. The runs go at the same time. Afterwards
hub00 is reset to as deployed.
"""

from __future__ import annotations

import concurrent.futures
import os
import subprocess
import warnings
from typing import TYPE_CHECKING

import pytest

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

SCHEMATHESIS = "schemathesis/schemathesis:4.33.4"
SOCAT = "alpine/socat:1.8.0.3"
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
            "docker", "run", "-d", "--rm", "--name", PROXY,
            "--network", f"container:{CONTAINER}",
            "-v", f"{SOCKET_DIR}:/vpnc", SOCAT,
            "TCP-LISTEN:8080,bind=127.0.0.1,fork,reuseaddr",
            "UNIX-CONNECT:/vpnc/api.sock",
        ],
        capture_output=True,
        check=True,
    )  # fmt: skip
    yield
    subprocess.run(["docker", "rm", "-f", PROXY], capture_output=True, check=False)  # noqa: S603, S607


def schemathesis(config: Path, *options: str) -> subprocess.CompletedProcess[str]:
    """Run Schemathesis against hub00's API."""
    return subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker", "run", "--rm", "--network", f"container:{CONTAINER}",
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
