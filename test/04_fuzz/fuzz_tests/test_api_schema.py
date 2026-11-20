"""Generated requests to every route of hub00's API (Schemathesis).

No server errors, answers as the OpenAPI schema says, invalid input refused, no
hangs. Afterwards hub00 is reset to as deployed.
"""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING

import pytest

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

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
CHECKS = [
    "not_a_server_error",
    "response_schema_conformance",
    "negative_data_rejection",
    "ensure_resource_availability",
]
# Not use_after_free: DELETE of a configuration stages its removal, which a
# commit applies and a discard drops.
EXCLUDED = (
    # What would change the service or vpnc itself.
    r"^/v1/(config/commit|config/service/commit|service/)"
    # Followed logs and events stream until closed.
    r"|/logs$|^/v1/events$"
)
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


@pytest.mark.usefixtures("api_on_tcp")
def test_api_schema(deployed: conftest.Deployed) -> None:
    """Every route answers generated requests as its schema says."""
    try:
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker", "run", "--rm", "--network", f"container:{CONTAINER}",
                SCHEMATHESIS, "run", "http://127.0.0.1:8080/openapi.json",
                "--checks", ",".join(CHECKS),
                "--max-examples", os.environ.get("FUZZ_EXAMPLES", "100"),
                "--request-timeout", "10",
                "--exclude-path-regex", EXCLUDED,
                "--no-color",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT,
        )  # fmt: skip
    finally:
        deployed.reset()
    assert conftest.restarts() == 0, "vpnc exited"
    assert result.returncode == 0, result.stdout[-20000:]
