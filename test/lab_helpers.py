"""Helpers shared by the lab test suites.

Run commands in the containerlab containers and wait for the lab to reach a state.
"""

from __future__ import annotations

import subprocess
import time
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

T = TypeVar("T")

CONTAINER_PREFIX = "clab-vpnc-"


def run_cmd(host: str, command: str) -> str:
    """Run a command in the docker container and return its output.

    The command is split on whitespace; use run_cmd_shell for quoting, pipes, etc.
    """
    cmd = ["docker", "exec", f"{CONTAINER_PREFIX}{host}"]
    cmd.extend(command.split())

    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def run_cmd_shell(host: str, command: str) -> str:
    """Run a shell command line in the docker container and return its output.

    The host shell interprets the command line, so pipes and redirects run on the
    host; wrap them in "bash -c '...'" to run them in the container.
    """
    cmd = f"docker exec {CONTAINER_PREFIX}{host} {command}"

    return subprocess.run(  # noqa: S602
        cmd,
        capture_output=True,
        text=True,
        check=True,
        shell=True,
    ).stdout


def run_cmd_vtysh(host: str, command: str) -> str:
    """Run a vtysh command in the docker container and return its output."""
    cmd = ["docker", "exec", f"{CONTAINER_PREFIX}{host}", "vtysh", "-c", command]

    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def wait_until(
    func: Callable[[], T],
    timeout: float,
    interval: float = 1,
    message: str = "condition",
) -> T:
    """Poll func until it returns a truthy value and return that value.

    Exceptions raised by func count as "not yet". Raises TimeoutError with the last
    result or exception after timeout seconds.
    """
    deadline = time.monotonic() + timeout
    last: object = None
    while True:
        try:
            if result := func():
                return result
            last = result
        except Exception as exc:  # noqa: BLE001
            last = exc
        if time.monotonic() >= deadline:
            msg = f"Timed out after {timeout}s waiting for {message}. Last: {last!r}"
            raise TimeoutError(msg)
        time.sleep(interval)
