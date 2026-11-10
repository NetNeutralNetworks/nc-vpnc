"""Manage network namespaces and run programs in them."""

from __future__ import annotations

import atexit
import logging
import os
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from pyroute2 import netns

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("vpnc")

T = TypeVar("T")

NETNS_DIR = Path("/var/run/netns")
# Namespaces deleted when vpnc stops.
_CLEANUP: set[str] = set()


def add(name: str, cleanup: bool = False) -> str:  # noqa: FBT001, FBT002
    """Add a namespace to the system, replacing a stale (unmounted) netns file."""
    path = NETNS_DIR / name
    if name in netns.listnetns() and not os.path.ismount(path):
        logger.warning(
            "Stale namespace file %s, recreating it.",
            path,
        )
        path.unlink(missing_ok=True)

    if name not in netns.listnetns():
        netns.create(name)

    if cleanup and name not in _CLEANUP:
        _CLEANUP.add(name)
        atexit.register(delete, name=name)

    return name


def delete(name: str) -> None:
    """Delete a namespace from the system."""
    ns_list = netns.listnetns()

    if name in ns_list:
        netns.remove(name)


def exists(name: str) -> bool:
    """Return whether a namespace exists."""
    return name in netns.listnetns()


@dataclass(frozen=True)
class Result:
    """The result of a program run in a namespace."""

    returncode: int
    stdout: str
    stderr: str


def call(name: str, func: Callable[[], T]) -> T:
    """Call a function in a namespace and return its result.

    The network namespace is per thread, so func runs in a short-lived thread
    moved into the namespace. Processes started there inherit the namespace.
    """
    result: list[T] = []
    error: list[BaseException] = []

    def target() -> None:
        try:
            netns.setns(name, flags=0)
            result.append(func())
        except BaseException as e:  # noqa: BLE001
            error.append(e)

    thread = threading.Thread(target=target, name=f"netns-{name}")
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]


def run(name: str, args: list[str], timeout: float = 30) -> Result:
    """Run a program in a namespace and wait for it."""
    proc = call(
        name,
        lambda: subprocess.run(  # noqa: S603
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
        ),
    )
    return Result(
        proc.returncode,
        proc.stdout.decode(errors="replace"),
        proc.stderr.decode(errors="replace"),
    )


def popen(name: str, args: list[str]) -> subprocess.Popen[bytes]:
    """Start a long-running program in a namespace."""
    return call(
        name,
        lambda: subprocess.Popen(  # noqa: S603
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ),
    )


def _sysctl_path(key: str) -> Path:
    return Path("/proc/sys", key.replace(".", "/"))


def ensure_sysctls(name: str, sysctls: dict[str, str]) -> bool:
    """Set the sysctls of a namespace that differ from the desired values."""

    def apply() -> list[str]:
        changed = []
        for key, value in sysctls.items():
            path = _sysctl_path(key)
            if path.read_text().strip() != value:
                path.write_text(value)
                changed.append(f"{key}={value}")
        return changed

    try:
        changed = call(name, apply)
    except OSError as e:
        logger.error("Setting sysctls in %s failed: %s", name, e)  # noqa: TRY400
        return False
    if changed:
        logger.info("Set sysctls in %s: %s.", name, ", ".join(changed))
    return bool(changed)
