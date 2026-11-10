"""Manage network namespaces and run programs in them."""

from __future__ import annotations

import atexit
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pyroute2 import NSPopen, netns

logger = logging.getLogger("vpnc")

NETNS_DIR = Path("/var/run/netns")


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

    if cleanup:
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


def run(name: str, args: list[str], timeout: float = 30) -> Result:
    """Run a program in a namespace and wait for it."""
    proc = NSPopen(name, args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return Result(
            proc.returncode,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )
    finally:
        proc.release()


def popen(name: str, args: list[str]) -> NSPopen:
    """Start a long-running program in a namespace; release() it when done."""
    return NSPopen(name, args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ensure_sysctls(name: str, sysctls: dict[str, str]) -> bool:
    """Set the sysctls of a namespace that differ from the desired values."""
    current = run(name, ["/usr/sbin/sysctl", *sysctls])
    values = {
        key.strip(): value.strip()
        for key, _, value in (
            line.partition("=") for line in current.stdout.splitlines()
        )
    }
    changed = [f"{k}={v}" for k, v in sysctls.items() if values.get(k) != v]
    if not changed:
        return False
    logger.info("Setting sysctls in %s: %s.", name, ", ".join(changed))
    result = run(name, ["/usr/sbin/sysctl", "-w", *changed])
    if result.returncode:
        logger.error("Setting sysctls in %s failed: %s", name, result.stderr.strip())
    return True
