"""Manage network namespaces and run programs in them.

pyroute2 forks the process to create a namespace or open a socket in one. Forking
a multithreaded process can deadlock the child, so this is done in a short-lived
thread moved into the namespace instead (the network namespace is per thread).
Within worker() one thread stays in the namespace for all calls.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

import pyroute2
from pyroute2 import netns
from pyroute2.netlink import NETLINK_ROUTE

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

logger = logging.getLogger("vpnc")

T = TypeVar("T")

NETNS_DIR = Path("/var/run/netns")
# Namespaces deleted when vpnc stops.
_CLEANUP: set[str] = set()


def add(name: str, cleanup: bool = False) -> str:  # noqa: FBT001, FBT002
    """Add a namespace to the system, replacing a stale (unmounted) netns file."""
    path = NETNS_DIR / name
    if path.exists() and not os.path.ismount(path):
        logger.warning(
            "Stale namespace file %s, recreating it.",
            path,
        )
        path.unlink(missing_ok=True)

    if not path.exists():
        _create(name)

    if cleanup and name not in _CLEANUP:
        _CLEANUP.add(name)
        atexit.register(delete, name=name)

    return name


def delete(name: str) -> None:
    """Delete a namespace from the system."""
    if exists(name):
        netns.remove(name)


def exists(name: str) -> bool:
    """Return whether a namespace exists."""
    return (NETNS_DIR / name).exists()


@dataclass(frozen=True)
class Result:
    """The result of a program run in a namespace."""

    returncode: int
    stdout: str
    stderr: str


def _in_thread(name: str, func: Callable[[], T]) -> T:
    """Call a function in a new thread and return its result."""
    result: list[T] = []
    error: list[BaseException] = []

    def target() -> None:
        try:
            result.append(func())
        except BaseException as e:  # noqa: BLE001
            error.append(e)

    thread = threading.Thread(target=target, name=f"netns-{name}")
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]


def _create(name: str) -> None:
    def create() -> None:
        os.unshare(os.CLONE_NEWNET)
        netns.attach(name, "thread-self")

    _in_thread(name, create)


# Per calling thread, the worker threads that stay in a namespace.
_WORKERS = threading.local()


@contextlib.contextmanager
def worker(name: str) -> Iterator[None]:
    """Run this thread's calls for a namespace in one thread, until the end."""
    workers: dict[str, ThreadPoolExecutor] = getattr(_WORKERS, "executors", None) or {}
    _WORKERS.executors = workers
    if name in workers:
        yield
        return
    workers[name] = ThreadPoolExecutor(
        max_workers=1,
        thread_name_prefix=f"netns-{name}",
        initializer=netns.setns,
        initargs=(name, 0),
    )
    try:
        yield
    finally:
        workers.pop(name).shutdown(wait=False)


def call(name: str, func: Callable[[], T]) -> T:
    """Call a function in a namespace and return its result.

    Processes and sockets created by func are in the namespace.
    """
    workers: dict[str, ThreadPoolExecutor] = getattr(_WORKERS, "executors", None) or {}
    if (executor := workers.get(name)) is not None:
        return executor.submit(func).result()

    def target() -> T:
        netns.setns(name, flags=0)
        return func()

    return _in_thread(name, target)


class IPRoute(pyroute2.IPRoute):
    """pyroute2 IPRoute for a namespace."""

    def __init__(self, name: str) -> None:
        """Open a netlink socket in the namespace (FileNotFoundError if missing)."""
        super().__init__(fileno=netlink_socket(name))
        self.netns = name


def netlink_socket(name: str) -> int:
    """Return the file descriptor of a new rtnetlink socket in a namespace."""
    return call(
        name,
        lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE),
    ).detach()


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
