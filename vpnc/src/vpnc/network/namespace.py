"""Manage Linux namespace."""

from __future__ import annotations

import atexit
import logging
import os
from pathlib import Path

from pyroute2 import netns

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
