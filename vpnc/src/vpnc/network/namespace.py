"""Manage Linux namespace."""

from __future__ import annotations

import atexit

from pyroute2 import netns


def add(name: str, cleanup: bool = False) -> str:  # noqa: FBT001, FBT002
    """Add a namespace to the system."""
    ns_list = netns.listnetns()

    if name not in ns_list:
        netns.create(name)

    if cleanup:
        atexit.register(delete, name=name)

    return name


def delete(name: str) -> None:
    """Delete a namespace from the system."""
    ns_list = netns.listnetns()

    if name in ns_list:
        netns.remove(name)
