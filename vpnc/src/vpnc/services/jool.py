"""Jool (NAT64) instances, one per network instance and named after it."""

from __future__ import annotations

import logging
import subprocess

from vpnc.network import namespace

logger = logging.getLogger("vpnc")

JOOL = "/usr/bin/jool"


def instances() -> set[str] | None:
    """Return the instances of all namespaces, in one call; None if it failed."""
    try:
        result = subprocess.run(  # noqa: S603
            [JOOL, "instance", "display", "--csv"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.warning("Listing the Jool instances failed.", exc_info=True)
        return None
    if result.returncode:
        return None
    return {
        fields[1]
        for line in result.stdout.splitlines()[1:]
        if len(fields := line.split(",")) >= 2  # noqa: PLR2004
    }


# Only what management opened is translated back: nothing from a tenant's host
# it didn't contact, and no TCP connection a tenant's host opens.
FILTERING = ("address-dependent-filtering", "drop-externally-initiated-tcp")


def settings(ni_id: str) -> dict[str, str] | None:
    """Return the settings of a network instance's instance; None without one."""
    result = namespace.run(ni_id, [JOOL, "-i", ni_id, "global", "display", "--csv"])
    if result.returncode:
        return None
    return {
        key: value
        for key, _, value in (
            line.partition(",") for line in result.stdout.splitlines()
        )
    }


def pool6(ni_id: str) -> str | None:
    """Return the NAT64 prefix of a network instance's instance; None without one."""
    return (settings(ni_id) or {}).get("pool6")


def add(ni_id: str, prefix: str) -> namespace.Result:
    """Add the instance of a network instance."""
    return namespace.run(
        ni_id,
        [JOOL, "instance", "add", ni_id, "--netfilter", "--pool6", prefix],
    )


def ensure_filtering(ni_id: str, current: dict[str, str]) -> bool:
    """Turn on the filtering that current (the settings) lacks; False if it failed."""
    for option in FILTERING:
        if current.get(option) == "TRUE":
            continue
        result = namespace.run(
            ni_id,
            [JOOL, "-i", ni_id, "global", "update", option, "true"],
        )
        if result.returncode:
            logger.error(
                "Setting %s in %s failed: %s",
                option,
                ni_id,
                result.stderr.strip(),
            )
            return False
        logger.info("Set %s in %s.", option, ni_id)
    return True


def remove(ni_id: str) -> None:
    """Remove the instance of a network instance."""
    namespace.run(ni_id, [JOOL, "instance", "remove", ni_id])
