"""vpncmangle's nftables table, through the nft program, in this process's namespace.

The same way as vpnc, which can't use libnftables (see vpnc.network.nftables).

DNS responses are queued to vpncmangle, each network instance's within its rate
limit: one thread handles all of them, so one network instance's can't take it.
"""

from __future__ import annotations

import collections
import json
import logging
import re
import subprocess
import threading

from . import config

logger = logging.getLogger("vpncmangle")

NFT = "/usr/sbin/nft"
TIMEOUT = 30
TABLE = "ip6 vpncmangle"
# Names used in the table: of network instances, e.g. C0001-00.
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
# Prefix of the counters of responses over the rate limit.
LIMITED = "limited-"

# The queue vpncmangle is bound to.
QUEUE: int | None = None
# Responses over the rate limit per network instance, counted by tables since replaced.
_LIMITED: collections.Counter[str] = collections.Counter()
# The main thread (binding the queue) and the observer (reloading) apply.
_LOCK = threading.Lock()


class NftablesError(Exception):
    """An nftables command failed."""


def run(commands: str, *, json_output: bool = False) -> str:
    """Run nft commands (as in an nft -f file) in one transaction."""
    args = [NFT, "-j", *commands.split()] if json_output else [NFT, "-f", "-"]
    proc = subprocess.run(  # noqa: S603
        args,
        input=None if json_output else commands.encode(),
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    if proc.returncode:
        error = proc.stderr.decode(errors="replace").strip()
        raise NftablesError(error or f"nft failed ({proc.returncode})")
    return proc.stdout.decode(errors="replace")


def table(queue: int) -> str:
    """Return the table: responses to the queue, by network instance."""
    limits = config.LIMITS
    limit = (
        f"limit rate over {limits.rate_limit} kbytes/second"
        f" burst {2 * limits.rate_limit} kbytes"
    )
    counters: list[str] = []
    matches: list[str] = []
    chains: list[str] = []
    for network, name, _ in config.ACL_MATCH:
        if not NAME_RE.fullmatch(name):
            continue
        if (counter := f"    counter {LIMITED}{name} {{ }}") not in counters:
            counters.append(counter)
            chains.append(
                f"    chain ni-{name} {{\n"
                f'        {limit} counter name "{LIMITED}{name}" drop\n'
                f"        queue num {queue}\n"
                "    }",
            )
        # In vpncmangle's order: the first network a source is in.
        matches.append(f"        ip6 saddr {network} goto ni-{name}")
    return "\n".join(
        [
            f"table {TABLE} {{",
            *counters,
            "    chain postrouting {",
            "        type filter hook postrouting priority mangle; policy accept;",
            # TODO@draggeta: fix DNS over TCP
            "        udp sport 53 jump responses",
            "    }",
            "    chain responses {",
            *matches,
            # Of no network instance: vpncmangle drops and counts it.
            f"        queue num {queue}",
            "    }",
            *chains,
            "}",
        ],
    )


def _counters() -> dict[str, int]:
    """Return the table's counts of responses over the rate limit."""
    try:
        listing = json.loads(run(f"list counters table {TABLE}", json_output=True))
    except (NftablesError, OSError, subprocess.SubprocessError, ValueError):
        return {}
    return {
        item["counter"]["name"].removeprefix(LIMITED): item["counter"]["packets"]
        for item in listing.get("nftables", [])
        if "counter" in item
    }


def apply(queue: int | None = None) -> None:
    """Replace the table for the loaded configuration; the old ip6tables rule too.

    For a queue vpncmangle just bound to, or the one it's bound to.
    """
    global QUEUE  # noqa: PLW0603
    with _LOCK:
        if queue is not None:
            QUEUE = queue
        if QUEUE is None:
            return
        counted = _counters()
        run(
            f"table {TABLE}\n"
            f"delete table {TABLE}\n"
            "destroy table ip6 mangle\n"
            f"{table(QUEUE)}\n",
        )
        # The new table counts from 0.
        _LIMITED.update(counted)


def rate_limited() -> dict[str, int]:
    """Return the responses over the rate limit per network instance, since started."""
    with _LOCK:
        counts = _LIMITED + collections.Counter(_counters())
    return dict(counts)
