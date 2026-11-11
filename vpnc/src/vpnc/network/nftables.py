"""nftables in a namespace, through the nft program.

Not libnftables: it waits on its netlink socket with select(), and glibc aborts
the process when that socket's file descriptor is 1024 or higher, which vpnc
reaches with about 200 network instances. nft starts with only a few open.

vpnc keeps its rules in its own table (TABLE) per namespace and replaces it in
one transaction, so there's no moment without rules.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

from vpnc.network import namespace

logger = logging.getLogger("vpnc")

FAMILY = "inet"
NAME = "vpnc"
TABLE = f"{FAMILY} {NAME}"
# Tables iptables-nft created for vpnc's old iptables rules.
IPTABLES_TABLES = ("ip filter", "ip6 filter", "ip nat", "ip6 nat")

NFT = "/usr/sbin/nft"
TIMEOUT = 30


class NftablesError(Exception):
    """An nftables command failed."""


def _run(commands: str, *, json_output: bool) -> str:
    """Run nft commands in the calling thread's namespace."""
    # With -j, nft also reads JSON from a file, so JSON listings go as arguments.
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


def run(netns: str, commands: str, *, json_output: bool = False) -> str:
    """Run nft commands (as in an nft -f file) in a namespace."""
    return namespace.call(netns, lambda: _run(commands, json_output=json_output))


def _strip_handles(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, dict):
        return {k: _strip_handles(v) for k, v in value.items() if k != "handle"}
    if isinstance(value, list):
        return [_strip_handles(v) for v in value]
    return value


def _in_table(item: dict[str, Any]) -> bool:
    """Return whether a JSON listing item is (in) vpnc's table."""
    kind, value = next(iter(item.items()))
    if kind == "metainfo":
        return False
    if kind == "table":
        return value["family"] == FAMILY and value["name"] == NAME
    return value.get("family") == FAMILY and value.get("table") == NAME


def ruleset(netns: str) -> dict[str, Any]:
    """Return vpnc's table and which old iptables tables exist, comparable as is."""

    def read() -> dict[str, Any]:
        # One nft run: the whole ruleset, filtered to vpnc's table.
        listing = json.loads(_run("list ruleset", json_output=True))["nftables"]
        names = {
            f"{t['table']['family']} {t['table']['name']}"
            for t in listing
            if "table" in t
        }
        return {
            "table": _strip_handles([x for x in listing if _in_table(x)]),
            "iptables": sorted(names & set(IPTABLES_TABLES)),
        }

    return namespace.call(netns, read)


def replace(netns: str, table: str) -> None:
    """Replace vpnc's table with table (its body) and drop the old iptables tables.

    Everything happens in one transaction.
    """
    commands = [
        f"table {TABLE}",
        f"delete table {TABLE}",
        *(f"destroy table {name}" for name in IPTABLES_TABLES),
        f"table {TABLE} {{\n{table}\n}}",
    ]
    run(netns, "\n".join(commands) + "\n")


def set_elements(netns: str, name: str) -> list[Any]:
    """Return the elements of a set in vpnc's table."""
    listing = json.loads(run(netns, f"list set {TABLE} {name}", json_output=True))
    for item in listing["nftables"]:
        if "set" in item:
            return list(item["set"].get("elem", []))
    return []


def replace_elements(netns: str, name: str, elements: list[str]) -> None:
    """Make a set in vpnc's table hold exactly elements, in one transaction."""
    commands = [f"flush set {TABLE} {name}"]
    if elements:
        commands.append(f"add element {TABLE} {name} {{ {', '.join(elements)} }}")
    run(netns, "\n".join(commands) + "\n")
