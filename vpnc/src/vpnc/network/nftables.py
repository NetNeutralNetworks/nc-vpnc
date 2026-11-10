"""nftables through libnftables, in a namespace, without nft processes.

vpnc keeps its rules in its own table (TABLE) per namespace and replaces it in
one transaction, so there's no moment without rules.
"""

from __future__ import annotations

import ctypes
import json
import logging
from typing import Any

from vpnc.network import namespace

logger = logging.getLogger("vpnc")

FAMILY = "inet"
NAME = "vpnc"
TABLE = f"{FAMILY} {NAME}"
# Tables iptables-nft created for vpnc's old iptables rules.
IPTABLES_TABLES = ("ip filter", "ip6 filter", "ip nat", "ip6 nat")

NFT_CTX_OUTPUT_JSON = 1 << 4

_LIB: ctypes.CDLL | None = None


class NftablesError(Exception):
    """An nftables command failed."""


def _lib() -> ctypes.CDLL:
    global _LIB  # noqa: PLW0603
    if _LIB is None:
        lib = ctypes.CDLL("libnftables.so.1")
        lib.nft_ctx_new.restype = ctypes.c_void_p
        lib.nft_ctx_new.argtypes = [ctypes.c_uint32]
        lib.nft_ctx_free.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_buffer_output.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_buffer_error.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_output_set_flags.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        lib.nft_ctx_get_output_buffer.restype = ctypes.c_char_p
        lib.nft_ctx_get_output_buffer.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_get_error_buffer.restype = ctypes.c_char_p
        lib.nft_ctx_get_error_buffer.argtypes = [ctypes.c_void_p]
        lib.nft_run_cmd_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _LIB = lib
    return _LIB


def _run(commands: str, *, json_output: bool) -> str:
    """Run nft commands in the calling thread's namespace."""
    lib = _lib()
    # A context opens its netlink socket in the namespace of this thread.
    ctx = lib.nft_ctx_new(0)
    try:
        lib.nft_ctx_buffer_output(ctx)
        lib.nft_ctx_buffer_error(ctx)
        if json_output:
            lib.nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_JSON)
        rc = lib.nft_run_cmd_from_buffer(ctx, commands.encode())
        output = (lib.nft_ctx_get_output_buffer(ctx) or b"").decode()
        error = (lib.nft_ctx_get_error_buffer(ctx) or b"").decode()
    finally:
        lib.nft_ctx_free(ctx)
    if rc:
        raise NftablesError(error.strip() or f"nft failed ({rc})")
    return output


def run(netns: str, commands: str, *, json_output: bool = False) -> str:
    """Run nft commands (as in an nft -f file) in a namespace."""
    return namespace.call(netns, lambda: _run(commands, json_output=json_output))


def _strip_handles(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, dict):
        return {k: _strip_handles(v) for k, v in value.items() if k != "handle"}
    if isinstance(value, list):
        return [_strip_handles(v) for v in value]
    return value


def ruleset(netns: str) -> dict[str, Any]:
    """Return vpnc's table and which old iptables tables exist, comparable as is."""

    def read() -> dict[str, Any]:
        tables = json.loads(_run("list tables", json_output=True))["nftables"]
        names = {
            f"{t['table']['family']} {t['table']['name']}"
            for t in tables
            if "table" in t
        }
        table: list[Any] = []
        if TABLE in names:
            listing = json.loads(_run(f"list table {TABLE}", json_output=True))
            table = [x for x in listing["nftables"] if "metainfo" not in x]
        return {
            "table": _strip_handles(table),
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
