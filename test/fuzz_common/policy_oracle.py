"""What hub00's firewall must allow, from vpnc's README, written apart from vpnc.

Connections open from management to tenants, never the other way or between
tenants; only configured peers reach IKE, ESP and WireGuard.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

NEVER_LEAVES = "never leaves the network instance"
ANSWERED = "answered"
ONLY_ICMP_ERRORS = "no answer but an ICMP error"
PASSES = "passes, and the reply returns"
REACHES_DAEMON = "reaches the daemon"
NO_ANSWER = "no answer"


@dataclass(frozen=True)
class Row:
    """A row of the policy: new traffic from a source to a target."""

    name: str
    source: str
    target: str
    traffic: str
    expected: str


POLICY = (
    Row("tenant-core", "tenant", "a CORE address", "any", NEVER_LEAVES),
    Row(
        "tenant-tenant",
        "tenant",
        "another tenant's routes, NAT64 or NPTv6 prefix",
        "any",
        NEVER_LEAVES,
    ),
    Row("tenant-own", "tenant", "its own other connection", "any", NEVER_LEAVES),
    Row("tenant-hub-echo", "tenant", "hub00's own address", "ICMPv6 echo", ANSWERED),
    Row(
        "tenant-hub-ports",
        "tenant",
        "hub00's own address",
        "TCP or UDP, any port",
        ONLY_ICMP_ERRORS,
    ),
    Row(
        "management",
        "management",
        "a tenant host, through NAT64 and NPTv6",
        "TCP, UDP, ICMP",
        PASSES,
    ),
    Row("peer", "a configured peer", "EXTERNAL", "IKE, ESP, WireGuard", REACHES_DAEMON),
    Row("stranger", "any other address", "EXTERNAL", "IKE, ESP, WireGuard", NO_ANSWER),
)

# Allowed, though not in the table: not defects.
EXCEPTIONS = (
    "neighbour discovery and the ICMPv6 types of nft-icmpv6-in-out",
    "established and related traffic",
    "the probes a connection configures",
    "TCP port 22 out of a downlink, for SSH tunnels",
    "DNS over TCP refused in CORE (a reset)",
)

ESP, IKE_PORTS = "esp", {500, 4500}


@dataclass
class Ruleset:
    """A network instance's nftables items, from snapshot()."""

    chains: dict[str, dict[str, Any]] = field(default_factory=dict)
    rules: dict[str, list[list[dict[str, Any]]]] = field(default_factory=dict)
    sets: dict[str, list[Any]] = field(default_factory=dict)

    @classmethod
    def read(cls, items: set[str], table: str = "vpnc") -> Ruleset:
        """Return the table's chains, rules (their expressions) and sets."""
        found = cls()
        for item in items:
            kind, _, text = item.partition(" ")
            value = json.loads(text)
            if value.get("table") != table:
                continue
            if kind == "chain":
                found.chains[value["name"]] = value
            elif kind == "rule":
                exprs = [e for e in value["expr"] if "counter" not in e]
                found.rules.setdefault(value["chain"], []).append(exprs)
            elif kind == "set":
                found.sets[value["name"]] = value.get("elem", [])
        for rules in found.rules.values():
            rules.sort(key=json.dumps)
        return found


def _match(left: dict[str, Any], right: Any, op: str = "==") -> dict[str, Any]:  # noqa: ANN401
    return {"match": {"op": op, "left": left, "right": right}}


def _meta(key: str) -> dict[str, Any]:
    return {"meta": {"key": key}}


def _verdict(exprs: list[dict[str, Any]]) -> str | None:
    for kind in ("accept", "drop", "reject", "jump", "goto"):
        if any(kind in e for e in exprs):
            return kind
    return None


def _has_saddr(exprs: list[dict[str, Any]]) -> bool:
    text = json.dumps(exprs)
    return '"field": "saddr"' in text


def tenant(items: set[str], ni: str, nat64: str | None = None) -> list[str]:
    """Return how a tenant network instance's ruleset breaks the policy.

    nat64: its NAT64 prefix, if it has one (e.g. fdcc:0:c:1::/96).
    """
    rules = Ruleset.read(items)
    problems = [
        f"{ni}: no {hook} chain with policy drop"
        for hook in ("input", "forward", "output")
        if not any(
            c.get("hook") == hook and c.get("policy") == "drop"
            for c in rules.chains.values()
        )
    ]
    ipv6 = _match(_meta("nfproto"), "ipv6")
    allowed = [
        [ipv6, _match(_meta("iifname"), f"{ni}_D"), {"accept": None}],
        [
            ipv6,
            _match({"ct": {"key": "state"}}, ["established", "related"], "in"),
            {"accept": None},
        ],
    ]
    problems += [
        f"{ni}: forward accepts {json.dumps(exprs)}"
        for chain in rules.chains.values()
        if chain.get("hook") == "forward"
        for exprs in rules.rules.get(chain["name"], [])
        if _verdict(exprs) in ("accept", "jump", "goto") and exprs not in allowed
    ]
    if nat64:
        address, length = nat64.split("/")
        drop = [
            _match(_meta("iifname"), f"{ni}_D", "!="),
            _match(
                {"payload": {"protocol": "ip6", "field": "daddr"}},
                {"prefix": {"addr": address, "len": int(length)}},
            ),
            {"drop": None},
        ]
        prerouting = [
            name for name, c in rules.chains.items() if c.get("hook") == "prerouting"
        ]
        if not any(drop in rules.rules.get(name, []) for name in prerouting):
            problems.append(f"{ni}: NAT64 prefix {nat64} not dropped from tunnels")
    return problems


def _elements(rules: Ruleset, prefix: str) -> set[Any]:
    found = set()
    for name, elements in rules.sets.items():
        if not name.startswith(prefix):
            continue
        for element in elements:
            value = element["elem"]["val"] if isinstance(element, dict) else element
            if isinstance(value, dict) and "concat" in value:
                value = tuple(value["concat"])
            found.add(value)
    return found


def external(
    items: set[str],
    peers: set[str],
    wireguard: set[tuple[str, int]],
    absent: set[str],
) -> list[str]:
    """Return how EXTERNAL's ruleset breaks the policy.

    Every accept of IKE, ESP or WireGuard names source addresses. peers: IPsec
    peers that must be among them; wireguard: (address, local port) pairs that
    must; absent: addresses that must not be.
    """
    rules = Ruleset.read(items)
    problems = []
    if not any(
        c.get("hook") == "input" and c.get("policy") == "drop"
        for c in rules.chains.values()
    ):
        problems.append("EXTERNAL: no input chain with policy drop")
    for chain in rules.chains.values():
        if chain.get("hook") != "input":
            continue
        for exprs in rules.rules.get(chain["name"], []):
            verdict = _verdict(exprs)
            if verdict not in ("accept", "jump", "goto") or _has_saddr(exprs):
                continue
            text = json.dumps(exprs)
            if '"right": "lo"' in text or '"icmp' in text:
                continue
            problems.append(f"EXTERNAL: input lets through {text}")
    ipsec = _elements(rules, "ipsec_peers")
    keyed = _elements(rules, "wireguard_peers")
    problems += [f"EXTERNAL: IPsec peer {a} not let in" for a in peers - ipsec]
    problems += [
        f"EXTERNAL: WireGuard peer {a} port {p} not let in"
        for a, p in wireguard - keyed
    ]
    present = ipsec | {address for address, _ in keyed}
    problems += [f"EXTERNAL: {a} let in, no peer" for a in absent & present]
    return problems
