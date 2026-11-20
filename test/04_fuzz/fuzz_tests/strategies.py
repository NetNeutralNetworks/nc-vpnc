"""Generated configuration: a valid tenant, changed in ways that may break it."""

from __future__ import annotations

import copy
from typing import Any

import yaml
from hypothesis import strategies as st

TENANT = "C0003"

# Downlinks to a peer that doesn't exist, so the tenant's state stays the same.
BASELINE: dict[str, Any] = {
    "version": "0.1.4",
    "id": TENANT,
    "name": "Fuzz test",
    "network_instances": {
        "00": {
            "type": "DOWNLINK",
            "connections": {
                0: {
                    "interface": {
                        "ipv4": ["10.230.0.1/30"],
                        "ipv6": ["fdcc:230::1/64"],
                    },
                    "routes": {
                        "ipv4": [{"to": "10.231.0.0/24"}],
                        "ipv6": [
                            {"to": "2001:db8:c59::/48", "nptv6": False},
                            {"to": "fdff:db8:c59::/52", "nptv6": True},
                        ],
                    },
                    "probes": [{"address": "10.231.0.1", "test_type": "ICMP"}],
                    "config": {
                        "type": "IPSEC",
                        "remote_addrs": ["192.0.2.99"],
                        "ike_proposal": "aes128gcm16-prfsha384-ecp384",
                        "ipsec_proposal": "aes128gcm16-prfsha384-ecp384",
                        "initiation": "NONE",
                        "psk": "fuzz-test-preshared-key-32-chars",
                    },
                },
                1: {
                    "routes": {"ipv4": [{"to": "10.232.0.0/24"}], "ipv6": []},
                    "config": {
                        "type": "WIREGUARD",
                        "remote_addrs": ["192.0.2.99"],
                        "local_port": 51823,
                        "private_key": "dnE7rUsvSZovKzZA8KiR19CbDe4iyIVlFo7NP7o4b0A=",
                        "public_key": "9xdzIRK5ARFePwKZUKZAMwXPddTRtQTlQ00J3aUEeGc=",
                    },
                },
            },
        },
        "01": {
            "type": "DOWNLINK",
            "connections": {
                0: {
                    "routes": {"ipv4": [{"to": "default"}], "ipv6": []},
                    "config": {
                        "type": "IPSEC",
                        "remote_addrs": ["2001:db8::99"],
                        "psk": "another-fuzz-test-key-of-32-chars",
                    },
                },
            },
        },
    },
}

# Values that are wrong, at a limit or used elsewhere in the lab.
AWKWARD: list[Any] = [
    None, "", " ", "x" * 5000, "🙂", "a\nb", "\x00", "../../etc/passwd",
    0, -1, 1, 65535, 65536, 2**31, 2**64, 1.5, 1e308, True, False, [], {}, [None],
    "default", "0.0.0.0/0", "::/0", "10.0.0.0/8", "256.1.1.1", "1.2.3.4/33",
    "fe80::1/64", "ff02::1", "::1", "127.0.0.1", "169.254.0.1/16",
    "192.0.2.5", "2001:db8::5",  # hub00's own addresses
    "2001:db8:c57::/48", "172.16.30.1",  # C0001's routes
    "100.99.0.0/16", "fdcc:cbe::/32", "fd60::/12",  # the service's prefixes
    "C0001", "C0003", "C0003-00", "DEFAULT", "CORE", "EXTERNAL", "DOWNLINK",
    "IPSEC", "WIREGUARD", "SSH", "PHYSICAL", "NONE", "START",
    "eth0", "eth1", "lo", "0.1.4", "0.0.1", "99.0.0",
]  # fmt: skip

values = st.one_of(
    st.sampled_from(AWKWARD),
    st.text(max_size=20),
    st.integers(),
    st.lists(st.sampled_from(AWKWARD), max_size=3),
    st.dictionaries(st.text(max_size=8), st.sampled_from(AWKWARD), max_size=3),
)


def _paths(data: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:  # noqa: ANN401
    """Return the paths of all keys and list items in data."""
    paths = [prefix] if prefix else []
    if isinstance(data, dict):
        for key, value in data.items():
            paths += _paths(value, (*prefix, key))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            paths += _paths(value, (*prefix, index))
    return paths


def _apply(data: Any, path: tuple[Any, ...], action: str, value: Any) -> None:  # noqa: ANN401
    """Change data at path; a path that's gone after an earlier change is skipped."""
    parent = data
    try:
        for key in path[:-1]:
            parent = parent[key]
        target = parent[path[-1]]
    except (KeyError, IndexError, TypeError):
        return
    key = path[-1]
    if action == "delete":
        del parent[key]
    elif action == "replace":
        parent[key] = value
    elif action == "wrap":
        parent[key] = [target]
    elif action == "add" and isinstance(target, dict):
        target[f"unknown_{len(target)}"] = value
    elif action == "add" and isinstance(target, list):
        target.append(value if value is not None else copy.deepcopy(target[:1]))


def changed(base: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """Return a copy of base with one to three changes."""
    change = st.tuples(
        st.sampled_from(_paths(base)),
        st.sampled_from(["delete", "replace", "replace", "wrap", "add"]),
        values,
    )

    def build(changes: list[tuple[tuple[Any, ...], str, Any]]) -> dict[str, Any]:
        data = copy.deepcopy(base)
        for path, action, value in changes:
            _apply(data, path, action, value)
        return data

    return st.lists(change, min_size=1, max_size=3).map(build)


def patches(base: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """Return a merge patch that sets one value somewhere in base (null removes)."""

    def build(path: tuple[Any, ...], value: Any) -> dict[str, Any]:  # noqa: ANN401
        # A merge patch replaces lists as a whole: stop at the first list.
        keys = []
        for key in path:
            if isinstance(key, int) and keys and _is_list(base, keys):
                break
            keys.append(key)
        patch: Any = value
        for key in reversed(keys):
            patch = {str(key): patch}
        return patch

    return st.builds(build, st.sampled_from(_paths(base)), values)


def _is_list(data: Any, keys: list[Any]) -> bool:  # noqa: ANN401
    for key in keys:
        data = data[key]
    return isinstance(data, list)


# Text that isn't (valid) YAML, or a configuration that's hard to read.
RAW = [
    "",
    "---\n",
    "- a\n- b\n",
    "{",
    "id: [unclosed\n",
    "\tid: C0003\n",
    "﻿id: C0003\n",
    "!!python/object/apply:os.system ['true']\n",
    "a: &a [*a]\n",
    "id: C0003\nid: C0001\n",
    "version: 0.1.4\nid: C0001\n",
    "version: 0.1.4\nid: C0003\nnetwork_instances: &n {00: *n}\n",
]

file_texts = st.one_of(
    st.sampled_from(RAW),
    st.text(st.characters(exclude_categories=("Cs",)), max_size=200),
    changed(BASELINE).map(yaml.safe_dump),
)
