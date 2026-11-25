"""Generated configuration: a valid tenant, changed in ways that may break it."""

from __future__ import annotations

import base64
import copy
import enum
import ipaddress
from dataclasses import dataclass
from typing import Any

import yaml
from hypothesis import strategies as st

TENANT = "C0003"

# Downlinks to a peer that doesn't exist, so the tenant's state stays the same.
BASELINE: dict[str, Any] = {
    "version": "0.1.5",
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

# Words of IPsec proposals: algorithms charon knows, weak ones, and none.
KEYWORDS = [
    "aes256gcm16", "aes128gcm16", "aes256", "aes128", "chacha20poly1305", "3des",
    "sha256", "sha384", "sha1", "md5", "prfsha256", "prfsha384", "prfsha1",
    "ecp384", "ecp256", "x25519", "curve25519", "modp3072", "modp2048", "modp1024",
    "mlkem768", "ke1_mlkem768", "esn", "noesn", "null", "aes256ccm", "",
]  # fmt: skip

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
    "eth0", "eth1", "lo", "0.1.5", "0.0.1", "99.0.0",
]  # fmt: skip

# Random values of the kinds the settings take: any address or network, port,
# lifetime, key or name.
addresses = st.one_of(st.ip_addresses(v=4), st.ip_addresses(v=6)).map(str)
networks = st.one_of(
    st.tuples(st.ip_addresses(v=4), st.integers(0, 32)),
    st.tuples(st.ip_addresses(v=6), st.integers(0, 128)),
).map(lambda n: str(ipaddress.ip_network(f"{n[0]}/{n[1]}", strict=False)))
typed = st.one_of(
    addresses,
    networks,
    # An interface's address: a host in a network.
    st.tuples(st.ip_addresses(v=4), st.integers(0, 32)).map(lambda n: f"{n[0]}/{n[1]}"),
    st.tuples(st.ip_addresses(v=6), st.integers(0, 128)).map(
        lambda n: f"{n[0]}/{n[1]}"
    ),
    st.integers(0, 70000),
    st.binary(min_size=32, max_size=32).map(lambda key: base64.b64encode(key).decode()),
    st.from_regex(r"[2-9A-F][0-9]{4}(-[0-9]{2}(-[0-9])?)?", fullmatch=True),
    st.lists(st.sampled_from(KEYWORDS), min_size=1, max_size=5).map("-".join),
)
# A value: one that's listed as awkward, one of a setting's kind, or anything.
values = st.one_of(
    st.sampled_from(AWKWARD),
    typed,
    st.text(max_size=20),
    st.integers(),
    st.lists(st.one_of(st.sampled_from(AWKWARD), typed), max_size=3),
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


def _apply(data: Any, path: tuple[Any, ...], action: str, value: Any) -> None:  # noqa: ANN401, C901
    """Change data at path; a path that's gone after an earlier change is skipped."""
    parent = data
    try:
        for key in path[:-1]:
            parent = parent[key]
        target = parent[path[-1]]
    except (KeyError, IndexError, TypeError):
        return
    if not isinstance(parent, (dict, list)):
        # E.g. a character of text that replaced a list.
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
        target.append(value)
    elif action == "duplicate" and isinstance(target, list) and target:
        target.append(copy.deepcopy(target[0]))
    elif action == "nest" and isinstance(target, list):
        # A list inside the list.
        target.append(copy.deepcopy(target[:1]))


def changed(base: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """Return a copy of base with one to three changes."""
    change = st.tuples(
        st.sampled_from(_paths(base)),
        st.sampled_from(
            ["delete", "replace", "replace", "wrap", "add", "duplicate", "nest"]
        ),
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


# IKE proposals other than the baseline's.
PROPOSALS = [
    "aes256gcm16-prfsha384-ecp384",
    "aes128gcm16-prfsha256-x25519",
    "chacha20poly1305-prfsha256-curve25519",
]


class Expected(enum.Enum):
    """What vpnc must do with a request."""

    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    EITHER = "EITHER"


# A setting a change removed.
GONE = "(gone)"


@dataclass(frozen=True)
class Change:
    """The setting a valid change sets: its path, and its value (or GONE).

    contains: the value is one item of the list at path.
    """

    path: tuple[Any, ...]
    value: Any
    contains: bool = False

    def held(self, data: Any) -> bool:  # noqa: ANN401
        """Return whether a configuration (as the API returns it) has the change."""
        for key in self.path:
            if not isinstance(data, dict):
                return False
            # Keys as configured (0), or as the API returns them ("0").
            found = next((k for k in (key, str(key)) if k in data), None)
            if found is None:
                return self.value == GONE
            data = data[found]
        if self.contains:
            # The API adds defaults to an item.
            return any(
                isinstance(item, dict) and self.value.items() <= item.items()
                for item in data
            )
        # A list removed reads as empty.
        return data == self.value or (self.value == GONE and data == [])


def valid(base: dict[str, Any]) -> st.SearchStrategy[tuple[dict[str, Any], Change]]:  # noqa: C901
    """Return a copy of base (BASELINE) with a change that vpnc accepts, and it."""

    def build(change: tuple[str, Any]) -> tuple[dict[str, Any], Change]:  # noqa: PLR0911
        what, value = change
        data = copy.deepcopy(base)
        connections = data["network_instances"]["00"]["connections"]
        key = 0 if 0 in connections else "0"
        connection = connections[key]
        at = ("network_instances", "00", "connections", key)
        if what == "name":
            data["name"] = f"Changed {value}"
            return data, Change(("name",), data["name"])
        if what == "metadata":
            data["metadata"] = {"fuzz": value}
            return data, Change(("metadata",), data["metadata"])
        if what == "disable":
            connection["enabled"] = False
            return data, Change((*at, "enabled"), value=False)
        if what == "mtu":
            connection["mtu"] = 1280 + value % 221
            return data, Change((*at, "mtu"), connection["mtu"])
        if what == "route":
            route = {"to": f"10.231.{1 + value % 200}.0/24"}
            connection["routes"]["ipv4"].append(route)
            return data, Change((*at, "routes", "ipv4"), route, contains=True)
        if what == "probes":
            del connection["probes"]
            return data, Change((*at, "probes"), GONE)
        if what == "psk":
            connection["config"]["psk"] = f"fuzz-test-new-preshared-key-{value:08d}"
            return data, Change((*at, "config", "psk"), connection["config"]["psk"])
        if what == "selectors":
            selectors = {
                "local": [f"10.233.{value % 200}.0/24"],
                "remote": ["10.231.0.0/24"],
            }
            connection["config"]["traffic_selectors"] = selectors
            return data, Change((*at, "config", "traffic_selectors"), selectors)
        if what == "proposal":
            proposal = PROPOSALS[value % len(PROPOSALS)]
            connection["config"]["ike_proposal"] = proposal
            return data, Change((*at, "config", "ike_proposal"), proposal)
        del data["network_instances"]["01"]
        return data, Change(("network_instances", "01"), GONE)

    return st.tuples(
        st.sampled_from(
            [
                *("name", "metadata", "disable", "mtu", "route", "probes", "remove"),
                *("psk", "selectors", "proposal"),
            ],
        ),
        st.integers(0, 10**6),
    ).map(build)


def _is_address(value: object) -> bool:
    """Return whether a value is text that reads as an address or a network."""
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_interface(value)
    except ValueError:
        return False
    return True


def mistyped(base: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """Return a copy of base that vpnc refuses, for a value of another kind.

    True or false as a number or an address, or a number as an address: read
    as they are, true is 1 and 5 is 0.0.0.5.
    """
    numbers, addresses = [], []
    for path in _paths(base):
        value = base
        for key in path:
            value = value[key]
        # Not metadata: that's anything.
        if "metadata" in path or isinstance(value, bool):
            continue
        if isinstance(value, int):
            numbers.append(path)
        elif _is_address(value):
            addresses.append(path)

    def build(path: tuple[Any, ...], value: Any) -> dict[str, Any]:  # noqa: ANN401
        data = copy.deepcopy(base)
        _apply(data, path, "replace", value)
        return data

    return st.one_of(
        st.builds(build, st.sampled_from(numbers), st.booleans()),
        st.builds(
            build,
            st.sampled_from(addresses),
            st.one_of(st.booleans(), st.integers(0, 2**128 - 1)),
        ),
    )


@st.composite
def written(draw: st.DrawFn, data: dict[str, Any]) -> str:
    """Return a configuration as a hand-written file: its layout, with comments."""
    text = yaml.safe_dump(
        data,
        indent=draw(st.sampled_from([2, 4])),
        sort_keys=draw(st.booleans()),
        default_style=draw(st.sampled_from([None, None, '"', "'"])),
        explicit_start=draw(st.booleans()),
    )
    lines = text.splitlines()
    comments = draw(st.lists(st.integers(0, len(lines)), max_size=4))
    for at in sorted(comments, reverse=True):
        indent = draw(st.sampled_from(["", "  ", "      "]))
        lines.insert(at, f"{indent}# {draw(st.sampled_from(COMMENTS))}")
    return "\n".join(lines) + draw(st.sampled_from(["\n", "\n", "", "\n\n"]))


# Comments that look like configuration.
COMMENTS = ["A comment", "type: ipsec", "id: C0003-00", "version: 0.0.1", "mode: hub:"]

# Text that isn't (valid) YAML, or a configuration that's hard to read.
RAW = [
    "",
    "---\n",
    "- a\n- b\n",
    "{",
    "id: [unclosed\n",
    "\tid: C0003\n",
    "\ufeffid: C0003\n",
    "!!python/object/apply:os.system ['true']\n",
    "a: &a [*a]\n",
    "id: C0003\nid: C0001\n",
    "version: 0.1.5\nid: C0001\n",
    "version: 0.1.5\nid: C0003\nnetwork_instances: &n {00: *n}\n",
]

# The baseline as vpnc stores it, set by the test that applies it: with the
# NPTv6 prefixes vpnc assigns. A file without them is the baseline too, but
# vpnc assigns them again, which takes a moment.
STORED: dict[str, Any] = {}


def stored() -> dict[str, Any]:
    """Return the baseline as vpnc stores it (before it's applied: as it is)."""
    return copy.deepcopy(STORED or BASELINE)


base = st.builds(stored)
# A file's text, and what vpnc must do with it if that's known: "applied" (it's
# valid and differs from the baseline), "same" (it's the baseline) or "refused".
file_texts = st.one_of(
    st.sampled_from(RAW).map(lambda text: (text, None)),
    st.text(st.characters(exclude_categories=("Cs",)), max_size=200).map(
        lambda text: (text, None),
    ),
    base.flatmap(changed).map(yaml.safe_dump).map(lambda text: (text, None)),
    base.flatmap(valid)
    .flatmap(lambda change: written(change[0]))
    .map(lambda text: (text, "applied")),
    base.flatmap(written).map(lambda text: (text, "same")),
    base.flatmap(mistyped).map(yaml.safe_dump).map(lambda text: (text, "refused")),
)

# A request, what vpnc must do with it, and what a valid one changes.
requests = st.one_of(
    st.tuples(
        st.just("PUT"), base.flatmap(changed), st.just(Expected.EITHER), st.none()
    ),
    base.flatmap(valid).map(
        lambda change: ("PUT", change[0], Expected.ACCEPT, change[1])
    ),
    st.tuples(
        st.just("PATCH"), base.flatmap(patches), st.just(Expected.EITHER), st.none()
    ),
    st.tuples(
        st.just("PUT"), base.flatmap(mistyped), st.just(Expected.REJECT), st.none()
    ),
)
