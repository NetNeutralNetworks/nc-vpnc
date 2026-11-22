"""Sequences of valid configuration changes, each committed with the API.

A tenant's network instances and connections are added, changed, disabled and
removed. After each commit vpnc must have applied it in full: its network
instances, connections, interfaces, addresses and routes, what charon and
WireGuard run for them (peers, ids, lifetimes, traffic selectors, ports, keys),
what nftables, FRR and vpncmangle took, and they answer. At the end of half of
the sequences hub00 restarts: started fresh from its files, it must get back to
the same state.
"""

from __future__ import annotations

import base64
import ipaddress
import os
from typing import Any

import pytest
from fuzz_common import policy_oracle
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

from . import conftest
from . import test_firewall_policy as firewall

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

TENANT = "C0005"
URL = f"/v1/config/tenants/{TENANT}"
NI_KEYS = ("00", "01", "02")
CONNECTION_KEYS = (0, 1, 2)
# A change takes about a second, a restart about 20: a sequence about 20 s.
STEPS = 10
STATES = settings(
    max_examples=max(2, int(os.environ.get("FUZZ_EXAMPLES", "100")) // 5),
    stateful_step_count=STEPS,
    deadline=None,
)
IKE_PROPOSALS = [
    "aes256gcm16-prfsha384-ecp384",
    "aes128gcm16-prfsha256-x25519",
    "aes256-sha256-modp3072",
    "chacha20poly1305-prfsha256-curve25519",
]
ESP_PROPOSALS = [
    "aes256gcm16-ecp384",
    "aes128gcm16",
    "aes256-sha256",
    "aes256gcm16-esn",
]
APPLY_TIMEOUT = 60
# Back to the state from before the restart.
RESTART_TIMEOUT = 300

wireguard_key = st.binary(min_size=32, max_size=32).map(
    lambda key: base64.b64encode(key).decode(),
)


def number(ni: str, connection: int) -> int:
    """Return a connection's number in the tenant, for addresses and ports."""
    return int(ni) * len(CONNECTION_KEYS) + connection


@st.composite
def connection(draw: st.DrawFn, ni: str, key: int) -> dict[str, Any]:
    """Return a valid connection; its addresses, routes and ports its own.

    With every setting that vpnc gives a default, so that the checks know it.
    """
    n = number(ni, key)
    routes: dict[str, list[dict[str, Any]]] = {
        "ipv4": draw(
            st.sampled_from(
                [
                    [],
                    [{"to": f"10.60.{n}.0/24"}],
                    [{"to": f"10.60.{n}.0/24"}, {"to": f"10.61.{n}.0/25"}],
                ],
            ),
        ),
        "ipv6": draw(
            st.lists(
                st.sampled_from(
                    [
                        {"to": f"2001:db8:c60:{n}00::/56", "nptv6": False},
                        {"to": f"fdff:db8:c60:{n}00::/56", "nptv6": True},
                        {"to": f"fdff:db8:c61:{n}ff::/64", "nptv6": True},
                    ],
                ),
                max_size=2,
                unique_by=lambda route: route["to"],
            ),
        ),
    }
    # Hosts in the routes: the peer doesn't exist, so none answers.
    probes = []
    if routes["ipv4"]:
        probes = draw(
            st.lists(
                st.sampled_from(
                    [
                        {"address": f"10.60.{n}.1", "test_type": "ICMP"},
                        {"address": f"10.60.{n}.2", "test_type": "TCP", "port": 443},
                    ],
                ),
                max_size=2,
                unique_by=lambda probe: probe["address"],
            ),
        )
    remotes = draw(
        st.sampled_from(
            [
                [f"192.0.2.{150 + n}"],
                [f"192.0.2.{150 + n}", f"2001:db8::{150 + n:x}"],
                [f"2001:db8::{150 + n:x}"],
            ],
        ),
    )
    kind = draw(st.sampled_from(["IPSEC", "WIREGUARD"]))
    if kind == "IPSEC":
        selectors = draw(st.booleans())
        config: dict[str, Any] = {
            "type": "IPSEC",
            "remote_addrs": remotes,
            "local_id": draw(st.sampled_from([None, "hub.fuzz.example"])),
            "remote_id": draw(st.sampled_from([None, f"peer{n}.fuzz.example"])),
            "ike_proposal": draw(st.sampled_from(IKE_PROPOSALS)),
            "ike_lifetime": draw(st.sampled_from([86400, 3600])),
            "ipsec_proposal": draw(st.sampled_from(ESP_PROPOSALS)),
            "ipsec_lifetime": draw(st.sampled_from([3600, 900])),
            # The peer doesn't exist.
            "initiation": "NONE",
            "psk": f"fuzz-states-preshared-key-{n:06d}",
            "traffic_selectors": {
                "local": [f"10.20.{n}.0/24"] if selectors else [],
                "remote": [f"10.60.{n}.0/24"] if selectors else [],
            },
        }
    else:
        config = {
            "type": "WIREGUARD",
            "remote_addrs": remotes,
            "local_port": 51840 + n,
            "remote_port": draw(st.sampled_from([51820, 51900 + n])),
            "private_key": draw(wireguard_key),
            "public_key": draw(wireguard_key),
        }
    return {
        "enabled": draw(st.booleans()),
        "metadata": draw(st.sampled_from([{}, {"owner": "fuzz"}])),
        "mtu": draw(st.sampled_from([None, 1280, 1400])),
        "interface": draw(
            st.sampled_from(
                [
                    {"ipv4": [], "ipv6": []},
                    {"ipv4": [f"10.240.{n}.1/30"], "ipv6": [f"fdcc:240:{n}::1/64"]},
                ],
            ),
        ),
        "routes": routes,
        "probes": probes,
        "config": config,
    }


def charon_problems(name: str, c: dict[str, Any], loaded: dict[str, str]) -> list[str]:
    """Return how charon's connection differs from an IPsec connection's settings."""
    settings_ = c["config"]
    line = loaded.get(name)
    if not c["enabled"]:
        return [f"{name} is disabled, but loaded in charon"] if line else []
    if not line:
        return [f"{name} isn't loaded in charon"]
    ike, _, child = line.partition(" children ")
    selectors = settings_["traffic_selectors"]
    expected = {
        "peers": (ike, f"remote_addrs=[{' '.join(settings_['remote_addrs'])}]"),
        "remote id": (
            ike,
            f"id={settings_['remote_id'] or settings_['remote_addrs'][0]} ",
        ),
        "IKE lifetime": (ike, f"rekey_time={settings_['ike_lifetime']} "),
        "IPsec lifetime": (child, f"rekey_time={settings_['ipsec_lifetime']} "),
        "local traffic selectors": (
            child,
            f"local-ts=[{' '.join(selectors['local']) or '0.0.0.0/0 ::/0'}]",
        ),
        "remote traffic selectors": (
            child,
            f"remote-ts=[{' '.join(selectors['remote']) or '0.0.0.0/0 ::/0'}]",
        ),
    }
    if settings_["local_id"]:
        expected["local id"] = (ike, f"id={settings_['local_id']} ")
    return [
        f"{name}: charon doesn't have the {what} ({text}): {line}"
        for what, (part, text) in expected.items()
        if text not in part
    ]


def wireguard_problems(
    name: str,
    c: dict[str, Any],
    wireguard: set[tuple[str, ...]],
) -> list[str]:
    """Return how WireGuard's interface differs from a connection's settings."""
    settings_ = c["config"]
    interface = f"wg-{name}"
    problems = []
    port = str(settings_["local_port"])
    if not any(e[:2] == (interface, "interface") and e[3] == port for e in wireguard):
        problems.append(f"{name}: WireGuard doesn't listen on port {port}")
    peers = {e[2:] for e in wireguard if e[:2] == (interface, "peer")}
    allowed = sorted(
        str(ipaddress.ip_network(route["to"]))
        for route in [*c["routes"]["ipv4"], *c["routes"]["ipv6"]]
    )
    # A peer without allowed IPs has none listed.
    expected = {(settings_["public_key"], ",".join(allowed) or "(none)")}
    if peers != (expected if c["enabled"] else set()):
        problems.append(f"{name}: WireGuard has the peers {sorted(peers)}")
    return problems


class ConfigStates(RuleBasedStateMachine):
    """A tenant changed a commit at a time; its state must follow."""

    deployed: conftest.Deployed
    # How long a change may take to be applied.
    apply_timeout = APPLY_TIMEOUT
    # Whether a sequence may send packets throughout (not while hub00 crashes).
    watching = True

    def __init__(self) -> None:
        """Start without the tenant."""
        super().__init__()
        self.config: dict[str, Any] = {
            "version": "0.1.4",
            "id": TENANT,
            "name": "Fuzz states",
            "network_instances": {},
        }
        self.created = False
        # Whether a commit checks it's applied.
        self.checking = True
        # Whether a fault or crash may have left the lab's tunnels down.
        self.disturbed = False
        # Whether hub00 restarts at the end.
        self.restart = True
        # Packets that hub00 must stop, throughout a sequence.
        self.watch: firewall.Watch | None = None
        # Whether a change failed: then the sequence ends without its restart.
        self.failed = False

    @initialize(restart=st.booleans(), watch=st.integers(0, 3))
    def with_or_without_restart(self, restart: bool, watch: int) -> None:  # noqa: FBT001
        """Restart hub00 at the end of this sequence, or not: it takes as long.

        In one of four, send packets that hub00 must stop while it commits.
        """
        self.restart = restart
        if watch == 0 and self.watching:
            self.watch = firewall.Watch()

    @property
    def nis(self) -> dict[str, Any]:
        """Return the tenant's network instances."""
        return self.config["network_instances"]

    def connections(self) -> list[tuple[str, int]]:
        """Return the tenant's connections by network instance and key."""
        return [(ni, key) for ni, cfg in self.nis.items() for key in cfg["connections"]]

    def commit(self, change: str) -> None:
        """Stage the configuration, commit it and (unless not) check it's applied."""
        try:
            status, detail = conftest.api("PUT", URL, self.config)
            assert status == 200, f"{change}: refused: {detail}"  # noqa: PLR2004
            status, detail = conftest.api("POST", f"{URL}/commit")
            assert status == 200, f"{change}: commit refused: {detail}"  # noqa: PLR2004
            self.created = True
            if self.checking:
                self.check(change)
        except BaseException:
            self.failed = True
            raise

    def ipsec(self) -> list[tuple[str, int]]:
        """Return the tenant's IPsec connections by network instance and key."""
        return [
            (ni, key)
            for ni, key in self.connections()
            if self.nis[ni]["connections"][key]["config"]["type"] == "IPSEC"
        ]

    def committed_resets(
        self, ni: str, key: int, change: str, expected: set[str]
    ) -> None:
        """Commit a change; check the connection's new CONFIG_RESET events.

        expected: what one new event must name; none if empty.
        """
        before = resets(ni, key)
        self.commit(change)
        if not expected:
            new = [e for e in resets(ni, key) if e not in before]
            assert not new, f"{change}: reset {new}"
            return
        try:
            conftest.wait_until(
                lambda: [e for e in resets(ni, key) if e not in before],
                timeout=10,
                message=f"{change}: a CONFIG_RESET event",
            )
        except TimeoutError:
            self.failed = True
            missing = f"{change}: no CONFIG_RESET event"
            raise AssertionError(missing) from None
        new = [e for e in resets(ni, key) if e not in before]
        assert len(new) == 1, f"{change}: {len(new)} resets: {new}"
        named = set(new[0]["details"].get("changed", []))
        assert named == expected, f"{change}: reset for {named}, not {expected}"

    def change_unchecked(self, data: st.DataObject) -> str:
        """Commit a change without checking it's applied (e.g. during a fault)."""
        self.checking = False
        try:
            if self.connections():
                self.toggle_connection(data)
                return "a connection toggled"
            if len(self.nis) < len(NI_KEYS):
                self.add_network_instance(data)
                return "a network instance added"
            self.add_connection(data)
            return "a connection added"
        finally:
            self.checking = True

    def pending(self) -> list[str]:
        """Return what isn't as configured, or doesn't run or answer.

        vpncmangle's answer only while no fault or crash took the tunnel down
        that it goes through.
        """
        state = conftest.snapshot()
        return self.problems(state) or conftest.unsound(dns=not self.disturbed)

    def check(self, change: str) -> None:
        """Check that the configuration is applied in full, and all answer."""
        try:
            conftest.wait_until(
                lambda: not self.pending(),
                timeout=self.apply_timeout,
                message=change,
            )
        except TimeoutError:
            raise AssertionError(
                "\n".join([f"{change}: not applied", *self.pending()])
            ) from None

    def settled(self) -> None:
        """Wait until the lab's tunnels are up again after faults and crashes.

        A peer that hub00 dropped without telling (a crash) only connects again
        once its dead peer detection gave up, minutes later: a sequence waits
        for that once, at its end, not after each fault or crash.
        """
        if self.disturbed:
            self.deployed.healthy(after="at the end")
            self.disturbed = False
            self.check("at the end")

    def problems(self, state: dict[str, Any]) -> list[str]:
        """Return how the state differs from the configuration."""
        problems = []
        expected_nis = {f"{TENANT}-{ni}" for ni in self.nis}
        nis = {name for name in state if name.startswith(f"{TENANT}-")}
        problems += [f"missing network instance {ni}" for ni in expected_nis - nis]
        problems += [f"left network instance {ni}" for ni in nis - expected_nis]
        expected = {
            (f"{TENANT}-{ni}-{key}", "UP" if c["enabled"] else "DOWN")
            for ni, cfg in self.nis.items()
            for key, c in cfg["connections"].items()
        }
        connections = {
            item
            for item in state["(vpnc)"]["admin_status"]
            if item[0].startswith(f"{TENANT}-")
        }
        problems += [f"missing connection {c}" for c in expected - connections]
        problems += [f"left connection {c}" for c in connections - expected]
        # What charon has loaded, by connection.
        loaded = {
            line[1:].split()[0]: line
            for line in state["(charon)"]["connections"]
            if line.startswith(f"{{{TENANT}-")
        }
        names = set()
        for ni, cfg in self.nis.items():
            found = state.get(f"{TENANT}-{ni}", {})
            routes = {r[2] for r in found.get("routes", ())}
            links = dict(found.get("links", ()))
            for key, c in cfg["connections"].items():
                name = f"{TENANT}-{ni}-{key}"
                names.add(name)
                ipsec = c["config"]["type"] == "IPSEC"
                interface = f"xfrm{key}" if ipsec else f"wg-{name}"
                # An enabled connection's interface is up once its peer is.
                if interface not in links:
                    problems.append(f"{name}: no interface {interface}")
                elif links[interface] and not c["enabled"]:
                    problems.append(f"{name} is disabled, but {interface} is up")
                if c["enabled"]:
                    problems += [
                        f"no route to {route['to']} ({name})"
                        for route in [*c["routes"]["ipv4"], *c["routes"]["ipv6"]]
                        if str(ipaddress.ip_network(route["to"])) not in routes
                    ]
                    addresses = map(
                        ipaddress.ip_interface,
                        [*c["interface"]["ipv4"], *c["interface"]["ipv6"]],
                    )
                    problems += [
                        f"{name}: {interface} doesn't have {address}"
                        for address in addresses
                        if (interface, str(address.ip), address.network.prefixlen)
                        not in found.get("addresses", ())
                    ]
                if ipsec:
                    problems += charon_problems(name, c, loaded)
                else:
                    problems += wireguard_problems(
                        name, c, found.get("wireguard", set())
                    )
        problems += [
            f"{name} isn't configured, but loaded in charon"
            for name in set(loaded) - names
        ]
        for ni in self.nis:
            if f"{TENANT}-{ni}" in state:
                problems += policy_oracle.tenant(
                    state[f"{TENANT}-{ni}"]["nftables"], f"{TENANT}-{ni}"
                )
        problems += policy_oracle.external(
            state.get("EXTERNAL", {}).get("nftables", set()), *self.peers()
        )
        return problems

    def peers(self) -> tuple[set[str], set[tuple[str, int]], set[str]]:
        """Return the peers EXTERNAL must let in, and those it mustn't.

        IPsec peers; WireGuard peers with their local port; the addresses of
        disabled connections.
        """
        ipsec: set[str] = set()
        wireguard: set[tuple[str, int]] = set()
        absent: set[str] = set()
        for cfg in self.nis.values():
            for c in cfg["connections"].values():
                remotes = c["config"]["remote_addrs"]
                if not c["enabled"]:
                    absent.update(remotes)
                elif c["config"]["type"] == "IPSEC":
                    ipsec.update(remotes)
                else:
                    wireguard.add((remotes[0], c["config"]["local_port"]))
        return ipsec, wireguard, absent

    @precondition(lambda self: len(self.nis) < len(NI_KEYS))
    @rule(data=st.data())
    def add_network_instance(self, data: st.DataObject) -> None:
        """Add a network instance with a connection."""
        ni = data.draw(st.sampled_from([k for k in NI_KEYS if k not in self.nis]))
        self.nis[ni] = {
            "type": "DOWNLINK",
            "connections": {0: data.draw(connection(ni, 0))},
        }
        self.commit(f"add {ni}")

    @precondition(lambda self: self.nis)
    @rule(data=st.data())
    def remove_network_instance(self, data: st.DataObject) -> None:
        """Remove a network instance."""
        ni = data.draw(st.sampled_from(sorted(self.nis)))
        del self.nis[ni]
        self.commit(f"remove {ni}")

    @precondition(
        lambda self: any(
            len(cfg["connections"]) < len(CONNECTION_KEYS) for cfg in self.nis.values()
        ),
    )
    @rule(data=st.data())
    def add_connection(self, data: st.DataObject) -> None:
        """Add a connection to a network instance."""
        ni = data.draw(
            st.sampled_from(
                [
                    k
                    for k, cfg in sorted(self.nis.items())
                    if len(cfg["connections"]) < len(CONNECTION_KEYS)
                ],
            ),
        )
        connections = self.nis[ni]["connections"]
        key = data.draw(
            st.sampled_from([k for k in CONNECTION_KEYS if k not in connections])
        )
        connections[key] = data.draw(connection(ni, key))
        # A reset is for a connection charon had.
        self.committed_resets(ni, key, f"add {ni}-{key}", set())

    @precondition(lambda self: self.connections())
    @rule(data=st.data())
    def replace_connection(self, data: st.DataObject) -> None:
        """Replace a connection with another (type, routes, addresses, keys).

        If it stays an enabled IPsec connection, a new id or selectors reset it.
        """
        ni, key = data.draw(st.sampled_from(self.connections()))
        old = self.nis[ni]["connections"][key]
        new = data.draw(connection(ni, key))
        self.nis[ni]["connections"][key] = new
        self.committed_resets(ni, key, f"replace {ni}-{key}", kept(old, new))

    @precondition(lambda self: self.connections())
    @rule(data=st.data())
    def toggle_connection(self, data: st.DataObject) -> None:
        """Disable or enable a connection."""
        ni, key = data.draw(st.sampled_from(self.connections()))
        c = self.nis[ni]["connections"][key]
        c["enabled"] = not c["enabled"]
        self.commit(f"{'enable' if c['enabled'] else 'disable'} {ni}-{key}")

    @precondition(lambda self: self.ipsec())
    @rule(data=st.data())
    def rotate_psk(self, data: st.DataObject) -> None:
        """Give an IPsec connection a new PSK: charon's SAs have the old one."""
        ni, key = data.draw(st.sampled_from(self.ipsec()))
        c = self.nis[ni]["connections"][key]
        c["config"]["psk"] = (
            f"rotated-{data.draw(st.binary(min_size=16, max_size=16)).hex()}"
        )
        expected = {"psk"} if c["enabled"] else set()
        self.committed_resets(ni, key, f"rotate {ni}-{key}'s PSK", expected)

    @precondition(lambda self: self.ipsec())
    @rule(data=st.data())
    def change_selectors(self, data: st.DataObject) -> None:
        """Change only an IPsec connection's traffic selectors."""
        ni, key = data.draw(st.sampled_from(self.ipsec()))
        c = self.nis[ni]["connections"][key]
        n = number(ni, key)
        options = [
            {"local": [], "remote": []},
            {"local": [f"10.20.{n}.0/24"], "remote": [f"10.60.{n}.0/24"]},
            {"local": [f"10.22.{n}.0/24"], "remote": [f"10.62.{n}.0/24"]},
        ]
        old = c["config"]["traffic_selectors"]
        c["config"]["traffic_selectors"] = data.draw(
            st.sampled_from([o for o in options if o != old])
        )
        expected = {"traffic_selectors"} if c["enabled"] else set()
        self.committed_resets(ni, key, f"change {ni}-{key}'s selectors", expected)

    @precondition(lambda self: self.ipsec())
    @rule(data=st.data())
    def change_metadata(self, data: st.DataObject) -> None:
        """Change only an IPsec connection's metadata: no reset."""
        ni, key = data.draw(st.sampled_from(self.ipsec()))
        c = self.nis[ni]["connections"][key]
        c["metadata"] = {"owner": f"fuzz-{data.draw(st.integers(0, 10**6))}"}
        self.committed_resets(ni, key, f"change {ni}-{key}'s metadata", set())

    @precondition(lambda self: self.connections())
    @rule(data=st.data())
    def remove_connection(self, data: st.DataObject) -> None:
        """Remove a connection."""
        ni, key = data.draw(st.sampled_from(self.connections()))
        del self.nis[ni]["connections"][key]
        self.commit(f"remove {ni}-{key}")

    @invariant()
    def vpnc_runs(self) -> None:
        """Vpnc never exited."""
        assert conftest.restarts() == 0, "vpnc exited"

    def teardown(self) -> None:
        """Restart hub00: from its files it must get back to the same state.

        The tenant goes in any case: the next sequence starts without it.
        """
        try:
            if self.watch is not None:
                leaks = self.watch.finish()
                assert self.watch.sent, "no packets sent to CORE throughout"
                assert not leaks, "\n".join(["left C0001-00 during commits:", *leaks])
            if self.failed:
                return
            self.settled()
            if self.created and self.restart:
                restarted_the_same(self.deployed, "not the same after a restart:")
                assert not self.pending(), "\n".join(self.pending())
        finally:
            remove_tenant()


def resets(ni: str, key: int) -> list[dict[str, Any]]:
    """Return a connection's CONFIG_RESET events."""
    status, found = conftest.api(
        "GET", f"/v1/events?connection={TENANT}-{ni}-{key}&event=CONFIG_RESET"
    )
    assert status == 200, f"events: {status} {found}"  # noqa: PLR2004
    return found


def kept(old: dict[str, Any], new: dict[str, Any]) -> set[str]:
    """Return what a replaced connection's SAs keep the old of, if charon had it.

    Its PSK, ids and traffic selectors; an id not set is its default (the
    first remote address for the remote id).
    """
    if not (old["enabled"] and new["enabled"]):
        return set()
    was, now = old["config"], new["config"]
    if was["type"] != "IPSEC" or now["type"] != "IPSEC":
        return set()
    changed = set()
    if was["psk"] != now["psk"]:
        changed.add("psk")
    if was["local_id"] != now["local_id"]:
        changed.add("local_id")
    if (was["remote_id"] or was["remote_addrs"][0]) != (
        now["remote_id"] or now["remote_addrs"][0]
    ):
        changed.add("remote_id")
    if was["traffic_selectors"] != now["traffic_selectors"]:
        changed.add("traffic_selectors")
    return changed


def without_processes(state: dict[str, Any]) -> dict[str, Any]:
    """Return a state without the daemons' process ids, new after a restart."""
    return {k: v for k, v in state.items() if k != "(daemons)"}


def same(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Return whether two states are the same, but for process ids."""
    return without_processes(before) == without_processes(after)


def restart(deployed: conftest.Deployed) -> None:
    """Restart hub00 as a reboot; it's sound again after."""
    conftest.restarted_node()
    deployed.restarted()


def restarted_the_same(deployed: conftest.Deployed, failure: str) -> None:
    """Restart hub00: started from its files it gets to the state it had."""
    before = conftest.stable()
    restart(deployed)
    try:
        conftest.wait_until(
            lambda: same(before, conftest.snapshot()),
            timeout=RESTART_TIMEOUT,
            message="the state from before the restart",
        )
    except TimeoutError:
        changes = conftest.diff(
            without_processes(before),
            without_processes(conftest.snapshot()),
        )
        raise AssertionError("\n".join([failure, *changes])) from None


def remove_tenant() -> None:
    """Remove the tenant's files, and wait until it's gone."""
    conftest.sh(
        conftest.HOST,
        f"rm -rf {conftest.ACTIVE_DIR}/{TENANT}.yaml"
        f" {conftest.CANDIDATE_DIR}/{TENANT}.yaml {conftest.HISTORY_DIR}/{TENANT}",
    )
    conftest.wait_until(
        lambda: not any(ni.startswith(f"{TENANT}-") for ni in conftest.snapshot()),
        timeout=APPLY_TIMEOUT,
        message=f"{TENANT} to be removed",
    )


def test_config_states(deployed: conftest.Deployed) -> None:
    """Every sequence of valid changes is applied, and the same after a restart."""
    ConfigStates.deployed = deployed
    try:
        run_state_machine_as_test(ConfigStates, settings=STATES)
    finally:
        remove_tenant()
        deployed.reset()
