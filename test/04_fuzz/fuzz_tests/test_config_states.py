"""Sequences of valid configuration changes, each committed with the API.

A tenant's network instances and connections are added, changed, disabled and
removed. After each commit vpnc must have applied it in full: its network
instances, connections and routes, what charon, nftables, FRR and vpncmangle
took, and they answer. At the end hub00 restarts: started fresh from its files,
it must get back to the same state.
"""

from __future__ import annotations

import base64
import os
from typing import Any

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

from . import conftest

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

TENANT = "C0005"
URL = f"/v1/config/tenants/{TENANT}"
NI_KEYS = ("00", "01", "02")
CONNECTION_KEYS = (0, 1, 2)
# Each sequence is a few commits; a sequence costs about a minute.
STATES = settings(
    max_examples=max(2, int(os.environ.get("FUZZ_EXAMPLES", "100")) // 10),
    stateful_step_count=6,
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
APPLY_TIMEOUT = 120
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
    """Return a valid connection; its addresses, routes and port its own."""
    n = number(ni, key)
    routes: dict[str, list[dict[str, Any]]] = {
        "ipv4": draw(st.sampled_from([[], [{"to": f"10.60.{n}.0/24"}]])),
        "ipv6": draw(
            st.sampled_from(
                [
                    [],
                    [{"to": f"2001:db8:c60:{n}00::/56", "nptv6": False}],
                    [{"to": f"fdff:db8:c60:{n}00::/56", "nptv6": True}],
                ],
            ),
        ),
    }
    remote = f"192.0.2.{150 + n}"
    kind = draw(st.sampled_from(["IPSEC", "WIREGUARD"]))
    if kind == "IPSEC":
        config: dict[str, Any] = {
            "type": "IPSEC",
            "remote_addrs": [remote],
            "ike_proposal": draw(st.sampled_from(IKE_PROPOSALS)),
            "ipsec_proposal": draw(st.sampled_from(ESP_PROPOSALS)),
            # The peer doesn't exist.
            "initiation": "NONE",
            "psk": f"fuzz-states-preshared-key-{n:06d}",
        }
    else:
        config = {
            "type": "WIREGUARD",
            "remote_addrs": [remote],
            "local_port": 51840 + n,
            "private_key": draw(wireguard_key),
            "public_key": draw(wireguard_key),
        }
    return {
        "enabled": draw(st.booleans()),
        "interface": draw(
            st.sampled_from(
                [
                    {"ipv4": [], "ipv6": []},
                    {"ipv4": [f"10.240.{n}.1/30"], "ipv6": [f"fdcc:240:{n}::1/64"]},
                ],
            ),
        ),
        "routes": routes,
        "config": config,
    }


class ConfigStates(RuleBasedStateMachine):
    """A tenant changed a commit at a time; its state must follow."""

    deployed: conftest.Deployed

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

    @property
    def nis(self) -> dict[str, Any]:
        """Return the tenant's network instances."""
        return self.config["network_instances"]

    def connections(self) -> list[tuple[str, int]]:
        """Return the tenant's connections by network instance and key."""
        return [(ni, key) for ni, cfg in self.nis.items() for key in cfg["connections"]]

    def commit(self, change: str) -> None:
        """Stage the configuration, commit it and (unless not) check it's applied."""
        status, detail = conftest.api("PUT", URL, self.config)
        assert status == 200, f"{change}: refused: {detail}"  # noqa: PLR2004
        status, detail = conftest.api("POST", f"{URL}/commit")
        assert status == 200, f"{change}: commit refused: {detail}"  # noqa: PLR2004
        self.created = True
        if self.checking:
            self.check(change)

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

    def check(self, change: str) -> None:
        """Check that the configuration is applied in full, and all answer."""
        try:
            conftest.wait_until(
                lambda: not self.problems(conftest.snapshot()),
                timeout=APPLY_TIMEOUT,
                interval=2,
                message=change,
            )
        except TimeoutError:
            problems = self.problems(conftest.snapshot())
            raise AssertionError(
                "\n".join([f"{change}: not applied", *problems])
            ) from None
        conftest.stable()
        conftest.check_loaded()
        conftest.check_answering()

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
        for ni, cfg in self.nis.items():
            routes = {r[2] for r in state.get(f"{TENANT}-{ni}", {}).get("routes", ())}
            for key, c in cfg["connections"].items():
                problems += [
                    f"no route to {route['to']} ({TENANT}-{ni}-{key})"
                    for route in c["routes"]["ipv4"]
                    if c["enabled"] and route["to"] not in routes
                ]
        return problems

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
        self.commit(f"add {ni}-{key}")

    @precondition(lambda self: self.connections())
    @rule(data=st.data())
    def replace_connection(self, data: st.DataObject) -> None:
        """Replace a connection with another (type, routes, addresses, keys)."""
        ni, key = data.draw(st.sampled_from(self.connections()))
        self.nis[ni]["connections"][key] = data.draw(connection(ni, key))
        self.commit(f"replace {ni}-{key}")

    @precondition(lambda self: self.connections())
    @rule(data=st.data())
    def toggle_connection(self, data: st.DataObject) -> None:
        """Disable or enable a connection."""
        ni, key = data.draw(st.sampled_from(self.connections()))
        c = self.nis[ni]["connections"][key]
        c["enabled"] = not c["enabled"]
        self.commit(f"{'enable' if c['enabled'] else 'disable'} {ni}-{key}")

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
        """Restart hub00: from its files it must get back to the same state."""
        if self.created:
            before = conftest.stable()
            restart(self.deployed)
            try:
                conftest.wait_until(
                    lambda: same(before, conftest.snapshot()),
                    timeout=RESTART_TIMEOUT,
                    interval=3,
                    message="the state from before the restart",
                )
            except TimeoutError:
                changes = conftest.diff(
                    without_processes(before), without_processes(conftest.snapshot())
                )
                raise AssertionError(
                    "\n".join(["not the same after a restart:", *changes]),
                ) from None
            conftest.check_loaded()
            conftest.check_answering()
        remove_tenant()


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


def remove_tenant() -> None:
    """Remove the tenant's files, and wait until it's gone."""
    conftest.run_cmd(
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
