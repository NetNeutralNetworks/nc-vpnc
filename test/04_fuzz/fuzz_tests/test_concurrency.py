"""Concurrent configuration changes: the API and hand edits at the same time.

Threads run generated sequences of API calls (stage, patch, commit, discard,
delete, read) and edits of the active files, on two tenants they share. No call
may fail with a server error and vpnc must keep running. Afterwards what runs
must be what the files say: applied in full, and the same after hub00 restarts
from them.
"""

from __future__ import annotations

import concurrent.futures
import os
from typing import Any

import pytest
import yaml
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest
from .test_config_states import RESTART_TIMEOUT, restart, same, without_processes

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# Each example ends with a restart: about 25 s.
CONCURRENCY = settings(
    max_examples=max(2, int(os.environ.get("FUZZ_EXAMPLES", "100")) // 2),
    deadline=None,
)
TENANTS = ("C0006", "C0007")
THREADS = 3
OK = 200
APPLY_TIMEOUT = 120
# The watcher handles each file event 0.1 s after it, and a file written by hand
# may be read half-written: within this time its last event is handled.
SETTLE_TIMEOUT = 10


def variant(tenant: str, number: int) -> dict[str, Any]:
    """Return one of a tenant's valid configurations."""
    t = TENANTS.index(tenant)
    return {
        "version": "0.1.4",
        "id": tenant,
        "name": f"Concurrency {number}",
        "network_instances": {
            "00": {
                "type": "DOWNLINK",
                "connections": {
                    0: {
                        "enabled": number != 1,
                        "routes": {
                            "ipv4": [{"to": f"10.{70 + t}.{number}.0/24"}],
                            "ipv6": [],
                        },
                        "config": {
                            "type": "IPSEC",
                            "remote_addrs": [f"192.0.2.{170 + t}"],
                            "initiation": "NONE",
                            "ike_proposal": [
                                "aes256gcm16-prfsha384-ecp384",
                                "aes128gcm16-prfsha256-x25519",
                                "aes256-sha256-modp3072",
                            ][number],
                            "psk": f"fuzz-concurrency-preshared-key-{t}{number}",
                        },
                    },
                },
            },
        },
    }


tenant = st.sampled_from(TENANTS)
number = st.integers(0, 2)
operation = st.one_of(
    st.tuples(st.just("put"), tenant, number),
    st.tuples(st.just("patch"), tenant, number),
    st.tuples(st.just("commit"), tenant),
    st.tuples(st.just("discard"), tenant),
    st.tuples(st.just("delete"), tenant),
    st.tuples(st.just("read"), tenant),
    st.tuples(st.just("write"), tenant, number),
    st.tuples(st.just("remove"), tenant),
)


def url(t: str) -> str:
    """Return a tenant's configuration URL."""
    return f"/v1/config/tenants/{t}"


def run(op: tuple[Any, ...]) -> None:
    """Run an operation; server errors raise."""
    kind, t, *rest = op
    if kind == "put":
        conftest.api("PUT", url(t), variant(t, rest[0]))
    elif kind == "patch":
        conftest.api("PATCH", url(t), {"name": f"Patched {rest[0]}"})
    elif kind in ("commit", "discard"):
        conftest.api("POST", f"{url(t)}/{kind}")
    elif kind == "delete":
        conftest.api("DELETE", url(t))
    elif kind == "read":
        conftest.api("GET", url(t))
        conftest.api("GET", "/v1/config/tenants")
    elif kind == "write":
        conftest.write_file(
            conftest.HOST,
            f"{conftest.ACTIVE_DIR}/{t}.yaml",
            yaml.safe_dump(variant(t, rest[0])),
        )
    elif kind == "remove":
        conftest.run_cmd(conftest.HOST, f"rm -f {conftest.ACTIVE_DIR}/{t}.yaml")


def remove_tenants() -> None:
    """Remove the tenants' files, and wait until they're gone."""
    for t in TENANTS:
        conftest.run_cmd(
            conftest.HOST,
            f"rm -rf {conftest.ACTIVE_DIR}/{t}.yaml {conftest.CANDIDATE_DIR}/{t}.yaml"
            f" {conftest.HISTORY_DIR}/{t}",
        )
    conftest.wait_until(
        lambda: not any(ni.startswith(TENANTS) for ni in conftest.snapshot()),
        timeout=APPLY_TIMEOUT,
        message="the tenants to be removed",
    )


def file_errors() -> dict[str, str]:
    """Return why the tenants' files aren't loaded."""
    listed = {c["id"]: c for c in conftest.api("GET", "/v1/config/tenants")[1]}
    return {t: listed[t]["error"] for t in TENANTS if listed.get(t, {}).get("error")}


def files() -> dict[str, Any]:
    """Return the tenants' active files, parsed (None: there's none)."""
    found = {}
    for t in TENANTS:
        text = conftest.run_cmd_shell(
            conftest.HOST,
            f"bash -c 'cat {conftest.ACTIVE_DIR}/{t}.yaml 2> /dev/null || true'",
        )
        found[t] = yaml.safe_load(text) if text.strip() else None
    return found


@CONCURRENCY
@given(
    sequences=st.lists(
        st.lists(operation, min_size=1, max_size=8),
        min_size=THREADS,
        max_size=THREADS,
    ),
)
def test_concurrency(deployed: conftest.Deployed, sequences: list[list[Any]]) -> None:
    """Concurrent changes leave vpnc running what its files say."""
    try:
        with concurrent.futures.ThreadPoolExecutor(THREADS) as pool:
            for future in [
                pool.submit(lambda s=s: [run(op) for op in s]) for s in sequences
            ]:
                future.result()
        assert conftest.restarts() == 0, "vpnc exited"

        try:
            conftest.wait_until(
                lambda: not file_errors(),
                timeout=SETTLE_TIMEOUT,
                message="the files to be loaded",
            )
        except TimeoutError:
            msg = f"files not loaded: {file_errors()}"
            raise AssertionError(msg) from None
        event(f"tenants with a file: {sum(f is not None for f in files().values())}")

        before = conftest.stable()
        conftest.check_loaded()
        conftest.check_answering()
        running = {t: conftest.api("GET", url(t))[0] == OK for t in TENANTS}
        on_disk = files()
        for t in TENANTS:
            assert running[t] == (on_disk[t] is not None), (
                f"{t}: runs {running[t]}, has a file {on_disk[t] is not None}"
            )

        restart(deployed)
        try:
            conftest.wait_until(
                lambda: same(before, conftest.snapshot()),
                timeout=RESTART_TIMEOUT,
                interval=3,
                message="the state from before the restart",
            )
        except TimeoutError:
            changes = conftest.diff(
                without_processes(before),
                without_processes(conftest.snapshot()),
            )
            msg = "\n".join(
                ["not what the files say: different after a restart:", *changes]
            )
            raise AssertionError(msg) from None
        conftest.check_bgp()
    finally:
        remove_tenants()


def test_concurrency_cleanup(deployed: conftest.Deployed) -> None:
    """Leave hub00 as deployed."""
    remove_tenants()
    deployed.reset()
