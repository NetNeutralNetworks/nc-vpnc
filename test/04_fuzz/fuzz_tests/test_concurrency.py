"""Concurrent configuration changes: the API and hand edits at the same time.

Threads run generated sequences of API calls (stage, patch, commit, discard,
delete, read) and edits of the active files, on two tenants they share. No call
may fail with a server error and vpnc must keep running. Afterwards what runs
must be what the files say: the configuration vpnc reports and the state it
applied (network instances, connections, routes, what charon has loaded), and
for one example in four also the same after hub00 restarts from the files.
"""

from __future__ import annotations

import concurrent.futures
import os
import uuid
from typing import Any

import pytest
import yaml
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest
from .test_config_states import charon_problems, restarted_the_same

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# An example takes about 3 s, one that ends with a restart about 25 s.
CONCURRENCY = settings(
    max_examples=max(2, int(os.environ.get("FUZZ_EXAMPLES", "100"))),
    deadline=None,
    database=conftest.DATABASE,
)
TENANTS = ("C0006", "C0007")
THREADS = 3
OK = 200
APPLY_TIMEOUT = 120


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
                            "ike_lifetime": 3600 * (1 + number),
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
        # Moved into place: two writes in place leave a mix (see test_torn_writes).
        conftest.write_file(
            conftest.HOST,
            f"{conftest.ACTIVE_DIR}/{t}.yaml",
            yaml.safe_dump(variant(t, rest[0])),
            via=f"{conftest.CONFIG_DIR}/.fuzz-{t}-{uuid.uuid4().hex}.yaml",
        )
    elif kind == "remove":
        conftest.run_cmd(conftest.HOST, f"rm -f {conftest.ACTIVE_DIR}/{t}.yaml")


def remove_tenants() -> None:
    """Remove the tenants' files, and wait until they're gone."""
    conftest.sh(
        conftest.HOST,
        " ".join(
            f"rm -rf {conftest.ACTIVE_DIR}/{t}.yaml {conftest.CANDIDATE_DIR}/{t}.yaml"
            f" {conftest.HISTORY_DIR}/{t};"
            for t in TENANTS
        ),
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
    texts = conftest.batch(
        conftest.HOST,
        [conftest.command(["cat", f"{conftest.ACTIVE_DIR}/{t}.yaml"]) for t in TENANTS],
    )
    return {
        t: yaml.safe_load(text["out"]) if text.get("out", "").strip() else None
        for t, text in zip(TENANTS, texts, strict=True)
    }


def settings_of(configuration: dict[str, Any]) -> tuple[Any, ...]:
    """Return what a variant sets, from a file or as vpnc reports it."""
    connections = configuration["network_instances"]["00"]["connections"]
    connection = connections[0] if 0 in connections else connections["0"]
    return (
        configuration["name"],
        connection.get("enabled", True),
        connection["routes"]["ipv4"][0]["to"],
        connection["config"]["ike_proposal"],
        connection["config"]["ike_lifetime"],
        connection["config"]["psk"],
    )


def running() -> dict[str, Any]:
    """Return the configuration each tenant runs (None: it doesn't)."""
    answers = conftest.gets([f"{url(t)}?reveal_secrets=true" for t in TENANTS])
    return {
        t: answer if status == OK else None
        for t, (status, answer) in zip(TENANTS, answers, strict=True)
    }


def problems(on_disk: dict[str, Any]) -> list[str]:
    """Return how what vpnc runs and applied differs from what the files say."""
    found = []
    state = conftest.snapshot()
    loaded = {line[1:].split()[0]: line for line in state["(charon)"]["connections"]}
    for t, configuration in running().items():
        ni = f"{t}-00"
        if on_disk[t] is None or configuration is None:
            if (on_disk[t] is None) != (configuration is None):
                found.append(f"{t} runs {configuration}, its file says {on_disk[t]}")
            if configuration is None and ni in state:
                found.append(f"{t} doesn't run, but has network instance {ni}")
            continue
        if settings_of(configuration) != settings_of(on_disk[t]):
            found.append(
                f"{t} runs {settings_of(configuration)},"
                f" its file says {settings_of(on_disk[t])}",
            )
        connection = configuration["network_instances"]["00"]["connections"]["0"]
        if ni not in state:
            found.append(f"{t} runs, but has no network instance {ni}")
            continue
        admin = (f"{ni}-0", "UP" if connection["enabled"] else "DOWN")
        if admin not in state["(vpnc)"]["admin_status"]:
            found.append(f"{ni}-0 isn't {admin[1]}")
        route = connection["routes"]["ipv4"][0]["to"]
        if connection["enabled"] and route not in {r[2] for r in state[ni]["routes"]}:
            found.append(f"{ni}-0 has no route to {route}")
        found += charon_problems(f"{ni}-0", connection, loaded)
    return found or conftest.unsound()


@pytest.fixture(scope="module")
def canary(deployed: conftest.Deployed) -> conftest.Canary:  # noqa: ARG001
    """Return what tells that vpnc handled the files written so far."""
    return conftest.Canary()


@CONCURRENCY
@given(
    sequences=st.lists(
        st.lists(operation, min_size=1, max_size=8),
        min_size=THREADS,
        max_size=THREADS,
    ),
    restart=st.sampled_from([True, False, False, False]),
)
def test_concurrency(
    deployed: conftest.Deployed,
    canary: conftest.Canary,
    sequences: list[list[Any]],
    restart: bool,  # noqa: FBT001
) -> None:
    """Concurrent changes leave vpnc running what its files say."""
    try:
        with concurrent.futures.ThreadPoolExecutor(THREADS) as pool:
            for future in [
                pool.submit(lambda s=s: [run(op) for op in s]) for s in sequences
            ]:
                future.result()
        assert conftest.restarts() == 0, "vpnc exited"

        # A file written by hand may be read half-written: its last change counts.
        canary.settled()
        assert not file_errors(), f"files not loaded: {file_errors()}"
        on_disk = files()
        event(f"tenants with a file: {sum(f is not None for f in on_disk.values())}")
        try:
            conftest.wait_until(
                lambda: not problems(on_disk),
                timeout=APPLY_TIMEOUT,
                message="what the files say",
            )
        except TimeoutError:
            raise AssertionError("\n".join(problems(on_disk))) from None

        if restart:
            restarted_the_same(
                deployed,
                "not what the files say: different after a restart:",
            )
            conftest.check_bgp()
    finally:
        remove_tenants()


def file_text(t: str) -> str:
    """Return a tenant's active file as it is."""
    return conftest.sh(conftest.HOST, ["cat", f"{conftest.ACTIVE_DIR}/{t}.yaml"])


def follows(t: str, *before: tuple[Any, ...] | None) -> None:
    """Check a tenant once vpnc handled its file: loaded, or reported and unchanged.

    before: what it may run if the file isn't loaded (settings_of; None: nothing).
    """
    assert conftest.restarts() == 0, "vpnc exited"
    error = file_errors().get(t)
    if error is None:
        on_disk = yaml.safe_load(file_text(t))
        conftest.wait_until(
            lambda: (
                running()[t] is not None
                and settings_of(running()[t]) == settings_of(on_disk)
            ),
            timeout=APPLY_TIMEOUT,
            message=f"{t} to run its file",
        )
        return
    now = running()[t]
    assert (settings_of(now) if now else None) in before, (
        f"{t}'s file isn't loaded ({error}), but what it runs changed"
    )


def test_torn_writes(deployed: conftest.Deployed, canary: conftest.Canary) -> None:  # noqa: ARG001
    """A file written in place may be read half-written: reported, never applied."""
    t = TENANTS[0]
    path = f"{conftest.ACTIVE_DIR}/{t}.yaml"
    via = f"{conftest.CONFIG_DIR}/.fuzz-{t}-torn.yaml"
    try:
        conftest.write_file(conftest.HOST, path, yaml.safe_dump(variant(t, 0)), via=via)
        canary.settled()
        follows(t, None)
        before = settings_of(running()[t])

        # Half of another variant, in place.
        text = yaml.safe_dump(variant(t, 2))
        conftest.write_file(conftest.HOST, path, text[: len(text) // 2])
        canary.settled()
        assert file_errors().get(t), "a half-written file isn't reported"
        follows(t, before)

        # Two variants in place at once: whatever the file ends as.
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            for future in [
                pool.submit(
                    conftest.write_file,
                    conftest.HOST,
                    path,
                    yaml.safe_dump(variant(t, n)),
                )
                for n in (1, 2)
            ]:
                future.result()
        canary.settled()
        # vpnc may have loaded one of them whole before the other's write.
        follows(t, before, *(settings_of(variant(t, n)) for n in (1, 2)))

        # A whole file moved into place: loaded.
        conftest.write_file(conftest.HOST, path, yaml.safe_dump(variant(t, 1)), via=via)
        canary.settled()
        assert not file_errors().get(t), f"not loaded: {file_errors().get(t)}"
        follows(t, None)
    finally:
        remove_tenants()


def test_concurrency_cleanup(
    deployed: conftest.Deployed, canary: conftest.Canary
) -> None:
    """Leave hub00 as deployed."""
    canary.remove()
    remove_tenants()
    deployed.reset()
