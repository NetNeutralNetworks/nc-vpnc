"""Generated configuration is refused or applied; vpnc keeps running (hub00).

A refused configuration changes nothing. An applied one is replaced by the
original again, after which the lab is as before.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st
from hypothesis.database import DirectoryBasedExampleDatabase

from . import conftest
from .strategies import BASELINE, TENANT, changed, file_texts, patches

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

FUZZ = settings(
    max_examples=int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    database=DirectoryBasedExampleDatabase(Path(__file__).parents[1] / ".hypothesis"),
)

TENANT_URL = f"/v1/config/tenants/{TENANT}"
SERVICE_URL = "/v1/config/service"
ACTIVE_FILE = f"{conftest.ACTIVE_DIR}/{TENANT}.yaml"
# The file watcher handles a change within a second; one that changes nothing
# shows nothing to wait for.
SETTLE = 2
RESTORE_TIMEOUT = 120
# Read by vpnctl; none may fail because of the configuration.
READS = [
    "/v1/status",
    "/v1/tenants",
    "/v1/network-instances",
    "/v1/connections",
    "/v1/config/tenants",
    TENANT_URL,
    f"{TENANT_URL}?revision=candidate",
    f"{TENANT_URL}/diff",
    SERVICE_URL,
]


class Baseline:
    """The tenant's configuration as vpnc stores it, and the node's state with it."""

    def __init__(self) -> None:
        """Read both, once applied: vpnc adds e.g. NPTv6 prefixes to the file."""
        self.state = conftest.stable()
        _, self.tenant = conftest.api("GET", f"{TENANT_URL}?reveal_secrets=true")
        _, self.service = conftest.api("GET", f"{SERVICE_URL}?reveal_secrets=true")


def remove_tenant() -> None:
    """Remove all of the tenant's files: active, candidate and history."""
    conftest.run_cmd(
        conftest.HOST,
        f"rm -rf {ACTIVE_FILE} {conftest.CANDIDATE_DIR}/{TENANT}.yaml"
        f" {conftest.HISTORY_DIR}/{TENANT}",
    )


@pytest.fixture(scope="module")
def baseline() -> Iterator[Baseline]:
    """Add the tenant and remove it afterwards."""
    remove_tenant()
    conftest.write_file(conftest.HOST, ACTIVE_FILE, yaml.safe_dump(BASELINE))
    conftest.wait_until(
        lambda: f"{TENANT}-01" in conftest.snapshot(),
        timeout=60,
        message=f"{TENANT} to be applied",
    )
    yield Baseline()
    remove_tenant()
    conftest.wait_until(
        lambda: f"{TENANT}-00" not in conftest.snapshot(),
        timeout=60,
        message=f"{TENANT} to be removed",
    )


def check_running() -> None:
    """Check that vpnc runs, never restarted, and answers every read."""
    assert conftest.restarts() == 0, "vpnc exited"
    for path in READS:
        conftest.api("GET", path)
    # One file can't break the list of all.
    assert conftest.api("GET", "/v1/config/tenants")[0] == 200  # noqa: PLR2004


def check_unchanged(base: Baseline) -> None:
    """Check that the node's state is still the baseline's."""
    changes = conftest.diff(base.state, conftest.snapshot())
    assert not changes, "\n".join(["refused, but the state changed:", *changes])


def put_back(base: Baseline) -> None:
    """Put the baseline's files back, without the API: it may be what failed."""
    candidates = conftest.CANDIDATE_DIR
    conftest.run_cmd(
        conftest.HOST,
        f"rm -f {candidates}/{TENANT}.yaml {candidates}/DEFAULT.yaml",
    )
    conftest.write_file(conftest.HOST, ACTIVE_FILE, yaml.safe_dump(base.tenant))


def restore(base: Baseline, failure: str) -> None:
    """Put the baseline's files back; the state must follow."""
    put_back(base)
    try:
        conftest.wait_until(
            lambda: conftest.snapshot() == base.state and not error(),
            timeout=RESTORE_TIMEOUT,
            message="the baseline state",
        )
    except TimeoutError:
        changes = conftest.diff(base.state, conftest.snapshot())
        raise AssertionError("\n".join([failure, *changes])) from None


@contextlib.contextmanager
def example(base: Baseline) -> Iterator[None]:
    """Run an example from the baseline, and put its files back afterwards."""
    restore(base, "an earlier example left the node broken:")
    try:
        yield
    finally:
        put_back(base)


def active() -> Any:  # noqa: ANN401
    """Return the configuration the tenant runs."""
    return conftest.api("GET", f"{TENANT_URL}?reveal_secrets=true")[1]


def error() -> str | None:
    """Return why the tenant's active file isn't running, from the list."""
    tenants = conftest.api("GET", "/v1/config/tenants")[1]
    return next((t["error"] for t in tenants if t["id"] == TENANT), None)


def candidate(url: str) -> Any:  # noqa: ANN401
    """Return the staged configuration (the active one if nothing is staged)."""
    return conftest.api("GET", f"{url}?revision=candidate&reveal_secrets=true")[1]


requests = st.one_of(
    st.tuples(st.just("PUT"), changed(BASELINE)),
    st.tuples(st.just("PATCH"), patches(BASELINE)),
)


@FUZZ
@given(request=requests)
def test_tenant_api(baseline: Baseline, request: tuple[str, dict[str, Any]]) -> None:
    """A staged configuration is refused, or committed or refused on commit."""
    method, body = request
    with example(baseline):
        status, _ = conftest.api(method, TENANT_URL, body)
        check_running()
        if status != 200:  # noqa: PLR2004
            event(f"{method} refused ({status})")
            assert candidate(TENANT_URL) == baseline.tenant, "refused, but staged"
            check_unchanged(baseline)
            return
        status, result = conftest.api("POST", f"{TENANT_URL}/commit")
        check_running()
        if status != 200 or not result["changed"]:  # noqa: PLR2004
            event(f"commit refused ({status})" if status != 200 else "no change")  # noqa: PLR2004
            check_unchanged(baseline)
            return
        event("applied")
        conftest.stable()
        check_running()
        restore(baseline, "not as before after restoring the configuration:")


@FUZZ
@given(data=st.data())
def test_service_api(baseline: Baseline, data: st.DataObject) -> None:
    """A staged service configuration is refused or staged; never committed here."""
    body = data.draw(changed(baseline.service), label="service")
    with example(baseline):
        status, _ = conftest.api("PUT", SERVICE_URL, body)
        check_running()
        event(f"PUT {status}")
        if status != 200:  # noqa: PLR2004
            assert candidate(SERVICE_URL) == baseline.service, "refused, but staged"
        check_unchanged(baseline)


@FUZZ
@given(text=file_texts)
def test_active_file(baseline: Baseline, text: str) -> None:
    """An active file vpnc refuses is reported; the tenant runs what it ran."""
    with example(baseline):
        conftest.write_file(conftest.HOST, ACTIVE_FILE, text)
        with contextlib.suppress(TimeoutError):
            conftest.wait_until(
                lambda: error() or active() != baseline.tenant,
                timeout=SETTLE,
                interval=0.2,
            )
        check_running()
        if active() == baseline.tenant:
            event("not applied" if error() else "the same")
            check_unchanged(baseline)
            return
        event("applied")
        conftest.stable()
        check_running()
        restore(baseline, "not as before after restoring the configuration:")
