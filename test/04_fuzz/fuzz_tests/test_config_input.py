"""Generated configuration is refused or applied; vpnc keeps running (hub00).

A refused configuration changes nothing. An applied one is replaced by the
original again, after which the lab is as before. A file that vpnc must accept
(it's valid) is applied, however it gets there: written in place, or moved into
place as editors and tools do. True, false or a number in place of a number or
an address is refused: it isn't read as 1 or 0.0.0.5.

An example only puts the original back if the one before it changed something:
after a refused one the tenant runs the original, whatever its file says.
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

from . import conftest, strategies
from .strategies import (
    BASELINE,
    TENANT,
    Change,
    Expected,
    changed,
    file_texts,
    mistyped,
    requests,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# An example takes 0.2 to 0.5 s; one that's applied about 2 s.
FUZZ = settings(
    max_examples=3 * int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    database=DirectoryBasedExampleDatabase(Path(__file__).parents[1] / ".hypothesis"),
)

TENANT_URL = f"/v1/config/tenants/{TENANT}"
SERVICE_URL = "/v1/config/service"
ACTIVE_FILE = f"{conftest.ACTIVE_DIR}/{TENANT}.yaml"
CANDIDATES = (
    f"{conftest.CANDIDATE_DIR}/{TENANT}.yaml {conftest.CANDIDATE_DIR}/DEFAULT.yaml"
)
# Where a file is written before it's moved into place: in the same directory
# (a rename), or outside it.
BESIDE = f"{conftest.ACTIVE_DIR}/.{TENANT}.yaml.tmp"
OUTSIDE = f"{conftest.CONFIG_DIR}/.fuzz-{TENANT}.yaml"
VIA = {"write": None, "rename": BESIDE, "move": OUTSIDE}
APPLY_TIMEOUT = 120
RESTORE_TIMEOUT = 120
MISTYPED = "true, false or a number is read as a number or an address"
# Read by vpnctl; none may fail because of the configuration.
STAGED = [
    f"{TENANT_URL}?revision=candidate",
    f"{TENANT_URL}/diff",
    f"{SERVICE_URL}?revision=candidate",
    f"{SERVICE_URL}/diff",
    # One file can't break the list of all.
    "/v1/config/tenants",
]
# What reads the files.
CONFIGURATION = [TENANT_URL, SERVICE_URL, *STAGED]
READS = [
    "/v1/status",
    "/v1/tenants",
    "/v1/network-instances",
    "/v1/connections",
    *CONFIGURATION,
]


def errors() -> dict[str, str | None]:
    """Return per tenant why its active file isn't running, from the list."""
    tenants = conftest.api("GET", "/v1/config/tenants")[1]
    return {t["id"]: t["error"] for t in tenants}


class Baseline:
    """The tenant's configuration as vpnc stores it, and the node's state with it."""

    def __init__(self) -> None:
        """Read both, once applied: vpnc adds e.g. NPTv6 prefixes to the file."""
        self.state = conftest.stable()
        _, self.tenant = conftest.api("GET", f"{TENANT_URL}?reveal_secrets=true")
        _, self.service = conftest.api("GET", f"{SERVICE_URL}?reveal_secrets=true")
        # Whether an example left something applied, staged, or only its file.
        self.changed = False
        self.staged = False
        self.file = False
        self.canary = conftest.Canary()

    def handled(self) -> None:
        """Wait until vpnc handled the files written so far."""
        self.canary.handled(APPLY_TIMEOUT)

    def restore(self, failure: str) -> None:
        """Put the baseline's files back, without the API; the state must follow."""
        conftest.sh(conftest.HOST, f"rm -f {CANDIDATES}")
        conftest.write_file(
            conftest.HOST, ACTIVE_FILE, yaml.safe_dump(self.tenant), via=OUTSIDE
        )
        self.handled()
        try:
            conftest.wait_until(
                lambda: conftest.snapshot() == self.state and not error(),
                timeout=RESTORE_TIMEOUT,
                message="the baseline state",
            )
        except TimeoutError:
            changes = conftest.diff(self.state, conftest.snapshot())
            raise AssertionError("\n".join([failure, *changes])) from None
        self.changed = self.staged = self.file = False

    def unstage(self) -> None:
        """Remove what's staged, without the API."""
        conftest.sh(conftest.HOST, f"rm -f {CANDIDATES}")
        self.staged = False


def remove_tenant() -> None:
    """Remove all of the tenant's files: active, candidate and history."""
    conftest.sh(
        conftest.HOST,
        f"rm -rf {ACTIVE_FILE} {CANDIDATES} {conftest.HISTORY_DIR}/{TENANT}",
    )


@pytest.fixture(scope="module")
def baseline(deployed: conftest.Deployed) -> Iterator[Baseline]:  # noqa: ARG001
    """Add the tenant and remove it afterwards."""
    remove_tenant()
    conftest.write_file(conftest.HOST, ACTIVE_FILE, yaml.safe_dump(BASELINE))
    conftest.wait_until(
        lambda: f"{TENANT}-01" in conftest.snapshot(),
        timeout=60,
        message=f"{TENANT} to be applied",
    )
    base = Baseline()
    strategies.STORED.update(base.tenant)
    yield base
    strategies.STORED.clear()
    base.canary.remove()
    remove_tenant()
    conftest.wait_until(
        lambda: f"{TENANT}-00" not in conftest.snapshot(),
        timeout=60,
        message=f"{TENANT} to be removed",
    )


def check_running(paths: list[str] = READS) -> None:
    """Check that vpnc runs, never restarted, and answers the reads."""
    assert conftest.restarts() == 0, "vpnc exited"
    conftest.gets(paths)


def check_applied() -> None:
    """Check that vpnc applied a configuration in full, and all answer."""
    try:
        conftest.wait_until(
            lambda: not conftest.unsound(),
            timeout=APPLY_TIMEOUT,
            message="the configuration to be applied",
        )
    except TimeoutError:
        problems = conftest.unsound()
        raise AssertionError("\n".join(["applied only partly:", *problems])) from None
    check_running()


def check_unchanged(base: Baseline) -> None:
    """Check that the node's state is still the baseline's."""
    changes = conftest.diff(base.state, conftest.snapshot())
    assert not changes, "\n".join(["refused, but the state changed:", *changes])


@contextlib.contextmanager
def example(base: Baseline, *, file: bool = False) -> Iterator[None]:
    """Run an example from the baseline: it says when it left it so.

    file: it replaces the active file, so the baseline's needn't be there.
    """
    if base.changed or (base.file and not file):
        base.restore("an earlier example left the node broken:")
    elif base.staged:
        base.unstage()
    base.changed = True
    yield


def active() -> Any:  # noqa: ANN401
    """Return the configuration the tenant runs."""
    return conftest.api("GET", f"{TENANT_URL}?reveal_secrets=true")[1]


def error() -> str | None:
    """Return why the tenant's active file isn't running, from the list."""
    return errors().get(TENANT)


def candidate(url: str) -> Any:  # noqa: ANN401
    """Return the staged configuration (the active one if nothing is staged)."""
    return conftest.api("GET", f"{url}?revision=candidate&reveal_secrets=true")[1]


# How many valid requests were accepted and applied.
ACCEPTED: list[Change] = []


@FUZZ
@given(request=requests)
def test_tenant_api(
    baseline: Baseline,
    request: tuple[str, dict[str, Any], Expected, Change | None],
) -> None:
    """A valid request is applied; another is refused, or committed or refused."""
    method, body, expected, change = request
    event(f"{method} {expected.value}")
    with example(baseline):
        status, detail = conftest.api(method, TENANT_URL, body)
        if expected is Expected.ACCEPT:
            assert change is not None
            accepted(baseline, status, detail, change)
            return
        if status != 200:  # noqa: PLR2004
            event(f"{method} refused ({status})")
            check_running(STAGED)
            assert candidate(TENANT_URL) == baseline.tenant, "refused, but staged"
            check_unchanged(baseline)
            baseline.changed = False
            return
        assert expected is not Expected.REJECT, MISTYPED
        check_running()
        status, result = conftest.api("POST", f"{TENANT_URL}/commit")
        if status != 200 or not result["changed"]:  # noqa: PLR2004
            event(f"commit refused ({status})" if status != 200 else "no change")  # noqa: PLR2004
            check_running()
            check_unchanged(baseline)
            baseline.changed, baseline.staged = False, True
            return
        event("applied")
        check_applied()
        baseline.restore("not as before after restoring the configuration:")


def accepted(baseline: Baseline, status: int, detail: Any, change: Change) -> None:  # noqa: ANN401
    """Check a valid change: staged, committed and running as it is."""
    assert status == 200, f"a valid change refused ({status}): {detail}"  # noqa: PLR2004
    assert change.held(candidate(TENANT_URL)), f"not staged: {change}"
    status, result = conftest.api("POST", f"{TENANT_URL}/commit")
    assert status == 200, f"a valid change's commit refused ({status}): {result}"  # noqa: PLR2004
    assert result["changed"], f"a valid change committed as no change: {change}"
    assert change.held(active()), f"committed, but not running: {change}"
    check_applied()
    ACCEPTED.append(change)
    baseline.restore("not as before after restoring the configuration:")


def test_tenant_api_accepted() -> None:
    """Valid changes ran: the API isn't only refusing."""
    assert ACCEPTED, "no valid change was applied"


@FUZZ
@given(data=st.data())
def test_service_api(baseline: Baseline, data: st.DataObject) -> None:
    """A staged service configuration is refused or staged; never committed here."""
    refused = data.draw(st.sampled_from([False, False, False, True]))
    bodies = mistyped(baseline.service) if refused else changed(baseline.service)
    body = data.draw(bodies, label="service")
    with example(baseline):
        status, _ = conftest.api("PUT", SERVICE_URL, body)
        event(f"PUT {status}")
        if status != 200:  # noqa: PLR2004
            check_running(STAGED)
            assert candidate(SERVICE_URL) == baseline.service, "refused, but staged"
            check_unchanged(baseline)
            baseline.changed = False
            return
        assert not refused, MISTYPED
        check_running()
        check_unchanged(baseline)
        baseline.changed, baseline.staged = False, True


@FUZZ
@given(case=file_texts, how=st.sampled_from(sorted(VIA)))
def test_active_file(
    baseline: Baseline, case: tuple[str, str | None], how: str
) -> None:
    """An active file vpnc refuses is reported; the tenant runs what it ran."""
    text, expected = case
    with example(baseline, file=True):
        conftest.write_file(conftest.HOST, ACTIVE_FILE, text, via=VIA[how])
        baseline.handled()
        if active() == baseline.tenant:
            # Not applied, or not yet: vpnc may have handled the canary first.
            baseline.handled()
        check_running(CONFIGURATION)
        problem = error()
        if active() == baseline.tenant:
            assert expected != "applied", (
                f"a valid file isn't applied ({how}): {problem}"
            )
            if expected == "same":
                assert not problem, (
                    f"the baseline's file isn't loaded ({how}): {problem}"
                )
            assert expected != "refused" or problem, f"no error: {MISTYPED} ({how})"
            try:
                mapping = isinstance(yaml.safe_load(text), dict)
            except (yaml.YAMLError, TypeError, ValueError):
                mapping = False
            assert mapping or problem, (
                f"no error for a file that isn't configuration ({how})"
            )
            event(f"{how}: {'not applied' if problem else 'the same'}")
            check_unchanged(baseline)
            baseline.changed, baseline.file = False, True
            return
        assert expected != "same", (
            f"the baseline's file changed the configuration ({how})"
        )
        assert expected != "refused", f"{MISTYPED} ({how})"
        event(f"{how}: applied")
        check_applied()
        baseline.restore("not as before after restoring the configuration:")
