"""Restarts at bad moments, between and right after valid configuration changes.

The configuration state machine (test_config_states.py), with crashes: a daemon
killed (charon, vpncmangle, FRR's), vpnc killed (its container restarts it), or
hub00 restarted right after a commit. Afterwards everything must run again, the
connections that were up be up again, and the files' configuration be applied.
"""

from __future__ import annotations

import os
import time

import pytest
from hypothesis import event, settings
from hypothesis import strategies as st
from hypothesis.stateful import precondition, rule, run_state_machine_as_test

from . import conftest
from .test_config_states import ConfigStates, remove_tenant, restart

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

RESTARTS = settings(
    max_examples=max(2, int(os.environ.get("FUZZ_EXAMPLES", "100")) // 10),
    stateful_step_count=6,
    deadline=None,
)
CONTAINER = f"{conftest.CONTAINER_PREFIX}{conftest.HOST}"
# A killed daemon runs again within this time: watchfrr waits up to 600 s before
# it restarts a daemon that keeps exiting.
DAEMON_TIMEOUT = 660
FRR_DAEMONS = ("bgpd", "zebra", "bfdd")


class Restarts(ConfigStates):
    """Configuration changes, and crashes."""

    def __init__(self) -> None:
        """Start without crashes."""
        super().__init__()
        # watchfrr waits longer to restart a daemon each time it exits again, up
        # to 600 s: one FRR daemon is killed until hub00 restarts.
        self.frr_killed = False

    def teardown(self) -> None:
        """Restart hub00 for a new watchfrr, if the sequence doesn't anyway."""
        if self.frr_killed and not self.created:
            restart(self.deployed)
        super().teardown()

    def recovered(self, after: str, before: set[str]) -> None:
        """Wait until what was up is up again; check the config is applied."""
        self.deployed.restarted()
        self.deployed.healthy(before, after)
        self.check(after)

    # A rule per daemon, so most steps are crashes, not only changes.
    @rule()
    def kill_charon(self) -> None:
        """Kill charon: vpnc starts it again."""
        self.kill_daemon("charon")

    @rule()
    def kill_vpncmangle(self) -> None:
        """Kill vpncmangle: vpnc starts it again."""
        self.kill_daemon("vpncmangle")

    @precondition(lambda self: not self.frr_killed)
    @rule()
    def kill_bgpd(self) -> None:
        """Kill bgpd: watchfrr starts it again."""
        self.kill_daemon("bgpd")

    @precondition(lambda self: not self.frr_killed)
    @rule()
    def kill_zebra(self) -> None:
        """Kill zebra: watchfrr starts it again."""
        self.kill_daemon("zebra")

    @precondition(lambda self: not self.frr_killed)
    @rule()
    def kill_bfdd(self) -> None:
        """Kill bfdd: watchfrr starts it again."""
        self.kill_daemon("bfdd")

    def kill_daemon(self, daemon: str) -> None:
        """Kill a daemon next to vpnc."""
        event(f"killed: {daemon}")
        self.frr_killed |= daemon in FRR_DAEMONS
        before = conftest.up_connections()
        killed = {pid for name, pid in conftest.daemons() if name == daemon}
        conftest.run_cmd(conftest.HOST, f"pkill -KILL -x {daemon}")

        def running_again() -> bool:
            pids = {pid for name, pid in conftest.daemons() if name == daemon}
            return bool(pids) and not pids & killed

        conftest.wait_until(
            running_again,
            timeout=DAEMON_TIMEOUT,
            interval=2,
            message=f"{daemon} to run again",
        )
        self.recovered(f"after killing {daemon}", before)

    @rule()
    def kill_vpnc(self) -> None:
        """Kill vpnc: its container restarts, with a fresh start."""
        event("killed: vpnc")
        before = conftest.up_connections()
        started = conftest.started()
        conftest.expect_restart()
        conftest.run_cmd(conftest.HOST, "pkill -KILL -x vpnc")
        conftest.restarted_node(before=started)
        self.frr_killed = False
        self.recovered("after killing vpnc", before)

    @rule(data=st.data(), delay=st.floats(0, 3))
    def restart_after_commit(self, data: st.DataObject, delay: float) -> None:
        """Commit a change and restart hub00 right after: the commit holds."""
        before = conftest.up_connections()
        done = self.change_unchecked(data)
        time.sleep(delay)
        conftest.restarted_node()
        self.frr_killed = False
        self.recovered(f"after a restart {delay:.1f} s after {done}", before)


def test_restarts(deployed: conftest.Deployed) -> None:
    """After any crash all runs again, and the configuration is applied."""
    Restarts.deployed = deployed
    # A new watchfrr: an earlier run may have left it slow to restart daemons.
    restart(deployed)
    try:
        run_state_machine_as_test(Restarts, settings=RESTARTS)
    finally:
        remove_tenant()
        deployed.reset()
