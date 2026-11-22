"""Restarts at bad moments, between and right after valid configuration changes.

The configuration state machine (test_config_states.py), with crashes: a daemon
killed (charon, vpncmangle, FRR's) or hanging for a while, vpnc killed (its
container restarts it) or hanging, or hub00 restarted right after a commit.
Afterwards everything must run again, BGP be up and the files' configuration be
applied; at the end of a sequence the connections that were up must be up again.
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
# How long a daemon hangs: a few seconds mostly.
HANG = st.one_of(st.integers(1, 5), st.integers(1, 20))


class Restarts(ConfigStates):
    """Configuration changes, and crashes."""

    # After a restart BGP may take this long.
    apply_timeout = conftest.BGP_TIMEOUT
    # Crashes stop the sniffer and injectors.
    watching = False

    def __init__(self) -> None:
        """Start without crashes."""
        super().__init__()
        # watchfrr waits longer to restart a daemon each time it exits again, up
        # to 600 s: one FRR daemon is killed until hub00 restarts.
        self.frr_killed = False

    def teardown(self) -> None:
        """Restart hub00 for a new watchfrr, if the sequence doesn't anyway."""
        try:
            if self.frr_killed and not (self.created and self.restart):
                restart(self.deployed)
        finally:
            super().teardown()

    def recovered(self, after: str) -> None:
        """Wait until all run again and BGP is up; check the config is applied."""
        self.disturbed = True
        self.deployed.restarted()
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
        killed = {pid for name, pid in conftest.daemons() if name == daemon}
        conftest.run_cmd(conftest.HOST, f"pkill -KILL -x {daemon}")

        def running_again() -> bool:
            pids = {pid for name, pid in conftest.daemons() if name == daemon}
            return bool(pids) and not pids & killed

        conftest.wait_until(
            running_again,
            timeout=DAEMON_TIMEOUT,
            message=f"{daemon} to run again",
        )
        self.recovered(f"after killing {daemon}")

    @rule()
    def kill_vpnc(self) -> None:
        """Kill vpnc: its container restarts, with a fresh start."""
        event("killed: vpnc")
        started = conftest.started()
        conftest.expect_restart()
        # Not through the agent: it ends with the node.
        conftest.docker_exec(conftest.HOST, "pkill -KILL -x vpnc")
        conftest.restarted_node(before=started)
        self.frr_killed = False
        self.recovered("after killing vpnc")

    @rule(
        daemon=st.sampled_from(["charon", "vpncmangle", "vpnc"]),
        seconds=HANG,
        change=st.booleans(),
        data=st.data(),
    )
    def hang(
        self,
        daemon: str,
        seconds: int,
        change: bool,  # noqa: FBT001
        data: st.DataObject,
    ) -> None:
        """Stop charon, vpncmangle or vpnc for a while, as if it hangs."""
        self.hung(daemon, seconds, data if change else None)

    @precondition(lambda self: not self.frr_killed)
    @rule(
        daemon=st.sampled_from(["bgpd", "zebra"]),
        seconds=HANG,
        change=st.booleans(),
        data=st.data(),
    )
    def hang_frr(
        self,
        daemon: str,
        seconds: int,
        change: bool,  # noqa: FBT001
        data: st.DataObject,
    ) -> None:
        """Stop an FRR daemon for a while: watchfrr restarts one that's silent."""
        self.frr_killed = True
        self.hung(daemon, seconds, data if change else None)

    def hung(self, daemon: str, seconds: int, data: st.DataObject | None) -> None:
        """Stop a daemon for a while; with data, commit a change meanwhile."""
        event(f"hung: {daemon}")
        conftest.run_cmd(conftest.HOST, f"pkill -STOP -x {daemon}")
        try:
            # vpnc's API doesn't answer while vpnc hangs.
            done = "nothing changed"
            if data is not None and daemon != "vpnc":
                done = self.change_unchecked(data)
            time.sleep(seconds)
        finally:
            conftest.run_cmd_shell(conftest.HOST, f"pkill -CONT -x {daemon}; true")
        self.recovered(f"after {daemon} hung for {seconds} s ({done})")

    @rule(data=st.data(), delay=st.floats(0, 3))
    def restart_after_commit(self, data: st.DataObject, delay: float) -> None:
        """Commit a change and restart hub00 right after: the commit holds."""
        done = self.change_unchecked(data)
        time.sleep(delay)
        conftest.restarted_node()
        self.frr_killed = False
        self.recovered(f"after a restart {delay:.1f} s after {done}")


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
