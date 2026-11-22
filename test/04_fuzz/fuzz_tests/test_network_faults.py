"""Network faults between, and during, valid configuration changes.

The configuration state machine (test_config_states.py), with faults on hub00's
uplink: down, flapping, losing packets (both ways) or delaying them, for a
while; sometimes a change is committed meanwhile. Once the fault is over BGP
must be up again and the configuration applied in full; at the end of a sequence
every connection that was up must be up again.
"""

from __future__ import annotations

import os
import time

import pytest
from hypothesis import event, settings
from hypothesis import strategies as st
from hypothesis.stateful import rule, run_state_machine_as_test

from . import conftest
from .test_config_states import ConfigStates, remove_tenant

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# A fault takes its time and the recovery after it: about 20 s.
FAULTS = settings(
    max_examples=max(2, int(os.environ.get("FUZZ_EXAMPLES", "100")) // 10),
    stateful_step_count=6,
    deadline=None,
)
UPLINK = "eth1"
# Short mostly: BFD and BGP notice within seconds. Up to half a minute, which
# IKE's dead peer detection and the tunnels' keepalives notice.
SECONDS = st.one_of(st.integers(1, 5), st.integers(1, 5), st.integers(1, 30))
# Ends a fault: the uplink up, without netem (what hub00 sends) and without the
# filter that drops what it gets.
REPAIR = (
    f"ip link set {UPLINK} up;"
    f" tc qdisc del dev {UPLINK} root 2> /dev/null;"
    f" tc qdisc del dev {UPLINK} ingress 2> /dev/null; true"
)


def in_external(command: str) -> None:
    """Run a shell command line in hub00's EXTERNAL network instance."""
    conftest.sh(
        conftest.HOST, ["ip", "netns", "exec", "EXTERNAL", "bash", "-c", command]
    )


class NetworkFaults(ConfigStates):
    """Configuration changes, and faults on the uplink."""

    # After an outage BGP may take this long.
    apply_timeout = conftest.BGP_TIMEOUT

    # A rule per fault, so most steps are faults, not only changes.
    @rule(data=st.data(), seconds=SECONDS, change=st.booleans())
    def uplink_down(self, data: st.DataObject, seconds: int, change: bool) -> None:  # noqa: FBT001
        """Take the uplink down for a while."""
        self.fault(data, "down", seconds, change=change)

    @rule(data=st.data(), seconds=SECONDS, change=st.booleans())
    def uplink_flap(self, data: st.DataObject, seconds: int, change: bool) -> None:  # noqa: FBT001
        """Take the uplink down and up, every second, for a while."""
        self.fault(data, "flap", seconds, change=change)

    @rule(data=st.data(), seconds=SECONDS, change=st.booleans())
    def uplink_loss(self, data: st.DataObject, seconds: int, change: bool) -> None:  # noqa: FBT001
        """Lose packets on the uplink for a while."""
        self.fault(data, "loss", seconds, change=change)

    @rule(data=st.data(), seconds=SECONDS, change=st.booleans())
    def uplink_delay(self, data: st.DataObject, seconds: int, change: bool) -> None:  # noqa: FBT001
        """Delay packets on the uplink for a while."""
        self.fault(data, "delay", seconds, change=change)

    def fault(
        self, data: st.DataObject, fault: str, seconds: int, *, change: bool
    ) -> None:
        """Break the uplink for a while, perhaps change the configuration."""
        event(f"fault: {fault}")
        self.disturbed = True
        try:
            if fault == "down":
                in_external(f"ip link set {UPLINK} down")
            elif fault == "loss":
                # One in so many packets hub00 gets, and as much of what it sends.
                one_in = data.draw(st.integers(1, 10), label="loses one in")
                in_external(
                    f"tc qdisc replace dev {UPLINK} root netem loss {100 // one_in}%;"
                    f" tc qdisc add dev {UPLINK} handle ffff: ingress;"
                    f" tc filter add dev {UPLINK} parent ffff: matchall"
                    f" action gact pass random netrand drop {one_in}",
                )
            elif fault == "delay":
                # Of what hub00 sends: an answer takes as much longer either way.
                ms = data.draw(st.integers(50, 3000), label="delay ms")
                in_external(f"tc qdisc replace dev {UPLINK} root netem delay {ms}ms")
            done = self.change_unchecked(data) if change else "nothing changed"
            if fault == "flap":
                for _ in range(seconds):
                    in_external(f"ip link set {UPLINK} down")
                    time.sleep(0.5)
                    in_external(f"ip link set {UPLINK} up")
                    time.sleep(0.5)
            else:
                time.sleep(seconds)
        finally:
            in_external(REPAIR)
        self.check(f"after the uplink {fault} for {seconds} s ({done})")


def test_network_faults(deployed: conftest.Deployed) -> None:
    """After any fault the connections recover and the configuration is applied."""
    NetworkFaults.deployed = deployed
    try:
        run_state_machine_as_test(NetworkFaults, settings=FAULTS)
    finally:
        in_external(REPAIR)
        remove_tenant()
        deployed.reset()
