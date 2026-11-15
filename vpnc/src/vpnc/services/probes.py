"""Probe hosts behind connections, to know whether traffic passes through them.

A connection's probes are tested in every full check while it's up, from its
interface's address. The watchdog resets a connection whose probes all fail.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from vpnc.network import probe

if TYPE_CHECKING:
    from vpnc.models.connections import Connection, Probe, ProbeTarget
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# Tests kept per probe: those of the last 3 minutes.
HISTORY = 6


@dataclass(frozen=True)
class Result:
    """A test of a probe."""

    # Unix time.
    timestamp: float
    failed: bool
    # Seconds until the answer.
    delay: float | None = None


# The last tests of each probe, oldest first, by connection name and target.
RESULTS: dict[str, dict[ProbeTarget, deque[Result]]] = {}
# The connections tested in the last full check: the others weren't up.
TESTED: set[str] = set()
_LOCK = threading.Lock()


def _test(ni: NetworkInstance, connection: Connection, item: Probe) -> probe.Test:
    """Return the test of a probe; ValueError if the interface has no address."""
    addresses = connection.calc_interface_ip_addresses(ni)
    family = addresses[0] if item.address.version == 4 else addresses[1]  # noqa: PLR2004
    if not family:
        msg = f"no IPv{item.address.version} address"
        raise ValueError(msg)
    return probe.Test(
        netns=ni.id,
        ifname=connection.intf_name(ni),
        source=family[0].ip,
        address=item.address,
        port=item.port,
    )


def run(
    up: list[tuple[NetworkInstance, Connection]],
    configured: dict[str, Connection],
) -> None:
    """Test the probes of the connections that are up.

    configured: all connections by name, to forget the tests of what's gone.
    """
    tests: dict[probe.Test, tuple[str, ProbeTarget]] = {}
    # Without a test, e.g. without an address to send from, a probe fails.
    delays: dict[tuple[str, ProbeTarget], float | None] = {}
    for ni, connection in up:
        name = connection.name(ni)
        for item in connection.probes:
            delays[name, item.target] = None
            try:
                tests[_test(ni, connection, item)] = (name, item.target)
            except ValueError as err:
                logger.debug("Probe of %s through %s failed: %s.", item, name, err)
    now = time.time()
    for test, delay in probe.run(tests).items():
        delays[tests[test]] = delay

    with _LOCK:
        before = {name for name in TESTED if failing(name)}
        for (name, target), delay in delays.items():
            history = RESULTS.setdefault(name, {}).setdefault(
                target,
                deque(maxlen=HISTORY),
            )
            history.append(Result(timestamp=now, failed=delay is None, delay=delay))
        TESTED.clear()
        TESTED.update(name for name, _ in delays)
        _forget(configured)
    for name in sorted(TESTED):
        if failing(name) and name not in before:
            logger.info("None of the probes through %s is answered.", name)
        elif name in before and not failing(name):
            logger.info("Probes through %s are answered again.", name)


def _forget(configured: dict[str, Connection]) -> None:
    """Forget the tests of probes that aren't configured anymore."""
    for name in list(RESULTS):
        kept = (
            {item.target for item in configured[name].probes}
            if name in configured
            else set()
        )
        RESULTS[name] = {
            target: tests for target, tests in RESULTS[name].items() if target in kept
        }
        if not RESULTS[name]:
            del RESULTS[name]


def failing(name: str) -> bool:
    """Return whether a connection's probes were just tested and all failed."""
    return name in TESTED and all(
        tests[-1].failed for tests in RESULTS.get(name, {}).values()
    )


def results(name: str, connection: Connection) -> list[tuple[Probe, list[Result]]]:
    """Return a connection's probes with their last tests, oldest first."""
    with _LOCK:
        tests = RESULTS.get(name, {})
        return [(item, list(tests.get(item.target, ()))) for item in connection.probes]


def tested(name: str) -> bool:
    """Return whether a connection's probes were tested in the last full check."""
    return name in TESTED
