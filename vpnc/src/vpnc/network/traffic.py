"""Traffic counters of interfaces, and the rates between two reads of them.

Named as in OpenConfig (openconfig-interfaces, openconfig-if-rates).

Every read of a namespace (state.NetnsState.read) records its counters. The
full check reads every namespace, so a rate needs no reads of its own.
"""

from __future__ import annotations

import struct
import threading
import time
from collections import deque
from dataclasses import dataclass

# Seconds a rate is measured over: the last read against the latest one at
# least MIN_WINDOW before it. With a full check every 30 seconds that's 15 to 45.
MIN_WINDOW = 15
# Reads longer ago aren't used: the rate would say little about now.
MAX_WINDOW = 300


@dataclass(frozen=True)
class Counters:
    """Traffic through an interface since it was created."""

    in_pkts: int
    out_pkts: int
    in_octets: int
    out_octets: int
    in_errors: int
    out_errors: int
    in_discards: int
    out_discards: int

    @classmethod
    def unpack(cls, data: bytes) -> Counters:
        """Return the counters of an IFLA_STATS64 attribute, which starts with them."""
        return cls(*struct.unpack_from("8Q", data))


@dataclass(frozen=True)
class Rates:
    """Traffic through an interface in bits per second, over load_interval seconds."""

    load_interval: int
    in_bits_rate: int
    out_bits_rate: int


# Per namespace its reads, oldest first: when, and the counters by interface.
_READS: dict[str, deque[tuple[float, dict[str, Counters]]]] = {}
_LOCK = threading.Lock()


def record(netns: str, counters: dict[str, Counters]) -> None:
    """Remember the counters just read of a namespace."""
    now = time.monotonic()
    with _LOCK:
        reads = _READS.setdefault(netns, deque())
        # Keep one read to measure against, and the ones that will be.
        while len(reads) > 1 and now - reads[1][0] >= MIN_WINDOW:
            reads.popleft()
        reads.append((now, counters))
        # Deleted namespaces aren't read anymore.
        for name in [n for n, r in _READS.items() if now - r[-1][0] > MAX_WINDOW]:
            del _READS[name]


def rates(netns: str, ifname: str) -> Rates | None:
    """Return the rates of an interface up to the last read of its namespace.

    None if it can't be measured (yet): the namespace wasn't read long enough
    before, or the interface was created since.
    """
    with _LOCK:
        reads = list(_READS.get(netns, ()))
    if not reads:
        return None
    (start, before), (end, after) = reads[0], reads[-1]
    if not MIN_WINDOW <= end - start <= MAX_WINDOW:
        return None
    if (old := before.get(ifname)) is None or (new := after.get(ifname)) is None:
        return None
    if new.in_octets < old.in_octets or new.out_octets < old.out_octets:
        return None
    return Rates(
        load_interval=round(end - start),
        in_bits_rate=round((new.in_octets - old.in_octets) * 8 / (end - start)),
        out_bits_rate=round((new.out_octets - old.out_octets) * 8 / (end - start)),
    )
