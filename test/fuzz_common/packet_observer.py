"""What became of injected packets: their fragments' identities, and what was seen.

An observation is evidence of one kind, not a verdict; a packet may have several.
NAT64 and NPTv6 change a packet's addresses, so an identity only finds a packet
forwarded untranslated; a translated one is found by its marker. A fragment's
identification may change on the way (hub00 sees another one for an IPsec
tunnel's second fragment), so a fragment of the same addresses as an example's
fragmented packet is attributed too: AMBIGUOUS if several fit.
"""

from __future__ import annotations

import collections
import struct
from dataclasses import dataclass

SEND_FAILED = "SEND_FAILED"
INGRESS_SEEN = "INGRESS_SEEN"
EGRESS_SEEN = "EGRESS_SEEN"
NO_FURTHER_OBSERVATION = "NO_FURTHER_OBSERVATION"
AMBIGUOUS = "AMBIGUOUS"
OBSERVATIONS = (
    SEND_FAILED,
    INGRESS_SEEN,
    EGRESS_SEEN,
    NO_FURTHER_OBSERVATION,
    AMBIGUOUS,
)

FRAGMENT = 44
# Extension headers before a Fragment header.
EXTENSIONS = (0, 43, 51, 60)

# family, source and destination (hex), identification.
Identity = tuple[int, str, str, int]


def identity(data: bytes) -> tuple[int, str, str, int] | None:
    """Return a packet's IPv4 identification, or its IPv6 Fragment header's.

    None: it has none, or its headers can't be read. The sniffer runs this too.
    """
    if len(data) >= 20 and data[0] >> 4 == 4:  # noqa: PLR2004
        return 4, data[12:16].hex(), data[16:20].hex(), (data[4] << 8) | data[5]
    if len(data) < 40 or data[0] >> 4 != 6:  # noqa: PLR2004
        return None
    header, at = data[6], 40
    while header in (0, 43, 51, 60):
        if at + 8 > len(data):
            return None
        size = (data[at + 1] + 2) * 4 if header == 51 else (data[at + 1] + 1) * 8  # noqa: PLR2004
        header, at = data[at], at + size
    if header != 44 or at + 8 > len(data):  # noqa: PLR2004
        return None
    ident = int.from_bytes(data[at + 4 : at + 8], "big")
    return 6, data[8:24].hex(), data[24:40].hex(), ident


def fragmented(data: bytes) -> bool:
    """Return whether a packet is a fragment. The sniffer runs this too."""
    if len(data) >= 20 and data[0] >> 4 == 4:  # noqa: PLR2004
        return bool(((data[6] << 8) | data[7]) & 0x3FFF)
    return identity(data) is not None


def _fragment(data: bytes) -> tuple[int | None, int | None, bool | None]:
    """Return a fragment's protocol, offset (bytes) and more-fragments flag."""
    if len(data) >= 20 and data[0] >> 4 == 4:  # noqa: PLR2004
        bits = struct.unpack_from("!H", data, 6)[0]
        return data[9], (bits & 0x1FFF) * 8, bool(bits & 0x2000)
    if identity(data) is None:
        return (data[6] if len(data) >= 40 else None), None, None  # noqa: PLR2004
    header, at = data[6], 40
    while header in EXTENSIONS:
        size = (data[at + 1] + 2) * 4 if header == 51 else (data[at + 1] + 1) * 8  # noqa: PLR2004
        header, at = data[at], at + size
    # identity() read the same headers, up to the Fragment header.
    bits = struct.unpack_from("!H", data, at + 2)[0]
    return data[at], bits & 0xFFF8, bool(bits & 1)


@dataclass(frozen=True)
class Sent:
    """A fragment as it was injected."""

    example: int
    packet: int
    family: int
    protocol: int | None
    identity: Identity | None
    offset: int | None
    more: bool | None
    data: bytes


def sent(example: int, packet: int, fragments: list[bytes]) -> list[Sent]:
    """Return the record of a packet's fragments."""
    found = []
    for data in fragments:
        protocol, offset, more = _fragment(data)
        family = data[0] >> 4 if data else 0
        found.append(
            Sent(example, packet, family, protocol, identity(data), offset, more, data)
        )
    return found


class Observer:
    """The run's sent fragments, and what was observed of each packet."""

    def __init__(self) -> None:
        """Start with nothing sent."""
        self.by_identity: dict[Identity, set[tuple[int, int]]] = (
            collections.defaultdict(set)
        )
        self.by_bytes: dict[bytes, set[tuple[int, int]]] = collections.defaultdict(set)
        # Of fragments: family, source, destination.
        self.by_pair: dict[tuple[int, str, str], set[tuple[int, int]]] = (
            collections.defaultdict(set)
        )
        self.packets: dict[int, int] = {}
        self.seen: dict[tuple[int, int], set[str]] = collections.defaultdict(set)

    def record(self, example: int, fragments: list[list[bytes]]) -> list[Identity]:
        """Record an example's packets; return their fragments' identities."""
        self.packets[example] = len(fragments)
        identities = []
        for number, pieces in enumerate(fragments):
            self.seen[example, number]
            for fragment in sent(example, number, pieces):
                self.by_bytes[fragment.data].add((example, number))
                if fragment.identity is not None:
                    self.by_identity[fragment.identity].add((example, number))
                    identities.append(fragment.identity)
                    if fragmented(fragment.data):
                        self.by_pair[fragment.identity[:3]].add((example, number))
        return identities

    def attribute(self, data: bytes, example: int | None) -> set[tuple[int, int]]:
        """Return the packets a sniffed one may be: by its bytes, identity or marker.

        example: the example its marker names, if it holds the whole marker.
        """
        if data in self.by_bytes:
            return self.by_bytes[data]
        known = identity(data)
        found = self.by_identity.get(known or (0, "", "", 0), set())
        if not found and known and fragmented(data):
            found = self.by_pair.get(known[:3], set())
        if example is not None:
            mine = {key for key in found if key[0] == example}
            return mine or {(example, n) for n in range(self.packets.get(example, 0))}
        return found

    def observe(self, keys: set[tuple[int, int]], what: str) -> None:
        """Note an observation of the packets it may be; AMBIGUOUS if several."""
        for key in keys:
            self.seen[key].add(what)
            if len(keys) > 1:
                self.seen[key].add(AMBIGUOUS)

    def failed(self, example: int, number: int) -> None:
        """Note that a packet's sending failed."""
        self.seen[example, number].add(SEND_FAILED)

    def finish(self, example: int) -> collections.Counter[str]:
        """Return the observations of an example's packets; mark the unseen."""
        totals: collections.Counter[str] = collections.Counter()
        for number in range(self.packets.get(example, 0)):
            seen = self.seen[example, number]
            if not seen & {INGRESS_SEEN, EGRESS_SEEN}:
                seen.add(NO_FURTHER_OBSERVATION)
            totals.update(seen)
        return totals
