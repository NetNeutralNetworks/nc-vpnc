"""DNS readers of the tests' own, without dnspython or scapy: vpncmangle uses dnspython.

records() is strict and reads a message as RFC 1035 has it; addresses() is
lenient and reads what a client might take addresses from.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import NamedTuple

HEADER = 12
MAX_NAME = 255
MAX_POINTERS = 20
SECTIONS = ("answer", "authority", "additional")
A, NS, CNAME, SOA, PTR, MX, AAAA, SRV, SVCB, HTTPS = 1, 2, 5, 6, 12, 15, 28, 33, 64, 65
IN = 1
IPV4HINT, IPV6HINT = 4, 6

Name = tuple[bytes, ...]


class MalformedError(ValueError):
    """The message isn't as RFC 1035 has it; the argument: where reading failed."""


@dataclass(frozen=True)
class Record:
    """A resource record; names lower-case labels, those in rdata written out."""

    section: str
    name: Name
    rtype: int
    rclass: int
    ttl: int
    # Bytes, with the names of NS, CNAME, PTR, MX, SOA and SRV as tuples.
    rdata: tuple[bytes | Name, ...]


@dataclass(frozen=True)
class Message:
    """A DNS message as records() reads it."""

    ident: int
    flags: int
    questions: tuple[tuple[Name, int, int], ...]
    records: tuple[Record, ...]


def name(data: bytes, pos: int) -> tuple[Name, int]:  # noqa: C901 (RFC 1035 4.1.4)
    """Return a name's labels (lower-case) and where it ends.

    Pointers go back, not into the header, at most MAX_POINTERS deep.
    """
    labels: list[bytes] = []
    end = None
    pointers = 0
    length = 1
    while True:
        if pos >= len(data):
            raise MalformedError(pos)
        size = data[pos]
        if size == 0:
            return tuple(labels), pos + 1 if end is None else end
        if size & 0xC0 == 0xC0:  # noqa: PLR2004
            if pos + 2 > len(data):
                raise MalformedError(pos)
            target = struct.unpack_from(">H", data, pos)[0] & 0x3FFF
            pointers += 1
            if target < HEADER or target >= pos or pointers > MAX_POINTERS:
                raise MalformedError(pos)
            if end is None:
                end = pos + 2
            pos = target
            continue
        if size & 0xC0:
            raise MalformedError(pos)
        if pos + 1 + size > len(data):
            raise MalformedError(pos)
        length += 1 + size
        if length > MAX_NAME:
            raise MalformedError(pos)
        labels.append(data[pos + 1 : pos + 1 + size].lower())
        pos += 1 + size


def _rdata(
    data: bytes, start: int, end: int, rtype: int, rclass: int
) -> tuple[bytes | Name, ...]:
    """Return a record's data, with the names in it written out."""
    # The bytes before a name, and how many names; then bytes up to the end.
    layout = {NS: (0, 1), CNAME: (0, 1), PTR: (0, 1), MX: (2, 1), SOA: (0, 2)}
    if rtype == SRV and rclass == IN:
        layout[SRV] = (6, 1)
    if rtype not in layout:
        return (data[start:end],)
    fixed, names = layout[rtype]
    if start + fixed > end:
        raise MalformedError(start)
    parts: list[bytes | Name] = [data[start : start + fixed]]
    pos = start + fixed
    for _ in range(names):
        written, pos = name(data, pos)
        if pos > end:
            raise MalformedError(start)
        parts.append(written)
    rest = data[pos:end]
    if (rtype == SOA and len(rest) != 20) or (rtype != SOA and rest):  # noqa: PLR2004
        raise MalformedError(start)
    parts.append(rest)
    return tuple(parts)


def records(data: bytes) -> Message:
    """Return a DNS message's question and records; MalformedError if it isn't one."""
    if len(data) < HEADER:
        raise MalformedError(0)
    ident, flags, questions, *counts = struct.unpack_from(">6H", data)
    pos = HEADER
    asked = []
    for _ in range(questions):
        owner, pos = name(data, pos)
        if pos + 4 > len(data):
            raise MalformedError(pos)
        asked.append((owner, *struct.unpack_from(">HH", data, pos)))
        pos += 4
    found = []
    for section, count in zip(SECTIONS, counts, strict=True):
        for _ in range(count):
            owner, pos = name(data, pos)
            if pos + 10 > len(data):
                raise MalformedError(pos)
            rtype, rclass, ttl, length = struct.unpack_from(">HHIH", data, pos)
            pos += 10
            if pos + length > len(data):
                raise MalformedError(pos)
            value = _rdata(data, pos, pos + length, rtype, rclass)
            found.append(Record(section, owner, rtype, rclass, ttl, value))
            pos += length
    if pos != len(data):
        raise MalformedError(pos)
    return Message(ident, flags, tuple(asked), tuple(found))


def readable(data: bytes) -> Message | None:
    """Return records(data), or None if it isn't a DNS message."""
    try:
        return records(data)
    except MalformedError:
        return None


class DNSAddress(NamedTuple):
    """An address a client may read from an answer."""

    # A, AAAA, ipv4hint or ipv6hint.
    source: str
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    section: str
    index: int


def _skip_name(data: bytes, offset: int) -> int:
    """Return the offset after an encoded name (pointers end it)."""
    while offset < len(data):
        size = data[offset]
        if size & 0xC0 == 0xC0:  # noqa: PLR2004
            return offset + 2
        if size == 0:
            return offset + 1
        offset += 1 + size
    raise ValueError


def _hints(value: bytes) -> list[tuple[str, bytes]]:
    """Return the address hints in SVCB data, as far as it goes."""
    found: list[tuple[str, bytes]] = []
    try:
        pos = _skip_name(value, 2)
    except ValueError:
        return found
    while pos + 4 <= len(value):
        key, length = struct.unpack_from(">HH", value, pos)
        param = value[pos + 4 : pos + 4 + length]
        pos += 4 + length
        size = {IPV4HINT: 4, IPV6HINT: 16}.get(key)
        if size:
            source = "ipv4hint" if key == IPV4HINT else "ipv6hint"
            found += [
                (source, param[i : i + size])
                for i in range(0, len(param) - size + 1, size)
            ]
    return found


def addresses(data: bytes, *, answers_only: bool = False) -> list[DNSAddress]:
    """Return the addresses a lenient client reads from an answer, of any class.

    It follows the counts and reads every section (or only the answers), as far
    as the data goes.
    """
    found: list[DNSAddress] = []
    if len(data) < HEADER:
        return found
    questions, *counts = struct.unpack(">4H", data[4:12])
    offset = HEADER
    index = 0
    try:
        for _ in range(questions):
            offset = _skip_name(data, offset) + 4
        for section, count in zip(SECTIONS, counts, strict=True):
            if answers_only and section != "answer":
                break
            for _ in range(count):
                offset = _skip_name(data, offset)
                rtype, _, _, length = struct.unpack(">HHIH", data[offset : offset + 10])
                value = data[offset + 10 : offset + 10 + length]
                offset += 10 + length
                if rtype == A and len(value) == 4:  # noqa: PLR2004
                    found.append(
                        DNSAddress("A", ipaddress.IPv4Address(value), section, index)
                    )
                elif rtype == AAAA and len(value) == 16:  # noqa: PLR2004
                    found.append(
                        DNSAddress("AAAA", ipaddress.IPv6Address(value), section, index)
                    )
                elif rtype in (SVCB, HTTPS):
                    found += [
                        DNSAddress(source, ipaddress.ip_address(raw), section, index)
                        for source, raw in _hints(value)
                    ]
                index += 1
    except (ValueError, struct.error):
        pass
    return found


def untranslated(
    answers: list[bytes],
    prefixes: list[ipaddress.IPv6Network],
) -> list[DNSAddress]:
    """Return the addresses in answers that vpncmangle must not let through.

    Any IPv4 address, an IPv6 one outside the translated prefixes, any hint.
    """
    return [
        found
        for data in answers
        for found in addresses(data)
        if found.address.version == 4  # noqa: PLR2004
        or found.source.endswith("hint")
        or not any(found.address in prefix for prefix in prefixes)
    ]
