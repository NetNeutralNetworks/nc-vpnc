"""What an answer must hold after vpncmangle, worked out apart from vpncmangle.

From RFC 1035 and the translations: class-IN A records become AAAA records at
the NAT64 prefix, class-IN AAAA records get their mapped prefix or go, other
classes of the address types go, SVCB/HTTPS address hints go, an RRSIG over
those types goes, the rest stays.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, replace

from fuzz_common.dns_wire import (
    AAAA,
    HTTPS,
    IN,
    IPV4HINT,
    IPV6HINT,
    SVCB,
    A,
    Message,
    Record,
)

TXT, DNAME, OPT, RRSIG, TSIG = 16, 39, 41, 46, 250
ADDRESS_TYPES = (A, AAAA, SVCB, HTTPS)
MANDATORY, ALPN, PORT = 0, 1, 3
QR, AD = 0x8000, 0x0020
OPCODE_UPDATE = 5
CHAOS = 3
# Types whose layout the oracle checks.
MODELLED = {1, 2, 5, 6, 12, 15, 16, 28, 33, 39, 41, 46, 64, 65}
# Types IANA assigned: a parser may check their data in ways the oracle doesn't.
ASSIGNED = {
    0,
    *range(1, 70),
    *range(99, 110),
    *range(249, 263),
    32768,
    32769,
} - MODELLED
# EDNS option codes IANA assigned, which a parser may check.
OPTION_CODES = set(range(1, 21))
# RFC 2181: a TTL with the top bit set is read as 0.
MAX_TTL = 0x7FFFFFFF


@dataclass(frozen=True)
class Translations:
    """A network instance's translations: its NAT64 prefix and NPTv6 routes."""

    nat64: ipaddress.IPv6Network | None
    # (local, remote) networks.
    dns66: tuple[tuple[ipaddress.IPv6Network, ipaddress.IPv6Network], ...]

    @classmethod
    def from_json(cls, ni: dict[str, list[list[str]]]) -> Translations:
        """Return a network instance's translations as translations.json has them."""
        nat64 = ipaddress.IPv6Network(ni["dns64"][0][0]) if ni["dns64"] else None
        return cls(nat64, _networks(*((a, b) for a, b in ni["dns66"])))


def _networks(*pairs: tuple[str, str]) -> tuple:
    return tuple((ipaddress.IPv6Network(a), ipaddress.IPv6Network(b)) for a, b in pairs)


# C0001-00 in the lab.
LAB = Translations(
    ipaddress.IPv6Network("fdcc:0:c:1::/96"),
    _networks(
        ("2001:db8:c57::/48", "2001:db8:c57::/48"),
        ("fd6c:1::/52", "fdff:db8:c57::/52"),
        ("fd6c:1:0:1000::/52", "fdff:db8:c57:1000::/52"),
        ("fd6c:1:0:2000::/56", "fdff:db8:c57:2000::/56"),
        ("fd6c:1:0:3000::/52", "fdff:db8:c57:3000::/52"),
    ),
)

# A record whose data the oracle can't tell: compared without it.
UNKNOWN: tuple = ("unknown",)


@dataclass(frozen=True)
class Expected:
    """What vpncmangle does with an answer.

    drop: it must drop it. may_drop: it may (it checks more than the oracle).
    unchanged: if accepted, as it came. Otherwise its header and records.
    """

    drop: bool = False
    may_drop: bool = False
    unchanged: bool = False
    flags: int = 0
    records: tuple[Record, ...] | None = None


class _BadError(Exception):
    """Data a parser must refuse."""


def _plain_name(data: bytes, pos: int) -> int:
    """Return where an uncompressed name ends."""
    length = 1
    while True:
        if pos >= len(data):
            raise _BadError
        size = data[pos]
        if size == 0:
            return pos + 1
        if size & 0xC0:
            raise _BadError
        length += 1 + size
        if length > 255 or pos + 1 + size > len(data):  # noqa: PLR2004
            raise _BadError
        pos += 1 + size


def _keys(value: bytes) -> list[int]:
    if not value or len(value) % 2:
        raise _BadError
    return [k for (k,) in struct.iter_unpack(">H", value)]


def _service(value: bytes) -> tuple[int, int, dict[int, bytes], bool]:  # noqa: C901, PLR0912 (RFC 9460 2.2)
    """Return SVCB data's priority, target end, parameters, and if all are known."""
    if len(value) < 2:  # noqa: PLR2004
        raise _BadError
    priority = struct.unpack_from(">H", value)[0]
    target = pos = _plain_name(value, 2)
    params: dict[int, bytes] = {}
    known = True
    while pos < len(value):
        if pos + 4 > len(value):
            raise _BadError
        key, length = struct.unpack_from(">HH", value, pos)
        if pos + 4 + length > len(value) or (params and key <= max(params)):
            raise _BadError
        params[key] = value[pos + 4 : pos + 4 + length]
        pos += 4 + length
    if priority == 0 and params:
        raise _BadError
    for key, param in params.items():
        if key == MANDATORY:
            listed = _keys(param)
            if listed != sorted(set(listed)) or MANDATORY in listed:
                raise _BadError
            if any(k not in params for k in listed):
                raise _BadError
        elif key == ALPN:
            pos = 0
            if not param:
                raise _BadError
            while pos < len(param):
                size = param[pos]
                if size == 0 or pos + 1 + size > len(param):
                    raise _BadError
                pos += 1 + size
        elif key == PORT:
            if len(param) != 2:  # noqa: PLR2004
                raise _BadError
        elif key in (IPV4HINT, IPV6HINT):
            size = 4 if key == IPV4HINT else 16
            if not param or len(param) % size:
                raise _BadError
        else:
            known = False
    return priority, target, params, known


def _check(record: Record, opts: list[Record]) -> bool:  # noqa: C901, PLR0911, PLR0912
    """Raise _BadError if a parser must refuse a record; return if it's modelled."""
    rtype, value = record.rtype, record.rdata
    raw = value[0] if len(value) == 1 and isinstance(value[0], bytes) else b""
    if rtype == TSIG:
        raise _BadError
    if rtype == OPT:
        if record.section != "additional" or record.name or opts:
            raise _BadError
        opts.append(record)
        pos, known = 0, True
        while pos < len(raw):
            if pos + 4 > len(raw):
                raise _BadError
            code, length = struct.unpack_from(">HH", raw, pos)
            if pos + 4 + length > len(raw):
                raise _BadError
            known = known and code not in OPTION_CODES
            pos += 4 + length
        return known
    if record.rclass == IN and rtype in (A, AAAA):
        if len(raw) != (4 if rtype == A else 16):
            raise _BadError
        return True
    if record.rclass == IN and rtype in (SVCB, HTTPS):
        return _service(raw)[3]
    if record.rclass == CHAOS and rtype == A:
        return False
    if rtype == TXT:
        pos = 0
        if not raw:
            raise _BadError
        while pos < len(raw):
            pos += 1 + raw[pos]
        if pos != len(raw):
            raise _BadError
        return True
    if rtype == DNAME:
        if _plain_name(raw, 0) != len(raw):
            raise _BadError
        return True
    if rtype == RRSIG:
        if len(raw) < 18:  # noqa: PLR2004
            raise _BadError
        _plain_name(raw, 18)
        return True
    return rtype not in ASSIGNED


def _ttl(record: Record) -> Record:
    return record if record.ttl <= MAX_TTL else replace(record, ttl=0)


def _translated(  # noqa: C901, PLR0911 (per type)
    record: Record,
    translations: Translations,
) -> Record | None:
    """Return a record as the client must see it, or None for gone."""
    rtype, raw = record.rtype, record.rdata[0]
    assert isinstance(raw, bytes)
    if rtype in ADDRESS_TYPES and record.rclass != IN:
        return None
    if rtype == A:
        if translations.nat64 is None:
            return None
        address = translations.nat64.network_address + int.from_bytes(raw)
        return _ttl(replace(record, rtype=AAAA, rdata=(address.packed,)))
    if rtype == AAAA:
        remote = ipaddress.IPv6Address(raw)
        for local, network in translations.dns66:
            if remote in network:
                mapped = local.network_address + (
                    int(remote) - int(network.network_address)
                )
                return _ttl(replace(record, rdata=(mapped.packed,)))
        return None
    if rtype in (SVCB, HTTPS):
        _, target, params, _ = _service(raw)
        if IPV4HINT not in params and IPV6HINT not in params:
            return _ttl(record)
        if set(_keys(params.get(MANDATORY, b"\0\0"))) & {IPV4HINT, IPV6HINT}:
            return None
        kept = b"".join(
            struct.pack(">HH", key, len(param)) + param
            for key, param in params.items()
            if key not in (IPV4HINT, IPV6HINT)
        )
        return _ttl(replace(record, rdata=(raw[:target] + kept,)))
    if rtype == RRSIG and struct.unpack_from(">H", raw)[0] in ADDRESS_TYPES:
        return None
    if rtype == OPT:
        return record
    if rtype in ASSIGNED:
        return _ttl(replace(record, rdata=UNKNOWN))
    return _ttl(record)


def expected(
    message: Message,
    translations: Translations | None,
    *,
    loaded: bool = True,
) -> Expected:
    """Return what vpncmangle must do with a message records() read.

    translations: of the source's network instance, None: it's of none.
    """
    opts: list[Record] = []
    try:
        # Every record: a later one may be one to refuse.
        modelled = all([_check(record, opts) for record in message.records])  # noqa: C419
    except _BadError:
        return Expected(drop=True)
    unsure = not modelled or message.flags >> 11 & 0xF == OPCODE_UPDATE
    addressed = any(r.rtype in ADDRESS_TYPES for r in message.records)
    if not message.flags & QR:
        return Expected(drop=addressed, may_drop=unsure, unchanged=True)
    if not loaded or translations is None:
        return Expected(drop=True)
    if not addressed:
        return Expected(may_drop=unsure, unchanged=True)
    if message.flags >> 11 & 0xF == OPCODE_UPDATE:
        return Expected(may_drop=True)
    kept = [
        new
        for record in message.records
        if record.rtype != OPT
        and (new := _translated(record, translations)) is not None
    ]
    return Expected(
        may_drop=unsure,
        flags=message.flags & ~AD,
        records=tuple(kept + opts),
    )


def comparable(records: tuple[Record, ...], like: tuple[Record, ...]) -> tuple:
    """Return records without the data of those the oracle doesn't know."""
    return tuple(
        replace(record, rdata=UNKNOWN) if model.rdata == UNKNOWN else record
        for record, model in zip(records, like, strict=False)
    )
