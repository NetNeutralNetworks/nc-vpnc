"""Generated DNS answers: well-formed, broken in a place, or with misfit records."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from hypothesis import event
from hypothesis import strategies as st

# DNS message parts.
A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, DNAME, OPT = (
    1,
    2,
    5,
    6,
    12,
    15,
    16,
    28,
    33,
    39,
    41,
)
DS, RRSIG, DNSKEY, NSEC3 = 43, 46, 48, 50
SVCB, HTTPS = 64, 65
TYPES = [
    A,
    AAAA,
    A,
    AAAA,
    CNAME,
    NS,
    SOA,
    PTR,
    MX,
    TXT,
    SRV,
    DNAME,
    OPT,
    SVCB,
    HTTPS,
    RRSIG,
]
# SVCB and HTTPS parameters.
MANDATORY, ALPN, PORT, IPV4HINT, IPV6HINT = 0, 1, 3, 4, 6
QNAME = "fuzz.example.com"
QUESTION = 12
POINTER = struct.pack(">H", 0xC000 | QUESTION)
MAX_SIZE = 1200
# Networks an AAAA record is in: the tenant's (translated or passed), another
# tenant's, hub00's own prefixes (left out), any.
NETWORKS = [
    "2001:db8:c57::/48",
    "fdff:db8:c57::/52",
    "fdff:db8:c57:1000::/52",
    "2001:db8:c58::/48",
    "fdcc:0:c:1::/96",
    "fd6c:1::/48",
    "fd00::/16",
    "::/0",
]


def mostly(value: object, other: st.SearchStrategy) -> st.SearchStrategy:
    """Return value three times as often as one of other."""
    return st.one_of(st.just(value), st.just(value), st.just(value), other)


def question(qtype: int) -> bytes:
    """Return the question mgt00 asks."""
    name = b"".join(bytes([len(p)]) + p.encode() for p in QNAME.split("."))
    return name + b"\0" + struct.pack(">HH", qtype, 1)


def labels() -> st.SearchStrategy[list[bytes]]:
    """Return a name's labels: mostly host names, some any bytes."""
    return st.lists(
        st.one_of(
            st.from_regex(rb"[a-z0-9-]{1,20}", fullmatch=True),
            st.from_regex(rb"[a-z0-9-]{1,20}", fullmatch=True),
            st.binary(min_size=1, max_size=63),
        ),
        max_size=4,
    )


@st.composite
def name(draw: st.DrawFn, names: list[int]) -> bytes:
    """Return an encoded name: labels, then the root or a pointer to a name."""
    encoded = b"".join(bytes([len(part)]) + part for part in draw(labels()))
    if names and draw(st.booleans()):
        return encoded + struct.pack(">H", 0xC000 | draw(st.sampled_from(names)))
    return encoded + b"\0"


@st.composite
def address_6(draw: st.DrawFn) -> bytes:
    """Return an IPv6 address in one of the networks."""
    network = ipaddress.IPv6Network(draw(st.sampled_from(NETWORKS)))
    host = draw(st.integers(0, network.num_addresses - 1))
    return (network.network_address + host).packed


@st.composite
def service_params(draw: st.DrawFn) -> bytes:
    """Return SVCB parameters: address hints, others around them, maybe mandatory."""
    params: dict[int, bytes] = {}
    if draw(st.booleans()):
        params[IPV4HINT] = b"".join(
            draw(st.lists(st.binary(min_size=4, max_size=4), min_size=1, max_size=2))
        )
    if draw(st.booleans()):
        params[IPV6HINT] = b"".join(draw(st.lists(address_6(), min_size=1, max_size=2)))
    if draw(st.booleans()):
        ids = draw(
            st.lists(st.from_regex(rb"[a-z0-9]{1,8}", fullmatch=True), min_size=1)
        )
        params[ALPN] = b"".join(bytes([len(i)]) + i for i in ids[:3])
    if draw(st.booleans()):
        params[PORT] = draw(st.binary(min_size=2, max_size=2))
    if params and draw(st.integers(0, 3)) == 0:
        keys = draw(st.lists(st.sampled_from(sorted(params)), min_size=1, unique=True))
        params[MANDATORY] = b"".join(struct.pack(">H", key) for key in sorted(keys))
    return b"".join(
        struct.pack(">HH", key, len(value)) + value
        for key, value in sorted(params.items())
    )


@st.composite
def rdata(draw: st.DrawFn, rtype: int, names: list[int]) -> bytes:  # noqa: PLR0911
    """Return a record's data as its type has it."""
    if rtype == A:
        return draw(st.binary(min_size=4, max_size=4))
    if rtype == AAAA:
        return draw(address_6())
    if rtype in (CNAME, NS, PTR, DNAME):
        return draw(name(names))
    if rtype == MX:
        return b"\0\x0a" + draw(name(names))
    if rtype == SOA:
        return (
            draw(name(names))
            + draw(name(names))
            + draw(st.binary(min_size=20, max_size=20))
        )
    if rtype == SRV:
        return draw(st.binary(min_size=6, max_size=6)) + draw(name(names))
    if rtype == TXT:
        strings = draw(st.lists(st.binary(max_size=40), max_size=3))
        return b"".join(bytes([len(s)]) + s for s in strings)
    if rtype in (SVCB, HTTPS):
        return b"\0\x01" + draw(name([])) + draw(service_params())
    if rtype == RRSIG:
        covered = draw(st.sampled_from([A, AAAA, HTTPS, SVCB, CNAME, TXT, MX]))
        return (
            struct.pack(">H", covered)
            + draw(st.binary(min_size=16, max_size=16))
            + draw(name([]))
            + draw(st.binary(max_size=40))
        )
    return draw(st.binary(max_size=40))


def _unended() -> st.SearchStrategy[bytes]:
    """Return a name's labels without the root or a pointer after them."""
    return labels().map(lambda parts: b"".join(bytes([len(p)]) + p for p in parts))


@st.composite
def _cut(draw: st.DrawFn, data: bytes) -> bytes:
    """Return data cut short."""
    return data[: draw(st.integers(0, max(len(data) - 1, 0)))]


@st.composite
def misfit_rdata(draw: st.DrawFn, rtype: int) -> bytes:  # noqa: C901, PLR0911
    """Return data framed right for a record, and wrong for its type."""
    if rtype == A:
        return draw(st.binary(max_size=3) | st.binary(min_size=5, max_size=20))
    if rtype == AAAA:
        return draw(st.binary(max_size=15) | st.binary(min_size=17, max_size=40))
    if rtype in (MX, SRV):
        size = 2 if rtype == MX else 6
        fixed = draw(st.binary(min_size=size, max_size=size))
        return draw(st.just(fixed) | _cut(fixed))
    if rtype == SOA:
        one = draw(name([]))
        numbers = draw(st.binary(min_size=20, max_size=20))
        return draw(st.just(one) | _cut(one + draw(name([])) + numbers))
    if rtype in (CNAME, NS, PTR):
        return draw(_unended())
    if rtype in (RRSIG, DNSKEY, DS, NSEC3):
        fixed = {RRSIG: 18, DNSKEY: 4, DS: 4, NSEC3: 5}[rtype]
        return draw(st.binary(max_size=fixed - 1))
    if rtype in (SVCB, HTTPS):
        target = draw(name([]))
        param = struct.pack(">HH", PORT, 2) + b"\1\xbb"
        whole = b"\0\x01" + target + param
        how = draw(st.sampled_from(["priority", "target", "parameter", "twice"]))
        if how == "priority":
            return whole[: draw(st.integers(0, 1))]
        if how == "target":
            return b"\0\x01" + draw(_unended())
        if how == "parameter":
            return whole[: draw(st.integers(len(whole) - len(param), len(whole) - 1))]
        return whole + param
    if rtype == OPT:
        value = draw(st.binary(max_size=10))
        extra = draw(st.integers(1, 20))
        return (
            struct.pack(">HH", draw(st.integers(0, 0xFFFF)), len(value) + extra) + value
        )
    return draw(st.binary(max_size=40))


MISFIT_TYPES = [
    A,
    AAAA,
    MX,
    SRV,
    SOA,
    CNAME,
    NS,
    PTR,
    RRSIG,
    DNSKEY,
    DS,
    NSEC3,
    HTTPS,
    SVCB,
    OPT,
]


@st.composite
def misfit_record(draw: st.DrawFn) -> bytes:
    """Return a record whose framing is right and whose data is wrong for its type."""
    rtype = draw(st.sampled_from(MISFIT_TYPES))
    value = draw(misfit_rdata(rtype))
    owner = b"\0" if rtype == OPT else POINTER
    return owner + struct.pack(">HHIH", rtype, 1, 60, len(value)) + value


@dataclass
class Message:
    """A DNS message, and where its names, counts and data lengths are."""

    data: bytearray
    names: list[int]
    lengths: list[int]


@st.composite
def message(draw: st.DrawFn, qtype: int) -> Message:
    """Return a well-formed answer: any records, in any section, of any name."""
    # A response (QR) mostly; any opcode, flags and return code.
    flags = draw(mostly(0x8180, st.integers(0, 0xFFFF)))
    data = bytearray(struct.pack(">HH4H", 0, flags, 0, 0, 0, 0))
    names: list[int] = []
    lengths: list[int] = []
    questions = draw(st.sampled_from([1, 1, 1, 1, 1, 0, 2]))
    for _ in range(questions):
        asked = draw(
            mostly(
                question(qtype),
                st.tuples(name(names), st.integers(0, 0xFFFF)).map(
                    lambda q: q[0] + struct.pack(">HH", q[1], 1),
                ),
            ),
        )
        names.append(len(data))
        data += asked
    counts = []
    for most in (6, 3, 3):
        count = 0
        for _ in range(draw(st.integers(0, most))):
            rtype = draw(st.one_of(st.sampled_from(TYPES), st.integers(0, 0xFFFF)))
            # An OPT record is of the root.
            owner = b"\0" if rtype == OPT else draw(name(names))
            record = owner + struct.pack(
                ">HHI",
                rtype,
                draw(st.sampled_from([1, 1, 1, 3, 255, 4096])),
                draw(st.one_of(st.just(60), st.integers(0, 0xFFFFFFFF))),
            )
            value = draw(rdata(rtype, names))
            if len(data) + len(record) + 2 + len(value) > MAX_SIZE:
                break
            names.append(len(data))
            lengths.append(len(data) + len(record))
            data += record + struct.pack(">H", len(value)) + value
            count += 1
        counts.append(count)
    struct.pack_into(">4H", data, 4, questions, *counts)
    return Message(data, names, lengths)


@st.composite
def broken(draw: st.DrawFn, qtype: int) -> bytes:
    """Return a well-formed answer broken in one or two places."""
    made = draw(message(qtype))
    data = made.data
    for _ in range(draw(st.integers(1, 2))):
        how = draw(
            st.sampled_from(["count", "length", "pointer", "byte", "cut", "more"]),
        )
        # Not what an earlier cut took.
        names = [at for at in made.names if at + 2 <= len(data)]
        lengths = [at for at in made.lengths if at + 2 <= len(data)]
        if how == "count" and len(data) >= QUESTION:
            # A little off mostly: over vpncmangle's limit (100 records) it
            # drops the answer unparsed.
            at = draw(st.sampled_from([4, 6, 8, 10]))
            count = struct.unpack_from(">H", data, at)[0]
            new = draw(mostly(None, st.integers(0, 0xFFFF)))
            if new is None:
                new = draw(st.integers(0, min(count + 3, 0xFFFF)))
            struct.pack_into(">H", data, at, new)
        elif how == "length" and lengths:
            at = draw(st.sampled_from(lengths))
            length = struct.unpack_from(">H", data, at)[0]
            new = draw(st.integers(0, min(length + 4, 0xFFFF)) | st.integers(0, 0xFFFF))
            struct.pack_into(">H", data, at, new)
        elif how == "pointer" and names:
            # To anywhere: itself, a later name, past the end.
            at = draw(st.sampled_from(names))
            struct.pack_into(">H", data, at, 0xC000 | draw(st.integers(0, 0x3FFF)))
        elif how == "byte" and len(data) > QUESTION:
            data[draw(st.integers(2, len(data) - 1))] = draw(st.integers(0, 255))
        elif how == "cut":
            del data[draw(st.integers(0, len(data))) :]
        else:
            data += draw(st.binary(min_size=1, max_size=20))
    return bytes(data)


@st.composite
def sound_record(draw: st.DrawFn) -> bytes:
    """Return a well-formed A, AAAA or CNAME record of the question's name."""
    rtype = draw(st.sampled_from([A, AAAA, CNAME]))
    data = {
        A: st.binary(min_size=4, max_size=4),
        AAAA: st.binary(min_size=16, max_size=16),
        CNAME: st.from_regex(rb"[a-z0-9]{1,20}", fullmatch=True).map(
            lambda n: bytes([len(n)]) + n + POINTER
        ),
    }[rtype]
    value = draw(data)
    ttl = draw(st.integers(0, 0xFFFFFFFF))
    return POINTER + struct.pack(">HHIH", rtype, 1, ttl, len(value)) + value


@st.composite
def misfit(draw: st.DrawFn, qtype: int) -> bytes:
    """Return an answer with misfit records among sound ones, in any section."""
    records = draw(
        st.lists(
            st.tuples(st.integers(0, 2), sound_record() | misfit_record()),
            max_size=6,
        ),
    )
    records.append((draw(st.integers(0, 2)), draw(misfit_record())))
    records = draw(st.permutations(records))
    counts = [sum(1 for section, _ in records if section == n) for n in range(3)]
    ordered = sorted(records, key=lambda record: record[0])
    header = struct.pack(">HH4H", 0, 0x8180, 1, *counts)
    return header + question(qtype) + b"".join(record for _, record in ordered)


@st.composite
def answer(draw: st.DrawFn, qtype: int) -> tuple[bool, bytes]:
    """Return whether to take the query's id, and a generated answer."""
    kind = draw(st.integers(0, 10))
    if kind == 0:
        event("answer: anything")
        return draw(st.booleans()), draw(st.binary(max_size=600))
    if kind <= 2:  # noqa: PLR2004
        event("answer: sound")
        records = draw(st.lists(sound_record(), min_size=1, max_size=8))
        header = struct.pack(">HH4H", 0, 0x8180, 1, len(records), 0, 0)
        return True, header + question(qtype) + b"".join(records)
    if kind <= 6:  # noqa: PLR2004
        event("answer: well-formed")
        return True, bytes(draw(message(qtype)).data)
    if kind <= 9:  # noqa: PLR2004
        event("answer: broken")
        return True, draw(broken(qtype))
    event("answer: misfit")
    return True, draw(misfit(qtype))
