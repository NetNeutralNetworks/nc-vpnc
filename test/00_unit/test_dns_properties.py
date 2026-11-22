"""vpncmangle's DNS engine in-process, judged by the tests' own reader and oracle.

DNS_EXAMPLES sets the examples per property (default 1000). A failure notes
its input as hex, and Hypothesis keeps it in its database.
"""

from __future__ import annotations

import ipaddress
import os
import struct
import subprocess
import sys
import textwrap

from fuzz_common import dns_oracle, dns_wire
from fuzz_common import dns_strategies as ds
from hypothesis import event, given, note, settings
from hypothesis import strategies as st
from vpncmangle.dns_processing import ACCEPT, DROP, Result, process

from vpncmangle import config

PROPERTIES = settings(
    max_examples=int(os.environ.get("DNS_EXAMPLES", "1000")),
    deadline=None,
)
# translations.json in the lab.
TRANSLATIONS = {
    "C0001-00": {
        "dns64": [["fdcc:0:c:1::/96", "0.0.0.0/0"]],
        "dns66": [
            ["2001:db8:c57::/48", "2001:db8:c57::/48"],
            ["fd6c:1::/52", "fdff:db8:c57::/52"],
            ["fd6c:1:0:1000::/52", "fdff:db8:c57:1000::/52"],
            ["fd6c:1:0:2000::/56", "fdff:db8:c57:2000::/56"],
            ["fd6c:1:0:3000::/52", "fdff:db8:c57:3000::/52"],
        ],
    },
    "C0001-01": {
        "dns64": [["fdcc:0:c:1:1::/96", "0.0.0.0/0"]],
        "dns66": [["2001:db8:c58::/48", "2001:db8:c58::/48"]],
    },
}
CONFIG = config.Config(config=TRANSLATIONS).config
ACL_MATCH = [
    (local, ni, translations)
    for ni, translations in CONFIG.items()
    for local, _ in translations.dns64 + translations.dns66
]
LIMITS = config.Limits()
# C0001-00's DNS server through NAT64 and as is; an address of no tenant.
SOURCES = ["fdcc:0:c:1::ac10:1f35", "2001:db8:c57:31::53"]
UNKNOWN = "2001:db8:dead::53"
CLIENT = "fd00:0:0:1::2"
PREFIXES = [
    ipaddress.IPv6Network(local) for local, _ in TRANSLATIONS["C0001-00"]["dns66"]
]
PREFIXES.append(ipaddress.IPv6Network("fdcc:0:c:1::/96"))


def checksum(data: bytes) -> int:
    """Return the ones' complement sum of data, folded."""
    data += b"\0" * (len(data) % 2)
    total = sum(int.from_bytes(data[i : i + 2]) for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def wrap(message: bytes, source: str = SOURCES[0]) -> bytes:
    """Return a DNS message as an IPv6 UDP packet from port 53 to the client."""
    src = ipaddress.IPv6Address(source).packed
    dst = ipaddress.IPv6Address(CLIENT).packed
    udp = struct.pack(">HHHH", 53, 40000, 8 + len(message), 0) + message
    pseudo = src + dst + struct.pack(">IxxxB", len(udp), 17)
    value = ~checksum(pseudo + udp) & 0xFFFF or 0xFFFF
    udp = udp[:6] + struct.pack(">H", value) + udp[8:]
    return struct.pack(">IHBB", 6 << 28, len(udp), 17, 64) + src + dst + udp


def run(packet: bytes) -> Result:
    """Return vpncmangle's verdict on a packet."""
    return process(packet, ACL_MATCH, LIMITS)


def sent(result: Result, packet: bytes) -> bytes:
    """Return the packet vpncmangle sends on."""
    return packet if result.payload is None else result.payload


def udp_start(packet: bytes) -> int:
    """Return where a packet's UDP header starts, past extension headers."""
    header, offset = packet[6], 40
    while header in (0, 43, 44, 51, 60):
        length = 8 if header == 44 else (packet[offset + 1] + 1) * 8  # noqa: PLR2004
        if header == 51:  # noqa: PLR2004
            length = (packet[offset + 1] + 2) * 4
        header, offset = packet[offset], offset + length
    assert header == 17, "not UDP"  # noqa: PLR2004
    return offset


def is_dns(packet: bytes) -> bool:
    """Return whether a packet is IPv6 UDP with a DNS header."""
    try:
        return len(packet) >= udp_start(packet) + 20
    except (AssertionError, IndexError):
        return False


def check_packet(packet: bytes, *, framing: bool = True) -> bytes:
    """Return the DNS message of a packet vpncmangle sent; assert its framing."""
    udp = packet[udp_start(packet) :]
    if framing:
        (payload_length,) = struct.unpack_from(">H", packet, 4)
        assert payload_length == len(packet) - 40, "wrong IPv6 payload length"
        assert struct.unpack_from(">H", udp, 4)[0] == len(udp), "wrong UDP length"
        pseudo = packet[8:40] + struct.pack(">IxxxB", len(udp), 17)
        assert checksum(pseudo + udp) == 0xFFFF, "wrong UDP checksum"  # noqa: PLR2004
    return udp[8:]


def check_sent(result: Result, packet: bytes) -> dns_wire.Message:
    """Check an accepted packet: framing, readable, no address untranslated."""
    # As it came, it's as right as it came.
    message = check_packet(sent(result, packet), framing=result.payload is not None)
    read = dns_wire.records(message)
    leaked = dns_wire.untranslated([message], PREFIXES)
    assert not leaked, f"untranslated addresses: {leaked}"
    return read


def check_expected(
    result: Result,
    expect: dns_oracle.Expected,
    original: dns_wire.Message,
    read: dns_wire.Message | None,
) -> None:
    """Check vpncmangle's verdict against the oracle's."""
    if result.action == DROP:
        assert expect.drop or expect.may_drop, f"dropped ({result.reason})"
        return
    assert not expect.drop, "accepted, must be dropped"
    assert read is not None
    if expect.unchanged:
        assert result.payload is None, "changed, must pass as it came"
        return
    if expect.records is None:
        return
    assert read.ident == original.ident, "another id"
    assert read.flags == expect.flags, f"flags {read.flags:#x}, not {expect.flags:#x}"
    assert read.questions == original.questions, "other questions"
    got = dns_oracle.comparable(read.records, expect.records)
    assert got == expect.records, f"records\n{got}\nnot\n{expect.records}"


@st.composite
def answers(draw: st.DrawFn) -> bytes:
    """Return a generated answer to an A or AAAA query, with the query's id."""
    qtype = draw(st.sampled_from([ds.A, ds.AAAA]))
    keep_id, data = draw(ds.answer(qtype))
    if not keep_id and len(data) >= 2:  # noqa: PLR2004
        data = b"\x12\x34" + data[2:]
    return data


@st.composite
def packets(draw: st.DrawFn) -> bytes:
    """Return any packet: an answer from any source, mangled headers, any bytes."""
    kind = draw(st.integers(0, 3))
    if kind == 0:
        return draw(st.binary(max_size=200))
    source = draw(st.sampled_from([*SOURCES, UNKNOWN]))
    packet = bytearray(wrap(draw(answers()), source))
    if kind == 1:
        at = draw(st.integers(0, len(packet) - 1))
        packet[at] = draw(st.integers(0, 255))
    elif kind == 2:  # noqa: PLR2004
        # An extension header before the UDP header.
        header = draw(st.sampled_from([0, 43, 44, 51, 60]))
        extension = bytes([17, 0]) + draw(st.binary(min_size=6, max_size=6))
        packet = bytearray(packet[:40] + extension + packet[40:])
        packet[6] = header
        struct.pack_into(">H", packet, 4, len(packet) - 40)
    return bytes(packet)


@PROPERTIES
@given(packet=packets())
def test_any_packet(packet: bytes) -> None:
    """Any packet: a verdict, never an exception; what passes is sound."""
    note(f"packet: {packet.hex()}")
    result = run(packet)
    note(f"sent: {(result.payload or b'').hex()}")
    event(f"{result.action}: {result.reason}")
    if result.action == ACCEPT and is_dns(packet):
        check_sent(result, packet)


def check_answer(data: bytes) -> str:
    """Check vpncmangle with an answer, from a tenant and a stranger; return how."""
    packet = wrap(data)
    result = run(packet)
    read = check_sent(result, packet) if result.action == ACCEPT else None
    original = dns_wire.readable(data)
    if original is None:
        return f"{result.action}: {result.reason}"
    expect = dns_oracle.expected(original, dns_oracle.LAB)
    check_expected(result, expect, original, read)
    if original.flags & dns_oracle.QR:
        stranger = run(wrap(data, UNKNOWN))
        assert stranger.action == DROP, "a stranger's answer passed"
    if expect.drop:
        return "oracle: drop"
    if expect.unchanged:
        return "oracle: as it came"
    if expect.records is not None and result.action == ACCEPT:
        return "oracle: compared"
    return f"{result.action}: {result.reason}"


@PROPERTIES
@given(data=answers())
def test_answers(data: bytes) -> None:
    """Answers: sound when passed, as the oracle has them, none from strangers."""
    note(f"answer: {data.hex()}")
    note(f"sent: {(run(wrap(data)).payload or b'').hex()}")
    event(check_answer(data))


PINNED = """
import struct
from test_dns_properties import run, wrap

def answer(rclass):
    header = struct.pack(">HH4H", 1, 0x8180, 1, 1, 0, 0)
    question = b"\\x03foo\\x00" + struct.pack(">HH", 1, 1)
    record = struct.pack(">HHHIH", 0xC00C, 1, rclass, 60, 4) + bytes([10, 0, 0, 1])
    return header + question + record

run(wrap(answer(255)))
print(run(wrap(answer(1))).payload.hex())
"""


def test_class_any_first() -> None:
    """In a new process: a class-ANY A record, then a class-IN one, translated."""
    output = subprocess.run(  # noqa: S603 (this interpreter, this test's code)
        [sys.executable, "-c", textwrap.dedent(PINNED)],
        capture_output=True,
        text=True,
        check=True,
        cwd=os.path.dirname(__file__),  # noqa: PTH120
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    ).stdout
    message = check_packet(bytes.fromhex(output))
    found = dns_wire.addresses(message)
    assert [str(a.address) for a in found] == ["fdcc:0:c:1::a00:1"], found


# Fixed cases.


def header(
    flags: int = 0x8180, qd: int = 1, an: int = 0, ns: int = 0, ar: int = 0
) -> bytes:
    """Return a DNS header."""
    return struct.pack(">HH4H", 0x1234, flags, qd, an, ns, ar)


QUESTION = b"\x04fuzz\x07example\x03com\x00" + struct.pack(">HH", ds.A, 1)
OWNER = b"\xc0\x0c"


def record(rtype: int, data: bytes, owner: bytes = OWNER, rclass: int = 1) -> bytes:
    """Return a resource record."""
    return owner + struct.pack(">HHIH", rtype, rclass, 300, len(data)) + data


def answer(*records: bytes, flags: int = 0x8180) -> bytes:
    """Return a response to the question with records in its answer section."""
    return header(flags, an=len(records)) + QUESTION + b"".join(records)


def a(address: str) -> bytes:
    """Return an A record."""
    return record(ds.A, ipaddress.IPv4Address(address).packed)


def aaaa(address: str) -> bytes:
    """Return an AAAA record."""
    return record(ds.AAAA, ipaddress.IPv6Address(address).packed)


def param(key: int, value: bytes) -> bytes:
    """Return an SVCB parameter."""
    return struct.pack(">HH", key, len(value)) + value


def translate(
    data: bytes, source: str = SOURCES[0]
) -> tuple[Result, dns_wire.Message | None]:
    """Return vpncmangle's verdict on an answer, and what it sent, read."""
    packet = wrap(data, source)
    result = run(packet)
    if result.action == DROP:
        return result, None
    return result, check_sent(result, packet)


def addresses(message: dns_wire.Message) -> list[str]:
    """Return the AAAA records of a message, in order."""
    return [
        str(ipaddress.IPv6Address(r.rdata[0]))
        for r in message.records
        if r.rtype == ds.AAAA
    ]


def test_rrsig_empty() -> None:
    """An RRSIG without data: dropped."""
    result, _ = translate(answer(a("10.0.0.1"), record(ds.RRSIG, b"")))
    assert (result.action, result.reason) == ("drop", "NOT_DNS")


def test_a_empty() -> None:
    """An A record without data: dropped."""
    result, _ = translate(answer(record(ds.A, b"")))
    assert (result.action, result.reason) == ("drop", "NOT_DNS")


def test_label_like_pointer() -> None:
    """A label of the byte c0: passed as a label (readable), or dropped."""
    result, read = translate(answer(record(ds.A, bytes(4), owner=b"\x01\xc0\x00")))
    if result.action == ACCEPT:
        assert read is not None
        assert read.records[0].name == (b"\xc0",)


def test_https_hints() -> None:
    """An HTTPS record with both hints: passed without them, other parameters kept."""
    params = param(1, b"\x02h2") + param(3, b"\x01\xbb")
    hints = param(4, bytes([10, 0, 0, 1])) + param(6, bytes(16))
    data = b"\x00\x01\x00"
    result, read = translate(answer(record(ds.HTTPS, data + params + hints)))
    assert result.action == "accept"
    assert read is not None
    assert [r.rdata for r in read.records] == [(data + params,)]


def test_https_mandatory_hint() -> None:
    """An HTTPS record whose mandatory names ipv4hint: gone."""
    params = param(0, b"\x00\x04") + param(4, bytes([10, 0, 0, 1]))
    result, read = translate(answer(record(ds.HTTPS, b"\x00\x01\x00" + params)))
    assert result.action == "accept"
    assert read is not None
    assert not read.records


def test_two_a() -> None:
    """Two A records: two AAAA records, each its own."""
    _, read = translate(answer(a("10.0.0.1"), a("172.16.31.4")))
    assert read is not None
    assert addresses(read) == ["fdcc:0:c:1::a00:1", "fdcc:0:c:1::ac10:1f04"]


def test_a_high() -> None:
    """An A record of 192 or more: its AAAA record."""
    _, read = translate(answer(a("200.1.2.3")))
    assert read is not None
    assert addresses(read) == ["fdcc:0:c:1::c801:203"]


def test_aaaa_routed() -> None:
    """An AAAA record in an NPTv6 route: mapped."""
    _, read = translate(answer(aaaa("fdff:db8:c57:1000::5")))
    assert read is not None
    assert addresses(read) == ["fd6c:1:0:1000::5"]


def test_aaaa_unrouted() -> None:
    """An AAAA record outside the routes: gone."""
    result, read = translate(answer(aaaa("2001:db8:c58::5"), aaaa("fd00::1")))
    assert result.action == "accept"
    assert read is not None
    assert not read.records


def test_rrsig_over_a() -> None:
    """An A record and an RRSIG over it: the AAAA record, AD cleared."""
    rrsig = struct.pack(">H", ds.A) + bytes(16) + b"\x00" + b"signature"
    _, read = translate(answer(a("10.0.0.1"), record(ds.RRSIG, rrsig), flags=0x81A0))
    assert read is not None
    assert [r.rtype for r in read.records] == [ds.AAAA]
    assert addresses(read) == ["fdcc:0:c:1::a00:1"]
    assert not read.flags & dns_oracle.AD


def test_compressed_names() -> None:
    """A, CNAME, MX and SOA with compressed names: addresses exact, others equal."""
    cname = record(ds.CNAME, b"\x03www\xc0\x11")
    mx = record(ds.MX, b"\x00\x0a\x04mail\xc0\x11", owner=b"\xc0\x11")
    soa = record(ds.SOA, b"\x02ns\xc0\x11\x05admin\xc0\x11" + bytes(range(20)))
    data = answer(a("10.0.0.1"), cname, mx, soa)
    _, read = translate(data)
    assert read is not None
    original = dns_wire.records(data)
    assert addresses(read) == ["fdcc:0:c:1::a00:1"]
    assert read.records[1:] == original.records[1:]


def test_query_bytes_after_header() -> None:
    """A query with no question or records, and bytes after its header: dropped."""
    result, _ = translate(header(0x0100, qd=0) + b"\x00\x01\x00\x01\x00")
    assert result.action == "drop"


def test_unknown_source() -> None:
    """A TXT-only answer from no network instance: dropped."""
    result, _ = translate(answer(record(ds.TXT, b"\x03abc")), source=UNKNOWN)
    assert (result.action, result.reason) == ("drop", "UNKNOWN_SOURCE")
