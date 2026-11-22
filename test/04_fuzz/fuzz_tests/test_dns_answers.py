"""Generated DNS answers from a tenant's DNS server, through hub00's vpncmangle.

A responder on cli00 answers a query from mgt00 (through hub00: NAT64, or the
identity translation of C0001-00) with a generated answer: well-formed with any
records, names and sections, or broken in a place (a lying count or length, a
pointer anywhere, truncated), or anything at all. vpncmangle must keep running
and translating, and what reaches mgt00 must hold no tenant address it didn't
translate (as a lenient parser, like a client's, reads it).

After each answer the responder sends a sentinel, an answer that vpncmangle
translates: it shows that vpncmangle still does, and that the generated answer
came before it or was dropped, without waiting for one that doesn't come.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# An example takes about 50 ms.
FUZZ = settings(
    max_examples=10 * int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
)
SERVER = "cli00"
NI = "C0001-00"
# The responder's addresses on cli00, and as mgt00 reaches them through hub00.
RESPONDER_4 = "172.16.31.53"
RESPONDER_6 = "2001:db8:c57:31::53"
TARGETS = {
    "NAT64": f"fdcc:0:c:1::{RESPONDER_4}",
    "DNS66": RESPONDER_6,
}
QNAME = "fuzz.example.com"
QTYPES = {"A": 1, "AAAA": 28}
# The sentinel's A record, and as vpncmangle translates it (NAT64).
SENTINEL_4 = "172.16.31.4"
SENTINEL_6 = "fdcc:0:c:1::ac10:1f04"
# Answers each query to the addresses with ANSWER (whether it gets the query's
# id, and the answer), then with the sentinel: an A record of the question's
# name, its id the query's inverted. It binds before the addresses exist
# (freebind): named takes any new address.
SENTINEL = f"""
def sentinel(query):
    ident = bytes(b ^ 0xFF for b in query[:2])
    header = ident + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
    record = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4)
    return header + query[12:] + record + socket.inet_aton("{SENTINEL_4}")
"""
RESPONDER = f"""
import select, socket, struct, threading
{SENTINEL}
ANSWER = None
SOCKS = []
for family, level, option, address in (
    (socket.AF_INET, socket.IPPROTO_IP, 15, "{RESPONDER_4}"),
    (socket.AF_INET6, socket.IPPROTO_IPV6, 78, "{RESPONDER_6}"),
):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.setsockopt(level, option, 1)
    s.bind((address, 53))
    SOCKS.append(s)


def serve():
    while True:
        for s in select.select(SOCKS, [], [])[0]:
            query, peer = s.recvfrom(4096)
            if ANSWER:
                keep_id, answer = ANSWER[0], bytes.fromhex(ANSWER[1])
                if keep_id and len(answer) >= 2:
                    answer = query[:2] + answer[2:]
                s.sendto(answer, peer)
            s.sendto(sentinel(query), peer)


threading.Thread(target=serve, daemon=True).start()
"""

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
SVCB, HTTPS = 64, 65
TYPES = [A, AAAA, A, AAAA, CNAME, NS, SOA, PTR, MX, TXT, SRV, DNAME, OPT, SVCB, HTTPS]
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


@st.composite
def name(draw: st.DrawFn, names: list[int]) -> bytes:
    """Return an encoded name: labels, then the root or a pointer to a name."""
    labels = draw(
        st.lists(
            st.one_of(
                st.from_regex(rb"[a-z0-9-]{1,20}", fullmatch=True),
                st.from_regex(rb"[a-z0-9-]{1,20}", fullmatch=True),
                st.binary(min_size=1, max_size=63),
            ),
            max_size=4,
        ),
    )
    encoded = b"".join(bytes([len(part)]) + part for part in labels)
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
        # A priority, a target, and address hints: IPv4 (4) and IPv6 (6).
        hints = draw(
            st.lists(
                st.one_of(
                    st.binary(min_size=4, max_size=4).map(lambda a: (4, a)),
                    address_6().map(lambda a: (6, a)),
                ),
                max_size=2,
                unique_by=lambda hint: hint[0],
            ),
        )
        return (
            b"\0\x01"
            + draw(name([]))
            + b"".join(struct.pack(">HH", key, len(a)) + a for key, a in sorted(hints))
        )
    return draw(st.binary(max_size=40))


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
                new = draw(st.integers(0, count + 3))
            struct.pack_into(">H", data, at, new)
        elif how == "length" and lengths:
            at = draw(st.sampled_from(lengths))
            length = struct.unpack_from(">H", data, at)[0]
            new = draw(st.integers(0, length + 4) | st.integers(0, 0xFFFF))
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
def answer(draw: st.DrawFn, qtype: int) -> tuple[bool, bytes]:
    """Return whether to take the query's id, and a generated answer."""
    kind = draw(st.integers(0, 9))
    if kind == 0:
        # Anything at all.
        return draw(st.booleans()), draw(st.binary(max_size=600))
    if kind <= 2:  # noqa: PLR2004
        # As a server answers the question.
        records = draw(st.lists(sound_record(), min_size=1, max_size=8))
        header = struct.pack(">HH4H", 0, 0x8180, 1, len(records), 0, 0)
        return True, header + question(qtype) + b"".join(records)
    if kind <= 6:  # noqa: PLR2004
        return True, bytes(draw(message(qtype)).data)
    return True, draw(broken(qtype))


# vpncmangle drops a network instance's answers over 50 kbytes per second (the
# sentinel too): the examples stay well under it.
RATE = 30000


def within_rate(sent: collections.deque[tuple[float, int]], size: int) -> None:
    """Wait until an answer of size (and its sentinel) is within the rate."""
    while True:
        now = time.monotonic()
        while sent and sent[0][0] < now - 1:
            sent.popleft()
        if sum(s for _, s in sent) + size <= RATE:
            break
        time.sleep(0.05)
    sent.append((now, size + 100))


def translated_prefixes() -> list[ipaddress.IPv6Network]:
    """Return the prefixes vpncmangle translates C0001-00's addresses into."""
    text = conftest.run_cmd(
        conftest.HOST,
        "cat /opt/ncubed/config/vpncmangle/translations.json",
    )
    ni = json.loads(text)[NI]
    return [ipaddress.IPv6Network(local) for local, _ in ni["dns64"] + ni["dns66"]]


def untranslated(
    answers: list[bytes],
    prefixes: list[ipaddress.IPv6Network],
) -> list[tuple[str, str]]:
    """Return the tenant addresses in answers that vpncmangle didn't translate."""
    return [
        (kind, address)
        for data in answers
        for kind, address in conftest.dns_addresses(data)
        if kind == "A" or not any(ipaddress.IPv6Address(address) in p for p in prefixes)
    ]


def translated_sentinel(server: str, qtype: int) -> str:
    """Return the sentinel as mgt00 gets it, without its id (hex): translated."""
    answers, _ = conftest.dns_ask(server, QNAME, qtype, "")
    assert answers, f"no answer from the responder through {server}"
    found = conftest.dns_addresses(answers[0], answers_only=True)
    assert found == [("AAAA", SENTINEL_6)], f"not the translated sentinel: {found}"
    return answers[0][2:].hex()


def errors() -> int:
    """Return how many answers vpncmangle failed on (an exception), once counted.

    It writes its counters every 30 s.
    """
    now = time.time()
    conftest.wait_until(
        lambda: (
            int(
                conftest.run_cmd(conftest.HOST, "stat -c %Y /run/vpncmangle/stats.json")
            )
            > now
        ),
        timeout=60,
        interval=1,
        message="vpncmangle's counters",
    )
    status = conftest.api("GET", "/v1/status")[1]
    return status["vpncmangle"]["drop_reasons"].get("ERROR", 0)


@dataclass
class Responder:
    """What the examples check against."""

    # The prefixes answers may hold.
    prefixes: list[ipaddress.IPv6Network]
    # The sentinel as mgt00 gets it, per path and query type.
    sentinels: dict[tuple[str, int], str]
    vitals: conftest.Vitals
    agent: conftest.Agent
    # When the last answers were sent, and their sizes.
    sent: collections.deque[tuple[float, int]]


@pytest.fixture(scope="module")
def responder(deployed: conftest.Deployed) -> Iterator[Responder]:  # noqa: ARG001
    """Run the responder on cli00."""
    agent = conftest.Agent(SERVER, setup=RESPONDER)
    try:
        agent.run("")
        conftest.sh(
            SERVER,
            f"ip address add {RESPONDER_4}/32 dev lo;"
            f" ip address add {RESPONDER_6}/128 dev lo",
        )
        for target in TARGETS.values():
            conftest.wait_until(
                lambda target=target: conftest.dns_ask(target, QNAME, 1, "")[0],
                timeout=30,
                message=f"the responder's answer through {target}",
            )
        yield Responder(
            translated_prefixes(),
            {
                (path, qtype): translated_sentinel(target, qtype)
                for path, target in TARGETS.items()
                for qtype in QTYPES.values()
            },
            conftest.vitals(),
            agent,
            collections.deque(),
        )
    finally:
        agent.stop()
        conftest.sh(
            SERVER,
            f"ip address del {RESPONDER_4}/32 dev lo;"
            f" ip address del {RESPONDER_6}/128 dev lo; true",
        )


@FUZZ
@given(data=st.data())
def test_dns_answers(responder: Responder, data: st.DataObject) -> None:
    """Vpncmangle survives any answer, and lets no tenant address through."""
    path = data.draw(st.sampled_from(sorted(TARGETS)), label="path")
    qtype = QTYPES[data.draw(st.sampled_from(sorted(QTYPES)), label="qtype")]
    keep_id, generated = data.draw(answer(qtype), label="answer")
    responder.agent.run("ANSWER = args", [keep_id, generated.hex()])
    within_rate(responder.sent, len(generated))

    # The answer and the sentinel take the same way, in order.
    received, sentinel = conftest.dns_ask(
        TARGETS[path],
        QNAME,
        qtype,
        responder.sentinels[path, qtype],
        grace=0.005,
    )
    event(f"{path}: {'answered' if received else 'dropped'}")

    leaked = untranslated(received, responder.prefixes)
    assert not leaked, f"untranslated tenant addresses reached mgt00: {leaked}"
    responder.vitals.check()
    assert sentinel, "vpncmangle didn't translate the answer after it"


def test_dns_answers_end(responder: Responder) -> None:
    """Vpncmangle translated what it could, and all still answer."""
    responder.agent.run("ANSWER = None")
    conftest.check_answering()
    assert not conftest.bgp_down(), f"BGP went down: {conftest.bgp_down()}"
    failed = errors()
    assert not failed, f"vpncmangle failed on {failed} answers (its ERROR counter)"
