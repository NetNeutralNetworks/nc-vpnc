"""Generated DNS answers from a tenant's DNS server, through hub00's vpncmangle.

A responder on cli00 answers a query from mgt00 (through hub00: NAT64, or the
identity translation of C0001-00) with a generated answer: lying counts, name
compression loops, wrong lengths, truncated. vpncmangle must keep running and
translating, and what reaches mgt00 must hold no tenant address it didn't
translate (as a lenient parser, like a client's, reads it).
"""

from __future__ import annotations

import ipaddress
import json
import os
import struct
import subprocess
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

FUZZ = settings(
    max_examples=int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
)
SERVER = "cli00"
CLIENT = "mgt00"
NI = "C0001-00"
# The responder's addresses on cli00, and as mgt00 reaches them through hub00.
RESPONDER_4 = "172.16.31.53"
RESPONDER_6 = "2001:db8:c57:31::53"
TARGETS = {
    "NAT64": f"fdcc:0:c:1::{RESPONDER_4}",
    "DNS66": RESPONDER_6,
}
ANSWER_FILE = "/tmp/fuzz-dns-answer"  # noqa: S108
PID_FILE = "/tmp/fuzz-dns-responder.pid"  # noqa: S108
QNAME = "fuzz.example.com"
QTYPES = {"A": 1, "AAAA": 28}
# Answers the responder on cli00 sends: the file's, with the query's id if asked.
# It binds before the addresses exist (freebind): named takes any new address.
RESPONDER = f"""
import os, select, socket
socks = []
for family, level, option, address in (
    (socket.AF_INET, socket.IPPROTO_IP, 15, "{RESPONDER_4}"),
    (socket.AF_INET6, socket.IPPROTO_IPV6, 78, "{RESPONDER_6}"),
):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.setsockopt(level, option, 1)
    s.bind((address, 53))
    socks.append(s)
open("{PID_FILE}", "w").write(str(os.getpid()))
while True:
    for s in select.select(socks, [], [])[0]:
        query, peer = s.recvfrom(4096)
        try:
            keep_id, answer = open("{ANSWER_FILE}").read().split()
            answer = bytes.fromhex(answer)
        except (OSError, ValueError):
            continue
        if keep_id == "1" and len(answer) >= 2:
            answer = query[:2] + answer[2:]
        s.sendto(answer, peer)
"""
# A query to the target (argv[1]) of the type (argv[2]); prints the answer in hex.
CLIENT_SCRIPT = f"""
import os, socket, struct, sys
query = os.urandom(2) + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)
query += b"".join(bytes([len(p)]) + p.encode() for p in "{QNAME}".split("."))
query += b"\\0" + struct.pack(">HH", int(sys.argv[2]), 1)
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(1.5)
s.sendto(query, (sys.argv[1], 53))
try:
    print(s.recvfrom(4096)[0].hex())
except TimeoutError:
    print()
"""

# DNS message parts.
A, NS, CNAME, PTR, MX, TXT, AAAA, OPT = 1, 2, 5, 12, 15, 16, 28, 41
QUESTION = 12


def label() -> st.SearchStrategy[bytes]:
    """Return a name's label: mostly fine, sometimes too long or odd."""
    return st.one_of(
        st.binary(min_size=1, max_size=20),
        st.from_regex(rb"[a-z0-9-]{1,63}", fullmatch=True),
        st.binary(min_size=64, max_size=80),
    )


@st.composite
def name(draw: st.DrawFn) -> bytes:
    """Return an encoded name: labels, a compression pointer, or both."""
    labels = draw(st.lists(label(), max_size=5))
    encoded = b"".join(bytes([len(part) % 256]) + part for part in labels)
    end = draw(
        st.one_of(
            st.just(b"\0"),
            # To the question's name, or anywhere (loops, past the end).
            st.just(struct.pack(">H", 0xC000 | QUESTION)),
            st.integers(0, 0x3FFF).map(lambda o: struct.pack(">H", 0xC000 | o)),
            st.binary(max_size=2),
        ),
    )
    return encoded + end


@st.composite
def rdata(draw: st.DrawFn, rtype: int) -> bytes:
    """Return a record's data: as its type has it, or of a wrong length."""
    right = {
        A: st.binary(min_size=4, max_size=4),
        AAAA: st.binary(min_size=16, max_size=16),
        CNAME: name(),
        NS: name(),
        PTR: name(),
        MX: name().map(lambda n: b"\0\x0a" + n),
    }.get(rtype, st.binary(max_size=40))
    return draw(st.one_of(right, right, right, st.binary(max_size=40)))


@st.composite
def record(draw: st.DrawFn) -> bytes:
    """Return a resource record, its length field true or not."""
    rtype = draw(
        st.one_of(
            st.sampled_from([A, AAAA, A, AAAA, CNAME, NS, PTR, MX, TXT, OPT]),
            st.integers(0, 0xFFFF),
        ),
    )
    owner = draw(st.one_of(st.just(struct.pack(">H", 0xC000 | QUESTION)), name()))
    data = draw(rdata(rtype))
    length = draw(st.one_of(st.just(len(data)), st.integers(0, 0xFFFF)))
    rclass = draw(st.sampled_from([1, 1, 1, 3, 255, 0xFFFF]))
    ttl = draw(st.integers(0, 0xFFFFFFFF))
    return owner + struct.pack(">HHIH", rtype, rclass, ttl, length) + data


@st.composite
def sound_record(draw: st.DrawFn) -> bytes:
    """Return a well-formed A, AAAA or CNAME record of the question's name."""
    rtype = draw(st.sampled_from([A, AAAA, CNAME]))
    data = {
        A: st.binary(min_size=4, max_size=4),
        AAAA: st.binary(min_size=16, max_size=16),
        CNAME: st.from_regex(rb"[a-z0-9]{1,20}", fullmatch=True).map(
            lambda n: bytes([len(n)]) + n + struct.pack(">H", 0xC000 | QUESTION)
        ),
    }[rtype]
    value = draw(data)
    pointer = struct.pack(">H", 0xC000 | QUESTION)
    ttl = draw(st.integers(0, 0xFFFFFFFF))
    return pointer + struct.pack(">HHIH", rtype, 1, ttl, len(value)) + value


@st.composite
def answer(draw: st.DrawFn, qtype: int) -> tuple[bool, bytes]:
    """Return whether to take the query's id, and a generated answer."""
    kind = draw(st.integers(0, 9))
    if kind == 0:
        # Anything at all.
        return draw(st.booleans()), draw(st.binary(max_size=600))
    if kind <= 3:  # noqa: PLR2004
        # Well-formed, so that vpncmangle translates it.
        records = draw(st.lists(sound_record(), min_size=1, max_size=8))
        question = b"".join(bytes([len(p)]) + p.encode() for p in QNAME.split("."))
        question += b"\0" + struct.pack(">HH", qtype, 1)
        header = struct.pack(">HH4H", 0, 0x8180, 1, len(records), 0, 0)
        return True, header + question + b"".join(records)
    question = draw(
        st.one_of(
            st.just(
                b"".join(bytes([len(p)]) + p.encode() for p in QNAME.split("."))
                + b"\0"
                + struct.pack(">HH", qtype, 1),
            ),
            name().map(lambda n: n + struct.pack(">HH", qtype, 1)),
            st.just(b""),
        ),
    )
    sections = [draw(st.lists(record(), max_size=n)) for n in (12, 4, 4)]
    true_counts = [1 if question else 0, *(len(s) for s in sections)]
    # True mostly, else a little or far off: over vpncmangle's limit (100
    # records) it drops the answer unparsed.
    counts = [
        draw(
            st.one_of(
                st.just(count),
                st.just(count),
                st.integers(0, count + 3),
                st.integers(0, 0xFFFF),
            )
        )
        for count in true_counts
    ]
    # A response (QR) mostly; any opcode, flags and return code.
    flags = draw(st.one_of(st.just(0x8180), st.integers(0, 0xFFFF)))
    message = struct.pack(">HH4H", 0, flags, *counts) + question
    message += b"".join(b"".join(section) for section in sections)
    if draw(st.integers(0, 4)) == 0:
        message = message[: draw(st.integers(0, len(message)))]
    return True, message[:1200]


def read_name(data: bytes, offset: int) -> int:
    """Return the offset after an encoded name (pointers end it)."""
    while offset < len(data):
        size = data[offset]
        if size & 0xC0 == 0xC0:  # noqa: PLR2004
            return offset + 2
        if size == 0:
            return offset + 1
        offset += 1 + size
    raise ValueError


def addresses(data: bytes) -> list[tuple[str, str]]:
    """Return the A and AAAA records a lenient client reads from an answer.

    It follows the counts and reads every section, as far as the data goes.
    """
    found: list[tuple[str, str]] = []
    if len(data) < QUESTION:
        return found
    questions, *records = struct.unpack(">4H", data[4:12])
    offset = QUESTION
    try:
        for _ in range(questions):
            offset = read_name(data, offset) + 4
        for _ in range(sum(records)):
            offset = read_name(data, offset)
            rtype, _, _, length = struct.unpack(">HHIH", data[offset : offset + 10])
            value = data[offset + 10 : offset + 10 + length]
            offset += 10 + length
            if rtype == A and len(value) == 4:  # noqa: PLR2004
                found.append(("A", str(ipaddress.IPv4Address(value))))
            elif rtype == AAAA and len(value) == 16:  # noqa: PLR2004
                found.append(("AAAA", str(ipaddress.IPv6Address(value))))
    except (ValueError, struct.error):
        pass
    return found


def translated_prefixes() -> list[ipaddress.IPv6Network]:
    """Return the prefixes vpncmangle translates C0001-00's addresses into."""
    text = conftest.run_cmd(
        conftest.HOST,
        "cat /opt/ncubed/config/vpncmangle/translations.json",
    )
    ni = json.loads(text)[NI]
    return [ipaddress.IPv6Network(local) for local, _ in ni["dns64"] + ni["dns66"]]


def vpncmangle_pid() -> set[tuple[str, int]]:
    """Return vpncmangle's process: a new one means it exited."""
    processes = conftest.snapshot()["(daemons)"]["processes"]
    return {daemon for daemon in processes if daemon[0] == "vpncmangle"}


def ask(path: str, qtype: int) -> bytes:
    """Return the answer mgt00 gets to its query through a path; empty: none."""
    return bytes.fromhex(
        subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker", "exec", f"{conftest.CONTAINER_PREFIX}{CLIENT}",
                "python3", "-c", CLIENT_SCRIPT, TARGETS[path], str(qtype),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
    )  # fmt: skip


def in_server(command: str) -> None:
    """Run a shell command on cli00."""
    conftest.run_cmd_shell(SERVER, f"bash -c '{command}'")


@pytest.fixture(scope="module")
def responder() -> Iterator[list[ipaddress.IPv6Network]]:
    """Run the responder on cli00; return the prefixes answers may hold."""
    container = f"{conftest.CONTAINER_PREFIX}{SERVER}"
    in_server(f"rm -f {PID_FILE}")
    process = subprocess.Popen(  # noqa: S603
        ["docker", "exec", container, "python3", "-c", RESPONDER],  # noqa: S607
    )
    try:
        conftest.wait_until(
            lambda: (
                process.poll() is None
                and conftest.run_cmd(SERVER, f"cat {PID_FILE}").strip()
            ),
            timeout=10,
            message="the responder",
        )
        in_server(
            f"ip address add {RESPONDER_4}/32 dev lo;"
            f" ip address add {RESPONDER_6}/128 dev lo",
        )
        # The responder answers through both paths: an answer without addresses.
        plain = (
            struct.pack(">HH4H", 0, 0x8180, 1, 0, 0, 0)
            + b"".join(bytes([len(p)]) + p.encode() for p in QNAME.split("."))
            + b"\0"
            + struct.pack(">HH", 1, 1)
        )
        conftest.write_file(SERVER, ANSWER_FILE, f"1 {plain.hex()}")
        for path in TARGETS:
            answered = conftest.wait_until(
                lambda path=path: ask(path, 1),
                timeout=30,
                message=f"the responder's answer through {path}",
            )
            assert answered[2:] == plain[2:], f"not the responder's answer: {path}"
        yield translated_prefixes()
    finally:
        process.kill()
        in_server(
            f"kill $(cat {PID_FILE}); rm -f {PID_FILE} {ANSWER_FILE};"
            f" ip address del {RESPONDER_4}/32 dev lo;"
            f" ip address del {RESPONDER_6}/128 dev lo; true",
        )


@pytest.mark.usefixtures("deployed")
@FUZZ
@given(data=st.data())
def test_dns_answers(
    responder: list[ipaddress.IPv6Network],
    data: st.DataObject,
) -> None:
    """Vpncmangle survives any answer, and lets no tenant address through."""
    before = vpncmangle_pid()
    path = data.draw(st.sampled_from(sorted(TARGETS)), label="path")
    qtype = data.draw(st.sampled_from(sorted(QTYPES)), label="qtype")
    keep_id, message = data.draw(answer(QTYPES[qtype]), label="answer")
    conftest.write_file(SERVER, ANSWER_FILE, f"{int(keep_id)} {message.hex() or '00'}")

    received = ask(path, QTYPES[qtype])
    event(f"{path}: {'answered' if received else 'dropped'}")

    leaked = [
        (kind, address)
        for kind, address in addresses(received)
        if kind == "A"
        or not any(ipaddress.IPv6Address(address) in p for p in responder)
    ]
    assert not leaked, f"untranslated tenant addresses reached mgt00: {leaked}"
    assert vpncmangle_pid() == before, "vpncmangle exited"
    conftest.check_answering()
    assert conftest.restarts() == 0, "vpnc exited"
