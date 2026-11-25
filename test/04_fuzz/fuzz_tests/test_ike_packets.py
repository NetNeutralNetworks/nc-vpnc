"""Generated IKE packets to hub00's charon, from a configured peer's address.

A tenant has IPsec connections to two extra addresses of mgt01 (hub00's firewall
only lets in the peers' IKE): IKEv2 to the IPv4 one, IKEv1 to the IPv6 one. From
them mgt01 sends generated IKE messages, to port 500 or 4500:

- a first message as a peer sends it (IKE_SA_INIT, or IKEv1's main or aggressive
  mode), its proposal, key exchange and nonce right or not, sometimes broken in
  one place: charon parses it, selects a proposal and answers;
- any chain of payloads, structured or not, with lying lengths;
- messages of later exchanges, for the IKE SA charon answered last;
- a header that's odd in any field.

charon must keep running and answering, and the connections that are up stay up.
After each example's messages mgt01 sends one that charon always answers: its
answer shows charon got through them, without waiting for answers to them.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
import yaml
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# An example takes about 40 ms.
FUZZ = settings(
    max_examples=10 * int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
    database=conftest.DATABASE,
)
TENANT = "C0008"
SENDER = "mgt01"
# The peers' addresses on mgt01, and the IKE version of their connections.
PEERS = {4: "192.0.2.201", 6: "2001:db8::201"}
VERSIONS = {4: 2, 6: 1}
HUB = {4: "192.0.2.5", 6: "2001:db8::5"}
APPLY_TIMEOUT = 120
CONFIG = {
    "version": "0.1.5",
    "id": TENANT,
    "name": "Fuzz IKE",
    "network_instances": {
        "00": {
            "type": "DOWNLINK",
            "connections": {
                0: {
                    "routes": {"ipv4": [{"to": "10.80.0.0/24"}], "ipv6": []},
                    "config": {
                        "type": "IPSEC",
                        "remote_addrs": [PEERS[4]],
                        "ike_proposal": "aes256gcm16-prfsha384-x25519",
                        "initiation": "NONE",
                        "psk": "fuzz-ike-packets-preshared-key-0",
                    },
                },
                1: {
                    "routes": {"ipv4": [{"to": "10.80.1.0/24"}], "ipv6": []},
                    "config": {
                        "type": "IPSEC",
                        "remote_addrs": [PEERS[6]],
                        "ike_version": 1,
                        "ike_proposal": "aes256-sha256-modp3072",
                        "initiation": "NONE",
                        "psk": "fuzz-ike-packets-preshared-key-1",
                    },
                },
            },
        },
    },
}
# Sends an example's messages from a peer's address, then the sentinel until
# charon answers it. A message to patch gets the SPIs of the IKE SA charon
# answered last (a first message it accepted). Returns what charon answered,
# how many first messages it accepted, and whether it answered the sentinel.
SENDER_CODE = """
import select, socket, struct, time

SOCKS, LAST = {}, {}
NOTIFY_2, NOTIFY_1 = 41, 11


def answer(data):
    # What an answer is: (IKE version, exchange, first payload, notify type).
    if len(data) < 28:
        return "short"
    version, exchange, first = data[17] >> 4, data[18], data[16]
    notify = ""
    if version == 2 and first == NOTIFY_2 and len(data) >= 36:
        notify = struct.unpack(">H", data[34:36])[0]
    if version == 1 and first == NOTIFY_1 and len(data) >= 40:
        notify = struct.unpack(">H", data[38:40])[0]
    return f"IKEv{version} exchange {exchange} payload {first} {notify}".strip()


def send(source, address, port, marker, messages, sentinel):
    if source not in SOCKS:
        family = socket.AF_INET6 if ":" in source else socket.AF_INET
        SOCKS[source] = socket.socket(family, socket.SOCK_DGRAM)
        SOCKS[source].bind((source, 0))
    s = SOCKS[source]
    while select.select([s], [], [], 0)[0]:
        s.recvfrom(4096)
    for data, patch in messages:
        data = bytearray.fromhex(data)
        if patch and source in LAST and len(data) >= 16:
            data[:16] = LAST[source]
        s.sendto(bytes(marker) + data, (address, port))
        # Each makes an IKE SA while charon reads it: more than a few of a peer
        # at a time and charon wants cookies, or drops them.
        time.sleep(0.001)
    sentinel = bytes.fromhex(sentinel)
    answers, accepted, answered = [], 0, False
    for _ in range(2):
        s.sendto(bytes(4 if port == 4500 else 0) + sentinel, (address, port))
        end = time.monotonic() + 1
        while not answered and (left := end - time.monotonic()) > 0:
            if not select.select([s], [], [], left)[0]:
                break
            data = s.recvfrom(4096)[0]
            if port == 4500 and data[:4] == bytes(4):
                data = data[4:]
            if data[:8] == sentinel[:8]:
                answered = True
            else:
                answers.append(answer(data))
                # An IKE_SA_INIT (34) answer with an SA (33), or IKEv1's main
                # mode (2) with one (1): the IKE SA stays, half-open.
                if len(data) >= 28 and (data[18], data[16]) in ((34, 33), (2, 1)):
                    accepted += 1
                    LAST[source] = bytes(data[:16])
        if answered:
            break
    return answers, accepted, answered
"""

# IKEv2: payload types, exchanges and transforms.
SA, KE, IDI, IDR, CERT, CERTREQ, AUTH, NONCE, NOTIFY, DELETE, VID = range(33, 44)
TSI, TSR, SK, CP, EAP, SKF = 44, 45, 46, 47, 48, 53
PAYLOADS = [*range(SA, VID + 1), TSI, TSR, SK, CP, EAP, SKF]
IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL, IKE_INTERMEDIATE = (
    34,
    35,
    36,
    37,
    43,
)
EXCHANGES = [IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL, IKE_INTERMEDIATE]
ENCR, PRF, INTEG, GROUP, ADDKE1 = 1, 2, 3, 4, 6
AES_GCM_16, AES_CBC, CHACHA20_POLY1305 = 20, 12, 28
KEY_LENGTH = 0x800E
X25519, ECP_256, ECP_384, MODP_2048, MODP_3072, ML_KEM_768 = 31, 19, 20, 14, 15, 36
# The size of a group's public value.
KE_SIZES = {
    X25519: 32,
    ECP_256: 64,
    ECP_384: 96,
    MODP_2048: 256,
    MODP_3072: 384,
    ML_KEM_768: 1184,
}
# The IKEv2 connection's proposal (aes256gcm16-prfsha384-x25519), and others
# that charon knows: transform type, id and key length.
PROPOSAL = [(ENCR, AES_GCM_16, 256), (PRF, 6, None), (GROUP, X25519, None)]
PROPOSALS = [
    [(ENCR, AES_GCM_16, 256), (PRF, 6, None), (GROUP, ECP_384, None)],
    [(ENCR, AES_GCM_16, 128), (PRF, 5, None), (GROUP, X25519, None)],
    [(ENCR, AES_CBC, 256), (INTEG, 12, None), (PRF, 5, None), (GROUP, MODP_3072, None)],
    [(ENCR, CHACHA20_POLY1305, None), (PRF, 5, None), (GROUP, X25519, None)],
    [*PROPOSAL, (ADDKE1, ML_KEM_768, None)],
    [(ENCR, AES_GCM_16, 256), (PRF, 6, None)],
    [],
]
# Notifies of a first message: NAT detection (a SHA-1 hash), fragmentation,
# hash algorithms, redirect, PPK, intermediate exchange, cookie.
NOTIFIES = {
    16388: 20,
    16389: 20,
    16430: 0,
    16431: 8,
    16406: 0,
    16435: 0,
    16438: 0,
    16390: 16,
}

# IKEv1: payload types, exchanges and SA attributes.
SA_1, KE_1, ID_1, HASH_1, NONCE_1, NOTIFY_1, DELETE_1, VID_1 = (
    1,
    4,
    5,
    8,
    10,
    11,
    12,
    13,
)
NAT_D_1, FRAG_1 = 20, 132
PAYLOADS_1 = [*range(SA_1, VID_1 + 1), NAT_D_1, 21, FRAG_1]
MAIN, AGGRESSIVE, INFORMATIONAL_1, QUICK = 2, 4, 5, 32
EXCHANGES_1 = [MAIN, AGGRESSIVE, INFORMATIONAL_1, 6, QUICK]
# Encryption (AES-CBC), key length, hash (SHA-256), authentication (PSK), group,
# life type (seconds) and duration: the IKEv1 connection's, and others.
TRANSFORM_1 = [(1, 7), (14, 256), (2, 4), (3, 1), (4, MODP_3072), (11, 1), (12, 28800)]
TRANSFORMS_1 = [
    [(1, 7), (14, 128), (2, 2), (3, 1), (4, MODP_2048), (11, 1), (12, 28800)],
    [(1, 5), (2, 2), (3, 1), (4, 2)],
    [(1, 7), (14, 256), (2, 4), (3, 3), (4, MODP_3072)],
    [],
]
# Vendor ids: DPD, NAT-T (RFC 3947), fragmentation, XAuth.
VENDORS = [
    "afcad71368a1f1c96b8696fc77570100",
    "4a131c81070358455c5728f20e95452f",
    "4048b7d56ebce88525e7de7f00d6c2d380000000",
    "09002689dfd6b712",
]
HEADER = 28


@dataclass(frozen=True)
class Message:
    """An IKE message to send."""

    data: bytes
    # Whether it gets the SPIs of the IKE SA that charon answered last.
    patch: bool = False
    # Sent instead while charon has a half-open IKE SA of the peer: charon
    # accepts data and keeps another, and it only keeps a few per peer.
    refused: bytes | None = None


def mostly(value: object, other: st.SearchStrategy) -> st.SearchStrategy:
    """Return value three times as often as one of other."""
    return st.one_of(st.just(value), st.just(value), st.just(value), other)


def header(  # noqa: PLR0913
    chain: bytes,
    first: int,
    *,
    version: int = 2,
    exchange: int = IKE_SA_INIT,
    flags: int = 0x08,
    message_id: int = 0,
    spis: bytes | None = None,
) -> bytes:
    """Return a message: by default a first IKEv2 request, from a new SPI."""
    return (
        (spis or os.urandom(8) + bytes(8))
        + struct.pack(
            ">BBBBII",
            first,
            version << 4,
            exchange,
            flags,
            message_id,
            HEADER + len(chain),
        )
        + chain
    )


def chained(payloads: list[tuple[int, bytes]]) -> bytes:
    """Return payloads (type, body) as a chain, each naming the next's type."""
    kinds = [kind for kind, _ in payloads[1:]] + [0]
    return b"".join(
        struct.pack(">BBH", following, 0, 4 + len(body)) + body
        for following, (_, body) in zip(kinds, payloads, strict=False)
    )


def first_of(payloads: list[tuple[int, bytes]]) -> int:
    """Return the type of the first payload."""
    return payloads[0][0] if payloads else 0


def proposal(transforms: list[tuple[int, int, int | None]], number: int = 1) -> bytes:
    """Return an IKEv2 proposal (the last) of transforms: type, id, key length."""
    body = b""
    for index, (kind, ident, length) in enumerate(transforms):
        attributes = struct.pack(">HH", KEY_LENGTH, length) if length else b""
        more = 3 if index + 1 < len(transforms) else 0
        body += struct.pack(">BBHBBH", more, 0, 8 + len(attributes), kind, 0, ident)
        body += attributes
    return (
        struct.pack(">BBHBBBB", 0, 0, 8 + len(body), number, 1, 0, len(transforms))
        + body
    )


def sa_1(transforms: list[list[tuple[int, int]]]) -> bytes:
    """Return an IKEv1 SA payload: a proposal with transforms of attributes."""
    body = b""
    for index, attributes in enumerate(transforms):
        encoded = b"".join(
            struct.pack(">HH", 0x8000 | kind, value) for kind, value in attributes
        )
        more = 3 if index + 1 < len(transforms) else 0
        body += struct.pack(">BBHBBH", more, 0, 8 + len(encoded), index + 1, 1, 0)
        body += encoded
    # The IPsec DOI, the situation (identity only), then the proposal: ISAKMP.
    return (
        struct.pack(">II", 1, 1)
        + struct.pack(">BBHBBBB", 0, 0, 8 + len(body), 1, 1, 0, len(transforms))
        + body
    )


def sentinel() -> bytes:
    """Return a first IKEv2 request that charon answers and then forgets.

    Its proposal isn't the connection's: charon answers NO_PROPOSAL_CHOSEN.
    """
    other = [
        (ENCR, AES_CBC, 128),
        (INTEG, 12, None),
        (PRF, 5, None),
        (GROUP, ECP_256, None),
    ]
    payloads = [
        (SA, proposal(other)),
        (KE, struct.pack(">HH", ECP_256, 0) + os.urandom(64)),
        (NONCE, os.urandom(32)),
    ]
    return header(chained(payloads), SA)


@st.composite
def extras(draw: st.DrawFn) -> list[tuple[int, bytes]]:
    """Return what else a first IKEv2 message holds: notifies and vendor ids."""
    found = []
    for _ in range(draw(st.integers(0, 3))):
        if draw(st.booleans()):
            kind = draw(
                st.one_of(st.sampled_from(sorted(NOTIFIES)), st.integers(0, 0xFFFF))
            )
            size = draw(mostly(NOTIFIES.get(kind, 0), st.integers(0, 64)))
            data = draw(st.binary(min_size=size, max_size=size))
            found.append((NOTIFY, struct.pack(">BBH", 0, 0, kind) + data))
        else:
            vendor = draw(
                st.one_of(
                    st.sampled_from(VENDORS).map(bytes.fromhex), st.binary(max_size=32)
                )
            )
            found.append((VID, vendor))
    return found


@st.composite
def reordered(draw: st.DrawFn, payloads: list[tuple[int, bytes]]) -> tuple[bool, list]:
    """Return whether payloads are as they were, and them: mostly so.

    Else one is left out or sent twice, or they're in another order.
    """
    how = draw(mostly("", st.sampled_from(["drop", "twice", "shuffle"])))
    if not how or not payloads:
        return True, payloads
    payloads = list(payloads)
    if how == "drop":
        payloads.pop(draw(st.integers(0, len(payloads) - 1)))
    elif how == "twice":
        payloads.append(draw(st.sampled_from(payloads)))
    else:
        payloads = draw(st.permutations(payloads))
    return False, payloads


@st.composite
def first_2(draw: st.DrawFn, family: int) -> Message:
    """Return an IKE_SA_INIT request, each of its parts right mostly."""
    transforms = draw(mostly(PROPOSAL, st.sampled_from(PROPOSALS)))
    # The connection's proposal on its own, or after others.
    others = draw(
        mostly([], st.lists(st.sampled_from(PROPOSALS), min_size=1, max_size=3))
    )
    proposals = [
        proposal(p, number + 1) for number, p in enumerate([*others, transforms])
    ]
    offered = b"".join(bytes([2]) + p[1:] for p in proposals[:-1]) + proposals[-1]
    group = draw(mostly(X25519, st.sampled_from([*KE_SIZES, 0, 0xFFFF])))
    size = draw(mostly(KE_SIZES.get(group, 32), st.integers(0, 600)))
    key = draw(st.binary(min_size=size, max_size=size))
    nonce = draw(
        mostly(32, st.integers(0, 300)).flatmap(
            lambda n: st.binary(min_size=n, max_size=n)
        )
    )
    whole, payloads = draw(
        reordered(
            [(SA, offered), (KE, struct.pack(">HH", group, 0) + key), (NONCE, nonce)]
        )
    )
    payloads = [*payloads, *draw(extras())]
    # Random: zeros or a repeat are read as a retransmit.
    spis = os.urandom(8) + bytes(8)
    accepted = (
        whole
        and VERSIONS[family] == 2  # noqa: PLR2004
        and transforms is PROPOSAL
        and (group, size) == (X25519, KE_SIZES[X25519])
        and 16 <= len(nonce) <= 256  # noqa: PLR2004
    )
    refused = None
    if accepted:
        # The same with another group: charon answers INVALID_KE_PAYLOAD.
        other = [
            (SA, offered),
            (KE, struct.pack(">HH", ECP_256, 0) + key),
            (NONCE, nonce),
        ]
        refused = header(chained([*other, *payloads[3:]]), SA, spis=spis)
    return Message(
        header(chained(payloads), first_of(payloads), spis=spis), refused=refused
    )


@st.composite
def first_1(draw: st.DrawFn, family: int) -> Message:
    """Return IKEv1's first message: main mode's (an SA) or aggressive mode's."""
    transforms = draw(
        mostly(
            [TRANSFORM_1],
            st.lists(st.sampled_from([TRANSFORM_1, *TRANSFORMS_1]), max_size=4),
        )
    )
    payloads = [(SA_1, sa_1(transforms))]
    aggressive = draw(st.sampled_from([False, False, True]))
    if aggressive:
        size = draw(mostly(KE_SIZES[MODP_3072], st.integers(0, 600)))
        payloads += [
            (KE_1, draw(st.binary(min_size=size, max_size=size))),
            (NONCE_1, draw(st.binary(min_size=0, max_size=64))),
            # An IPv4 address as the id.
            (
                ID_1,
                struct.pack(">BBH", 1, 0, 0) + draw(st.binary(min_size=4, max_size=4)),
            ),
        ]
    whole, payloads = draw(reordered(payloads))
    vendors = draw(st.lists(st.sampled_from(VENDORS).map(bytes.fromhex), max_size=4))
    payloads = [*payloads, *((VID_1, vendor) for vendor in vendors)]
    # Random: zeros or a repeat are read as a retransmit.
    spis = os.urandom(8) + bytes(8)
    exchange = AGGRESSIVE if aggressive else MAIN
    accepted = (
        whole and not aggressive and VERSIONS[family] == 1 and TRANSFORM_1 in transforms
    )
    refused = None
    if accepted:
        # The same without the connection's transform: NO_PROPOSAL_CHOSEN.
        other = [(SA_1, sa_1([TRANSFORMS_1[0]])), *payloads[1:]]
        refused = header(
            chained(other), SA_1, version=1, exchange=exchange, flags=0, spis=spis
        )
    data = header(
        chained(payloads),
        first_of(payloads),
        version=1,
        exchange=exchange,
        flags=0,
        spis=spis,
    )
    return Message(data, refused=refused)


@st.composite
def transform(draw: st.DrawFn) -> bytes:
    """Return a transform substructure: type, id, maybe a key length."""
    kind = draw(st.one_of(st.integers(1, 6), st.integers(0, 255)))
    ident = draw(
        st.one_of(
            st.sampled_from([12, 20, 14, 19, 31, 6, 5, 36, 0]), st.integers(0, 0xFFFF)
        )
    )
    attributes = draw(
        st.one_of(
            st.just(b""),
            st.just(struct.pack(">HH", KEY_LENGTH, 256)),
            st.binary(max_size=8),
        ),
    )
    length = draw(mostly(8 + len(attributes), st.integers(0, 0xFFFF)))
    return (
        struct.pack(
            ">BBHBBH", draw(st.sampled_from([3, 3, 0])), 0, length, kind, 0, ident
        )
        + attributes
    )


@st.composite
def any_proposal(draw: st.DrawFn) -> bytes:
    """Return a proposal substructure with transforms, its lengths true or not."""
    transforms = draw(st.lists(transform(), max_size=6))
    spi = draw(st.sampled_from([b"", b"", b"\x01\x02\x03\x04", bytes(8)]))
    body = b"".join(transforms)
    length = draw(mostly(8 + len(spi) + len(body), st.integers(0, 0xFFFF)))
    count = draw(mostly(len(transforms), st.integers(0, 255)))
    return (
        struct.pack(
            ">BBHBBBB",
            draw(st.sampled_from([0, 0, 2])),
            0,
            length,
            draw(st.integers(0, 3)),
            draw(st.sampled_from([1, 1, 3, 2, 0, 255])),
            len(spi),
            count,
        )
        + spi
        + body
    )


@st.composite
def body(draw: st.DrawFn, kind: int) -> bytes:
    """Return a payload's body: as its type has it mostly, or any bytes."""
    structured = {
        SA: st.lists(any_proposal(), min_size=1, max_size=3).map(b"".join),
        SA_1: st.lists(any_proposal(), max_size=2).map(
            lambda p: struct.pack(">II", 1, 1) + b"".join(p)
        ),
        KE: st.tuples(
            st.sampled_from([*KE_SIZES, 0, 0xFFFF]), st.binary(max_size=300)
        ).map(
            lambda t: struct.pack(">HH", t[0], 0) + t[1],
        ),
        NONCE: st.binary(max_size=300),
        NOTIFY: st.tuples(
            st.sampled_from([0, 1, 3]),
            st.sampled_from([*NOTIFIES, 14, 24, 0xFFFF]),
            st.binary(max_size=40),
        ).map(lambda t: struct.pack(">BBH", t[0], 0, t[1]) + t[2]),
        # A fragment: its number and how many there are.
        SKF: st.tuples(
            st.integers(0, 3), st.integers(0, 3), st.binary(max_size=120)
        ).map(
            lambda t: struct.pack(">HH", t[0], t[1]) + t[2],
        ),
        FRAG_1: st.tuples(
            st.integers(0, 3), st.integers(0, 3), st.binary(max_size=120)
        ).map(
            lambda t: struct.pack(">HBB", 1, t[0], t[1]) + t[2],
        ),
    }.get(kind, st.binary(max_size=120))
    return draw(st.one_of(structured, structured, st.binary(max_size=120)))


@st.composite
def any_chain(draw: st.DrawFn, version: int) -> tuple[int, bytes]:
    """Return the first payload's type and a chain of any payloads.

    Their lengths are true mostly: charon stops at the first that isn't.
    """
    known = PAYLOADS if version == 2 else PAYLOADS_1  # noqa: PLR2004
    kinds = draw(
        st.lists(st.one_of(st.sampled_from(known), st.integers(0, 255)), max_size=6)
    )
    chain = b""
    for index, kind in enumerate(kinds):
        data = draw(body(kind))
        following = kinds[index + 1] if index + 1 < len(kinds) else 0
        length = draw(st.one_of(*[st.just(4 + len(data))] * 9, st.integers(0, 0xFFFF)))
        critical = draw(st.sampled_from([0, 0, 0, 0x80]))
        chain += struct.pack(">BBH", following, critical, length) + data
    return (kinds[0] if kinds else 0), chain


@st.composite
def chain_message(draw: st.DrawFn) -> Message:
    """Return a first message of any payloads: its header is one charon reads."""
    version = draw(st.sampled_from([2, 2, 1]))
    first, chain = draw(any_chain(version))
    if version == 1:
        exchange = draw(st.sampled_from([MAIN, MAIN, AGGRESSIVE]))
        return Message(header(chain, first, version=1, exchange=exchange, flags=0))
    return Message(header(chain, first))


@st.composite
def later_message(draw: st.DrawFn) -> Message:
    """Return a message of a later exchange, for the IKE SA charon answered last.

    Encrypted (anything: charon can't decrypt it), in fragments, or in the clear.
    """
    version = draw(st.sampled_from([2, 2, 1]))
    if version == 2:  # noqa: PLR2004
        first, chain = draw(
            st.one_of(
                st.binary(max_size=200).map(lambda data: (SK, chained([(SK, data)]))),
                body(SKF).map(lambda data: (SKF, chained([(SKF, data)]))),
                any_chain(2),
            ),
        )
        data = header(
            chain,
            first,
            exchange=draw(
                st.sampled_from(
                    [
                        IKE_AUTH,
                        IKE_AUTH,
                        IKE_INTERMEDIATE,
                        INFORMATIONAL,
                        CREATE_CHILD_SA,
                    ]
                )
            ),
            flags=draw(mostly(0x08, st.sampled_from([0x28, 0x20, 0]))),
            message_id=draw(st.sampled_from([1, 1, 1, 0, 2, 0xFFFFFFFF])),
        )
        return Message(data, patch=True)
    # Main mode's key exchange (with NAT detection), or anything.
    size = draw(mostly(KE_SIZES[MODP_3072], st.integers(0, 600)))
    exchange_1 = [
        (KE_1, draw(st.binary(min_size=size, max_size=size))),
        (NONCE_1, draw(st.binary(min_size=0, max_size=64))),
        (NAT_D_1, draw(st.binary(min_size=32, max_size=32))),
        (NAT_D_1, draw(st.binary(min_size=32, max_size=32))),
    ]
    first, chain = draw(st.one_of(st.just((KE_1, chained(exchange_1))), any_chain(1)))
    data = header(
        chain,
        first,
        version=1,
        exchange=draw(st.sampled_from([MAIN, MAIN, QUICK, INFORMATIONAL_1, 6])),
        # Encrypted or not.
        flags=draw(st.sampled_from([0, 0, 1])),
        message_id=draw(st.sampled_from([0, 0, 1, 0xFFFFFFFF])),
    )
    return Message(data, patch=True)


@st.composite
def odd_header(draw: st.DrawFn) -> Message:
    """Return a message with a header that's odd in any of its fields."""
    first, chain = draw(any_chain(2))
    length = draw(mostly(HEADER + len(chain), st.integers(0, 0xFFFFFFFF)))
    data = (
        draw(st.binary(min_size=8, max_size=8))
        + draw(mostly(bytes(8), st.binary(min_size=8, max_size=8)))
        + struct.pack(
            ">BBBBII",
            first,
            draw(mostly(0x20, st.sampled_from([0x10, 0x30, 0x21, 0]))),
            draw(
                mostly(
                    IKE_SA_INIT,
                    st.one_of(
                        st.sampled_from([*EXCHANGES, *EXCHANGES_1]), st.integers(0, 255)
                    ),
                )
            ),
            draw(mostly(0x08, st.sampled_from([0x20, 0x28, 0, 0x10, 0xFF]))),
            draw(mostly(0, st.sampled_from([1, 0xFFFFFFFF]))),
            length,
        )
        + chain
    )
    return Message(data)


@st.composite
def broken(draw: st.DrawFn, data: bytes) -> bytes:
    """Return a message broken in one place: a field, a length, cut or longer."""
    data = bytearray(data)
    how = draw(st.sampled_from(["byte", "byte", "length", "cut", "more"]))
    if how == "byte" and data:
        data[draw(st.integers(0, len(data) - 1))] = draw(st.integers(0, 255))
    elif how == "length" and len(data) > HEADER + 4:
        # A payload's length, wherever one starts.
        at = HEADER
        starts = []
        while at + 4 <= len(data):
            starts.append(at)
            at += max(4, struct.unpack_from(">H", data, at + 2)[0])
        at = draw(st.sampled_from(starts))
        struct.pack_into(">H", data, at + 2, draw(st.integers(0, 0xFFFF)))
    elif how == "cut":
        del data[draw(st.integers(0, len(data))) :]
    else:
        data += draw(st.binary(min_size=1, max_size=40))
    return bytes(data)


@st.composite
def ike_message(draw: st.DrawFn, family: int) -> Message:
    """Return an IKE message for a peer's connection."""
    kind = draw(st.integers(0, 9))
    if kind <= 4:  # noqa: PLR2004
        # Of the connection's IKE version mostly.
        version = draw(mostly(VERSIONS[family], st.sampled_from([1, 2])))
        made = draw((first_2 if version == 2 else first_1)(family))  # noqa: PLR2004
        if draw(st.integers(0, 2)) == 0:
            return Message(draw(broken(made.data)))
        return made
    if kind <= 6:  # noqa: PLR2004
        return draw(chain_message())
    if kind <= 8:  # noqa: PLR2004
        return draw(later_message())
    return draw(odd_header())


@dataclass
class Peer:
    """The peers on mgt01, and what the examples check against."""

    agent: conftest.Agent
    vitals: conftest.Vitals
    # When charon last kept an IKE SA of a peer, by address family.
    accepted: dict[int, float]


def in_sender(command: str) -> None:
    """Run a shell command in mgt01's EXTERNAL network instance."""
    conftest.sh(SENDER, f"ip netns exec EXTERNAL {command}")


# charon drops a half-open IKE SA after 30 s.
HALF_OPEN = 35


@pytest.fixture(scope="module")
def peer(deployed: conftest.Deployed) -> Iterator[Peer]:
    """Configure the peers and their tenant."""
    in_sender(f"ip address add {PEERS[4]}/24 dev eth1")
    in_sender(f"ip address add {PEERS[6]}/64 dev eth1 nodad")
    conftest.write_file(
        conftest.HOST,
        f"{conftest.ACTIVE_DIR}/{TENANT}.yaml",
        yaml.safe_dump(CONFIG),
    )
    agent = conftest.Agent(SENDER, netns="EXTERNAL", setup=SENDER_CODE)
    try:
        conftest.wait_until(
            lambda: f"{TENANT}-00" in conftest.snapshot(),
            timeout=APPLY_TIMEOUT,
            message=f"{TENANT} to be applied",
        )
        conftest.stable()
        conftest.check_loaded()
        # charon answers the sentinel from both peers.
        for family, source in PEERS.items():
            conftest.wait_until(
                lambda family=family, source=source: agent.run(
                    "result = send(*args)",
                    [source, HUB[family], 500, [], [], sentinel().hex()],
                )[2],
                timeout=30,
                message=f"charon's answer to {source}",
            )
        yield Peer(agent, conftest.vitals(), {})
    finally:
        agent.stop()
        conftest.sh(conftest.HOST, f"rm -f {conftest.ACTIVE_DIR}/{TENANT}.yaml")
        in_sender(f"ip address del {PEERS[4]}/24 dev eth1; true")
        in_sender(f"ip address del {PEERS[6]}/64 dev eth1; true")
        deployed.reset()


@FUZZ
@given(data=st.data())
def test_ike_packets(peer: Peer, data: st.DataObject) -> None:
    """Charon survives any IKE message, and what's up stays up."""
    family = data.draw(st.sampled_from([4, 6]), label="family")
    transport = data.draw(
        st.sampled_from(["500", "500", "4500", "4500 ESP"]), label="to"
    )
    messages = data.draw(
        st.lists(ike_message(family), min_size=1, max_size=3), label="messages"
    )
    # On 4500 IKE has four zero bytes first; without them it's ESP.
    port = int(transport.split(maxsplit=1)[0])
    marker = 4 if transport == "4500" else 0
    half_open = time.monotonic() - peer.accepted.get(family, -HALF_OPEN) < HALF_OPEN
    sent = [
        ((m.refused if half_open and m.refused else m.data).hex(), m.patch)
        for m in messages
    ]

    answers, accepted, answered = peer.agent.run(
        "result = send(*args)",
        [PEERS[family], HUB[family], port, [0] * marker, sent, sentinel().hex()],
    )
    if accepted:
        peer.accepted[family] = time.monotonic()
    event(f"IPv{family} port {transport}")
    for answer in answers:
        event(f"charon answered: {answer}")

    assert answered, "charon didn't answer the message after them"
    peer.vitals.check()


def test_ike_packets_end(peer: Peer) -> None:
    """Charon accepted IPv4 and IPv6 first messages; all answer once it drops them."""
    missing = {4, 6} - set(peer.accepted)
    assert not missing, f"charon accepted no first message over IPv{missing}"
    time.sleep(max(0, max(peer.accepted.values()) + HALF_OPEN - time.monotonic()))
    conftest.check_answering()
