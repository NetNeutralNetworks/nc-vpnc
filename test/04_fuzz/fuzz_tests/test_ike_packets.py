"""Generated IKE packets to hub00's charon, from a configured peer's address.

A tenant has an IPsec connection to an extra address of mgt01 (hub00's firewall
only lets in the peers' IKE). From it mgt01 sends generated IKE messages: any
exchange, payloads (structured or not), lying lengths, truncated, to port 500 or
4500. charon must keep running and answering, and the connections that are up
stay up.
"""

from __future__ import annotations

import os
import struct
import subprocess
from typing import TYPE_CHECKING

import pytest
import yaml
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest
from .test_network_faults import up_connections

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# An example takes about a second.
FUZZ = settings(
    max_examples=4 * int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
)
TENANT = "C0008"
SENDER = "mgt01"
PEER_4 = "192.0.2.201"
PEER_6 = "2001:db8::201"
HUB = {4: "192.0.2.5", 6: "2001:db8::5"}
APPLY_TIMEOUT = 120
CONFIG = {
    "version": "0.1.4",
    "id": TENANT,
    "name": "Fuzz IKE",
    "network_instances": {
        "00": {
            "type": "DOWNLINK",
            "connections": {
                key: {
                    "routes": {"ipv4": [{"to": f"10.80.{key}.0/24"}], "ipv6": []},
                    "config": {
                        "type": "IPSEC",
                        "remote_addrs": [peer],
                        "initiation": "NONE",
                        "psk": f"fuzz-ike-packets-preshared-key-{key}",
                    },
                }
                for key, peer in enumerate((PEER_4, PEER_6))
            },
        },
    },
}
# Sends the packets (hex, after the address and port) from the peer's address.
SENDER_SCRIPT = """
import socket, sys
address, port, *packets = sys.argv[1:]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
s.bind(("2001:db8::201" if family == socket.AF_INET6 else "192.0.2.201", 0))
s.settimeout(0.2)
for packet in packets:
    s.sendto(bytes.fromhex(packet), (address, int(port)))
    try:
        s.recvfrom(4096)
    except TimeoutError:
        pass
"""

# Payload types: SA, KE, IDi, CERT, CERTREQ, AUTH, Nonce, Notify, Delete, VID,
# TSi, TSr, SK, CP, EAP, SKF.
PAYLOADS = [33, 34, 35, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 53]
# IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL, IKE_INTERMEDIATE.
EXCHANGES = [34, 35, 36, 37, 43]


@st.composite
def transform(draw: st.DrawFn) -> bytes:
    """Return a transform substructure: type, id, maybe a key length."""
    kind = draw(st.one_of(st.integers(1, 5), st.integers(0, 255)))
    ident = draw(
        st.one_of(
            st.sampled_from([12, 20, 14, 19, 31, 2, 5, 0]), st.integers(0, 0xFFFF)
        )
    )
    attributes = draw(
        st.one_of(
            st.just(b""),
            st.just(struct.pack(">HH", 0x800E, 256)),
            st.binary(max_size=8),
        ),
    )
    length = draw(st.one_of(st.just(8 + len(attributes)), st.integers(0, 0xFFFF)))
    return struct.pack(">BBHBBH", 3, 0, length, kind, 0, ident) + attributes


@st.composite
def proposal(draw: st.DrawFn) -> bytes:
    """Return a proposal substructure with transforms."""
    transforms = draw(st.lists(transform(), max_size=6))
    spi = draw(st.sampled_from([b"", b"\x01\x02\x03\x04", bytes(8)]))
    body = b"".join(transforms)
    length = draw(st.one_of(st.just(8 + len(spi) + len(body)), st.integers(0, 0xFFFF)))
    protocol = draw(st.sampled_from([1, 3, 2, 0, 255]))
    count = draw(st.one_of(st.just(len(transforms)), st.integers(0, 255)))
    return (
        struct.pack(">BBHBBBB", 0, 0, length, 1, protocol, len(spi), count) + spi + body
    )


@st.composite
def payload_body(draw: st.DrawFn, kind: int) -> bytes:
    """Return a payload's body: as its type has it mostly, or any bytes."""
    structured = {
        33: st.lists(proposal(), min_size=1, max_size=3).map(b"".join),
        34: st.tuples(
            st.sampled_from([19, 31, 14, 2, 0, 0xFFFF]), st.binary(max_size=300)
        ).map(
            lambda t: struct.pack(">HH", t[0], 0) + t[1],
        ),
        40: st.binary(min_size=0, max_size=300),
        41: st.tuples(
            st.sampled_from([0, 1, 3]),
            st.sampled_from([16388, 16389, 16390, 16430, 16404, 14, 24, 0xFFFF]),
            st.binary(max_size=40),
        ).map(lambda t: struct.pack(">BBH", t[0], 0, t[1]) + t[2]),
    }.get(kind, st.binary(max_size=120))
    return draw(st.one_of(structured, structured, st.binary(max_size=120)))


def mostly(value: int, other: st.SearchStrategy[int]) -> st.SearchStrategy[int]:
    """Return value three times as often as one of other."""
    return st.one_of(st.just(value), st.just(value), st.just(value), other)


@st.composite
def ike_message(draw: st.DrawFn) -> bytes:
    """Return an IKE message: header and a chain of payloads.

    The header is mostly valid, an IKE_SA_INIT request: charon parses the
    payloads only of a message with a valid header.
    """
    kinds = draw(
        st.lists(st.one_of(st.sampled_from(PAYLOADS), st.integers(0, 255)), max_size=6)
    )
    bodies = [draw(payload_body(kind)) for kind in kinds]
    chain = b""
    for i, body in enumerate(bodies):
        following = kinds[i + 1] if i + 1 < len(kinds) else 0
        length = draw(mostly(4 + len(body), st.integers(0, 0xFFFF)))
        critical = draw(st.sampled_from([0, 0, 0x80]))
        chain += struct.pack(">BBH", following, critical, length) + body
    exchange = draw(
        mostly(34, st.one_of(st.sampled_from(EXCHANGES), st.integers(0, 255)))
    )
    responder_spi = draw(
        st.one_of(
            st.just(bytes(8)),
            st.just(bytes(8)),
            st.just(bytes(8)),
            st.binary(min_size=8, max_size=8),
        )
    )
    length = draw(mostly(28 + len(chain), st.integers(0, 0xFFFFFFFF)))
    header = (
        draw(st.binary(min_size=8, max_size=8))
        + responder_spi
        + struct.pack(
            ">BBBBII",
            kinds[0] if kinds else 0,
            draw(mostly(0x20, st.sampled_from([0x10, 0x30, 0]))),
            exchange,
            draw(mostly(0x08, st.sampled_from([0x20, 0x28, 0]))),
            draw(mostly(0, st.sampled_from([1, 0xFFFFFFFF]))),
            length,
        )
    )
    message = header + chain
    if draw(st.integers(0, 9)) == 0:
        message = message[: draw(st.integers(0, len(message)))]
    return message[:1400]


def charon() -> set[tuple[str, int]]:
    """Return charon's process: a new one means it exited."""
    processes = conftest.snapshot()["(daemons)"]["processes"]
    return {daemon for daemon in processes if daemon[0] == "charon"}


def in_sender(command: str) -> None:
    """Run a shell command in mgt01's EXTERNAL network instance."""
    conftest.run_cmd_shell(SENDER, f"bash -c 'ip netns exec EXTERNAL {command}'")


@pytest.fixture(scope="module")
def peer(deployed: conftest.Deployed) -> Iterator[set[str]]:
    """Configure the peer; return the connections up before."""
    in_sender(f"ip address add {PEER_4}/24 dev eth1")
    in_sender(f"ip address add {PEER_6}/64 dev eth1 nodad")
    conftest.write_file(
        conftest.HOST,
        f"{conftest.ACTIVE_DIR}/{TENANT}.yaml",
        yaml.safe_dump(CONFIG),
    )
    try:
        conftest.wait_until(
            lambda: f"{TENANT}-00" in conftest.snapshot(),
            timeout=APPLY_TIMEOUT,
            message=f"{TENANT} to be applied",
        )
        conftest.stable()
        conftest.check_loaded()
        yield up_connections()
    finally:
        conftest.run_cmd(conftest.HOST, f"rm -f {conftest.ACTIVE_DIR}/{TENANT}.yaml")
        in_sender(f"ip address del {PEER_4}/24 dev eth1; true")
        in_sender(f"ip address del {PEER_6}/64 dev eth1; true")
        deployed.reset()


@FUZZ
@given(
    family=st.sampled_from([4, 6]),
    transport=st.sampled_from(["500", "4500", "4500 ESP"]),
    messages=st.lists(ike_message(), min_size=1, max_size=5),
)
def test_ike_packets(
    peer: set[str],
    family: int,
    transport: str,
    messages: list[bytes],
) -> None:
    """Charon survives any IKE message, and what's up stays up."""
    before = charon()
    # On 4500 IKE has four zero bytes first; without them it's ESP.
    port = transport.split(maxsplit=1)[0]
    prefix = b"\0\0\0\0" if transport == "4500" else b""
    event(f"IPv{family} port {transport}")
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker", "exec", f"{conftest.CONTAINER_PREFIX}{SENDER}",
            "ip", "netns", "exec", "EXTERNAL", "python3", "-c", SENDER_SCRIPT,
            HUB[family], port, *((prefix + m).hex() or "00" for m in messages),
        ],
        capture_output=True,
        check=True,
    )  # fmt: skip

    assert charon() == before, "charon exited"
    conftest.check_answering()
    down = peer - up_connections()
    assert not down, f"went down: {', '.join(sorted(down))}"
    assert not conftest.bgp_down(), f"BGP went down: {conftest.bgp_down()}"
    assert conftest.restarts() == 0, "vpnc exited"
