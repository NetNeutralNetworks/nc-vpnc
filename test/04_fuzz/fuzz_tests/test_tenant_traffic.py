"""Generated traffic from tenants into hub00, through their tunnels, from any range.

Packets enter hub00 as a tenant's: through cli00's SSH tunnel and end00's IPsec
tunnel (C0001-00), and end01's WireGuard tunnel (C0001-01; with any allowed IPs
on end01: they're the tenant's to set). Their sources and destinations come from
the tenant's routes and traffic selectors, the other tenant's, both NAT64 and
NPTv6 prefixes, the core, hub00's own addresses and odd ones (multicast,
link-local, ...). IPv4 and IPv6, with options, extension headers and fragments;
ICMP and ICMPv6 of any type, with ND options and embedded packets; UDP (DNS
answers among it), TCP and other protocols. A tenant starts nothing through
hub00: no packet leaves its network instance, other than in hub00's own ICMP
errors and echo replies. One sniffer in all of hub00's network instances sees
what does.

Also spoofed DNS answers to mgt00's queries (through NAT64, as is and NPTv6),
with the same IP variations: vpncmangle lets no tenant address through that it
didn't translate. Throughout, vpnc, its daemons, the connections and BGP keep
running.

After an example's packets a sentinel follows them through the tunnel (a ping
of hub00, or a DNS answer that vpncmangle translates): once it's there, hub00
has had the packets, and the tunnel still carries.
"""

from __future__ import annotations

import collections
import ipaddress
import itertools
import json
import os
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple

import pytest
from fuzz_common import dns_strategies, dns_wire
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest
from . import test_dns_answers as dns

if TYPE_CHECKING:
    from collections.abc import Iterator

    Address = ipaddress.IPv4Address | ipaddress.IPv6Address

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# An example takes about 60 ms.
FUZZ = settings(
    max_examples=10 * int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
)


@dataclass(frozen=True)
class Link:
    """A tenant's tunnel into hub00, as its other end sends into it."""

    node: str
    netns: str | None
    interface: str
    # hub00's network instance it enters, and its address there (the sentinel's).
    ni: str
    hub: str
    tenant: str
    # A host that hub00 reaches through this link only: it pings it.
    host: str


LINKS = {
    "SSH": Link(
        "cli00",
        None,
        "tun0",
        "C0001-00",
        "fdcc:cbe:0:1::",
        "2001:db8:c57::1",
        "2001:db8:c57::1",
    ),
    "IPSEC": Link(
        "end00",
        "CORE",
        "xfrm0",
        "C0001-00",
        "fdcc:cbe::",
        "2001:db8:c57::ffff",
        "172.16.30.1",
    ),
    "WIREGUARD": Link(
        "end01",
        "CORE",
        "wg-CORE-0",
        "C0001-01",
        "fdcc:cbe:1::",
        "2001:db8:c58::1",
        "2001:db8:c58::1",
    ),
}


@dataclass(frozen=True)
class Tenant:
    """A network instance's ranges, as hub00 and the core know them."""

    routes: tuple[str, ...]
    hosts: tuple[str, ...]
    nat64: str
    nptv6: tuple[str, ...]
    links: tuple[str, ...]


TENANTS = {
    "C0001-00": Tenant(
        routes=(
            "2001:db8:c57::/48",
            "fdff:db8:c57::/52",
            "fdff:db8:c57:1000::/52",
            "fdff:db8:c57:2000::/56",
            "fdff:db8:c57:3000::/52",
            "172.16.30.0/24",
            "172.16.31.0/24",
        ),
        hosts=(
            "172.16.30.1",
            "172.16.31.1",
            "2001:db8:c57::1",
            "2001:db8:c57:31::1",
            "fdff:db8:c57::1",
            "fdff:db8:c57:31::1",
        ),
        nat64="fdcc:0:c:1::/96",
        nptv6=("fd6c:1::/48", "fd6c:1::1", "fd6c:1:0:31::1"),
        links=("100.99.0.0/28", "100.99.0.16/28", "fdcc:cbe::/64", "fdcc:cbe:0:1::/64"),
    ),
    "C0001-01": Tenant(
        routes=(
            "2001:db8:c58::/48",
            "fdff:db8:c58::/52",
            "fdff:db8:c58:1000::/52",
            "fdff:db8:c58:2000::/56",
            "fdff:db8:c58:3000::/52",
            "172.17.30.0/24",
            "172.17.31.0/24",
        ),
        hosts=(
            "172.17.30.1",
            "172.17.31.1",
            "2001:db8:c58::1",
            "2001:db8:c58:31::1",
            "fdff:db8:c58::1",
            "fdff:db8:c58:31::1",
        ),
        nat64="fdcc:0:c:1:1::/96",
        nptv6=("fd6c:1:1::/48", "fd6c:1:1::1", "fd6c:1:1:31::1"),
        links=("100.99.1.0/28", "fdcc:cbe:1::/64"),
    ),
}
CORE = (
    "fd00::/16",
    "fd01::/16",
    "fd00::3",
    "fd01:3::1",
    "fd00:1:2::",
    "fd00:1:2::1",
    "fd00:1:2::1:0",
    "fd00:1:2::1:1",
)
EXTERNAL = ("192.0.2.0/24", "2001:db8::/64", "192.0.2.5", "2001:db8::5", "192.0.2.3")
SPECIAL = (
    "0.0.0.0",  # noqa: S104
    "127.0.0.1",
    "255.255.255.255",
    "224.0.0.1",
    "224.0.0.5",
    "239.255.255.250",
    "169.254.0.1",
    "240.0.0.1",
    "100.64.0.1",
    "::",
    "::1",
    "ff02::1",
    "ff02::2",
    "ff02::1:ff00:1",
    "ff05::1:3",
    "fe80::1",
    "::ffff:192.0.2.5",
    "64:ff9b::c000:205",
)

# The spoofed DNS answers: mgt00 asks these addresses; cli00 holds them.
DNS_PATHS = {
    "NAT64": ("fdcc:0:c:1::172.16.31.153", "172.16.31.153"),
    "DNS66": ("2001:db8:c57:31::153", "2001:db8:c57:31::153"),
    "NPTv6": ("fd6c:1:0:31::153", "fdff:db8:c57:31::153"),
}
# How long a sentinel may take.
SENTINEL_TIMEOUT = 2
# A link that works answers one of these pings (a second each).
CARRY_TRIES = 5
# Per run: in every packet, before the example's number.
MAGIC = os.urandom(8)
EXAMPLES = itertools.count(1)
# An example's sentinel has its number with this.
SENTINEL = 1 << 31
# The versions a tun device takes.
IP_VERSIONS = (4, 6)
# Set by AF_PACKET on packets a host sends.
OUTGOING = 4

# Sends packets (hex) on an interface, as its link layer has them. On a
# WireGuard interface with any allowed IPs for its peer, as a tenant can set
# them: vpnc sets its own again.
INJECTOR = """
import socket, subprocess

SOCKET = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)


def inject(interface, packets):
    if interface.startswith("wg"):
        peers = subprocess.run(
            ["wg", "show", interface, "peers"], capture_output=True, text=True
        ).stdout.split()
        for peer in peers:
            subprocess.run(
                ["wg", "set", interface, "peer", peer, "allowed-ips", "0.0.0.0/0,::/0"]
            )
    for packet in packets:
        data = bytes.fromhex(packet)
        protocol = 0x86DD if data and data[0] >> 4 == 6 else 0x0800
        try:
            SOCKET.sendto(data, (interface, protocol))
        except OSError:
            pass
"""
# Prints the packets that hold the marker (argv[1]) in the network instances
# (the other arguments): network instance, interface, packet type, packet (hex).
# Until its input closes.
SNIFFER = """
import os, select, socket, sys

magic = bytes.fromhex(sys.argv[1])
own = os.open("/proc/self/ns/net", os.O_RDONLY)
socks = {}
for ni in sys.argv[2:]:
    if ni != "root":
        netns = os.open(f"/run/netns/{ni}", os.O_RDONLY)
        os.setns(netns, os.CLONE_NEWNET)
        os.close(netns)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 24)
    socks[s] = ni
    os.setns(own, os.CLONE_NEWNET)
print("ready", flush=True)
while True:
    for s in select.select([sys.stdin, *socks], [], [])[0]:
        if s is sys.stdin:
            # The test ended.
            sys.exit()
        data, address = s.recvfrom(65535)
        if magic in data:
            print(socks[s], address[0], address[2], data.hex(), flush=True)
"""
# Answers each query to the addresses it holds with SPEC's packets, sent on
# tun0 (into hub00) to the query's sender: its address, port and id patched in,
# their checksums adjusted. Then with the sentinel (see test_dns_answers.py). It
# binds before the addresses exist (freebind), so that named doesn't take them.
SPOOFER = f"""
import select, socket, struct, threading
{dns.SENTINEL}
SPEC = None
socks = []
for family, level, option, address in (
    (socket.AF_INET, socket.IPPROTO_IP, 15, "{DNS_PATHS["NAT64"][1]}"),
    (socket.AF_INET6, socket.IPPROTO_IPV6, 78, "{DNS_PATHS["DNS66"][1]}"),
    (socket.AF_INET6, socket.IPPROTO_IPV6, 78, "{DNS_PATHS["NPTv6"][1]}"),
):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.setsockopt(level, option, 1)
    s.bind((address, 53))
    socks.append(s)
raw = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)


def adjust(packet, at, old, new):
    total = ~struct.unpack_from("!H", packet, at)[0] & 0xFFFF
    for i in range(0, len(old), 2):
        total += (~struct.unpack_from("!H", old, i)[0] & 0xFFFF)
        total += struct.unpack_from("!H", new, i)[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    struct.pack_into("!H", packet, at, ~total & 0xFFFF)


def spoof(s, query, peer, spec):
    dst = socket.inet_pton(s.family, peer[0])
    port = struct.pack("!H", peer[1])
    for data, dst_at, l4_at, ipsum_at in spec["fragments"]:
        packet = bytearray(bytes.fromhex(data))
        old = bytes(packet[dst_at:dst_at + len(dst)])
        packet[dst_at:dst_at + len(dst)] = dst
        if ipsum_at is not None:
            adjust(packet, ipsum_at, old, dst)
        u = l4_at
        if u is not None and len(packet) >= u + 10:
            before = old + bytes(packet[u + 2:u + 4] + packet[u + 8:u + 10])
            ident = query[:2] if spec["keep_id"] else bytes(packet[u + 8:u + 10])
            packet[u + 2:u + 4] = port
            packet[u + 8:u + 10] = ident
            if s.family == socket.AF_INET6 or packet[u + 6:u + 8] != b"\\0\\0":
                adjust(packet, u + 6, before, dst + port + ident)
        protocol = 0x86DD if s.family == socket.AF_INET6 else 0x0800
        try:
            raw.sendto(bytes(packet), ("tun0", protocol))
        except OSError:
            pass


def serve():
    while True:
        for s in select.select(socks, [], [])[0]:
            query, peer = s.recvfrom(4096)
            if SPEC:
                spoof(s, query, peer, SPEC)
            s.sendto(sentinel(query), peer)


threading.Thread(target=serve, daemon=True).start()
"""


class Fragment(NamedTuple):
    """A packet, and where its destination, transport header and checksum are."""

    data: bytes
    dst_at: int
    l4_at: int | None
    ipsum_at: int | None


def mostly(value: object, other: st.SearchStrategy) -> st.SearchStrategy:
    """Return value three times as often as one of other."""
    return st.one_of(st.just(value), st.just(value), st.just(value), other)


def checksum(data: bytes) -> int:
    """Return the Internet checksum of data."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def pseudo(src: Address, dst: Address, proto: int, length: int) -> bytes:
    """Return the pseudo-header of a transport checksum."""
    if src.version == 4:  # noqa: PLR2004
        return src.packed + dst.packed + struct.pack("!xBH", proto, length & 0xFFFF)
    return src.packed + dst.packed + struct.pack("!I3xB", length, proto)


@st.composite
def summed(draw: st.DrawFn, data: bytes, at: int, prefix: bytes = b"") -> bytes:
    """Return data with its checksum at at: right mostly, sometimes wrong or zero."""
    right = checksum(prefix + data)
    value = draw(mostly(right, st.one_of(st.just(0), st.integers(0, 0xFFFF))))
    return data[:at] + struct.pack("!H", value) + data[at + 2 :]


# Addresses


def nat64(prefix: str, hosts: tuple[str, ...]) -> list[str]:
    """Return the NAT64 prefix and the IPv4 hosts in it."""
    network = ipaddress.IPv6Network(prefix)
    return [prefix] + [
        str(ipaddress.IPv6Address(int(network.network_address) | int(v4)))
        for host in hosts
        if (v4 := ipaddress.ip_address(host)).version == 4  # noqa: PLR2004
    ]


def categories(ni: str) -> dict[str, list[str]]:
    """Return the ranges and hosts per category, as a tenant of ni sees them."""
    own = TENANTS[ni]
    other = next(t for name, t in TENANTS.items() if name != ni)
    return {
        "own": [*own.routes, *own.hosts],
        "own NAT64": nat64(own.nat64, own.hosts),
        "own NPTv6": list(own.nptv6),
        "other tenant": [*other.routes, *other.hosts],
        "other NAT64": nat64(other.nat64, other.hosts),
        "other NPTv6": list(other.nptv6),
        "core": list(CORE),
        "hub": [*own.links, *other.links, "192.0.2.5", "2001:db8::5"],
        "external": list(EXTERNAL),
        "special": list(SPECIAL),
    }


@st.composite
def address(draw: st.DrawFn, family: int, entries: list[str]) -> Address:
    """Return an address of a family: one of the hosts, or in one of the ranges."""
    if not entries:
        bits = 32 if family == 4 else 128  # noqa: PLR2004
        return ipaddress.ip_address(draw(st.integers(0, 2**bits - 1)))
    entry = ipaddress.ip_network(draw(st.sampled_from(entries)), strict=False)
    last = entry.num_addresses - 1
    offset = draw(
        st.one_of(st.just(0), st.just(1), st.just(last), st.integers(0, last)),
    )
    return entry.network_address + min(offset, last)


@st.composite
def endpoint(draw: st.DrawFn, family: int, ni: str) -> tuple[str, Address]:
    """Return a category and an address of it (any: random)."""
    found = {
        name: [
            e
            for e in entries
            if ipaddress.ip_network(e, strict=False).version == family
        ]
        for name, entries in categories(ni).items()
    }
    name = draw(st.sampled_from([*sorted(n for n, e in found.items() if e), "any"]))
    return name, draw(address(family, found.get(name, [])))


# Transport


PORTS = [53, 22, 179, 3784, 4784, 6784, 500, 4500, 51820, 123, 67, 547, 5353, 0, 8080]
ICMP4 = {
    0: [0],
    3: list(range(16)),
    4: [0],
    5: [0, 1, 2, 3],
    8: [0],
    9: [0],
    10: [0],
    11: [0, 1],
    12: [0, 1, 2],
    13: [0],
    14: [0],
    17: [0],
    18: [0],
}
ICMP4_ERRORS = {3, 4, 5, 11, 12}
ICMP6 = {
    1: list(range(8)),
    2: [0],
    3: [0, 1],
    4: [0, 1, 2, 3],
    128: [0],
    129: [0],
    130: [0],
    131: [0],
    132: [0],
    133: [0],
    134: [0],
    135: [0],
    136: [0],
    137: [0],
    139: [0, 1, 2],
    140: [0, 1, 2],
    143: [0],
}
ICMP6_ERRORS = {1, 2, 3, 4}
ND = {133: 4, 134: 12, 135: 20, 136: 20, 137: 36}
# An unknown ND option that holds the marker, so that options before it parse.
MARKER_OPTION = 200


def port() -> st.SearchStrategy[int]:
    """Return a port: a known one mostly."""
    return st.one_of(st.sampled_from(PORTS), st.integers(0, 0xFFFF))


@st.composite
def nd_option(draw: st.DrawFn, family_inner: st.SearchStrategy[bytes]) -> bytes:
    """Return an ND option, its length true or not."""
    kind = draw(
        st.one_of(
            st.sampled_from([1, 2, 3, 4, 5, 14, 24, 25, 31, 38]), st.integers(0, 255)
        )
    )
    body = {
        1: st.binary(min_size=6, max_size=6),
        2: st.binary(min_size=6, max_size=6),
        # Prefix information: length, flags, lifetimes, prefix.
        3: st.tuples(
            st.integers(0, 255),
            st.integers(0, 255),
            st.binary(min_size=12, max_size=12),
            st.binary(min_size=16, max_size=16),
        ).map(lambda t: bytes(t[:2]) + t[2] + t[3]),
        4: family_inner.map(lambda p: bytes(6) + p),
        5: st.integers(0, 0xFFFFFFFF).map(lambda m: bytes(2) + struct.pack("!I", m)),
        24: st.binary(min_size=6, max_size=22),
        25: st.lists(st.binary(min_size=16, max_size=16), max_size=3).map(
            lambda a: bytes(2) + b"\xff\xff\xff\xff" + b"".join(a)
        ),
        31: st.binary(max_size=30).map(lambda n: bytes(2) + b"\xff\xff\xff\xff" + n),
        38: st.binary(min_size=14, max_size=14),
    }.get(kind, st.binary(max_size=30))
    data = draw(body)
    data += bytes(-(len(data) + 2) % 8)
    length = draw(mostly((len(data) + 2) // 8, st.integers(0, 255)))
    return bytes([kind, length]) + data


@st.composite
def inner(draw: st.DrawFn, family: int, ni: str, marker: bytes) -> bytes:
    """Return a packet as an ICMP error embeds it: maybe truncated, then the marker."""
    _, src = draw(endpoint(family, ni))
    _, dst = draw(endpoint(family, ni))
    proto, l4 = draw(transport(family, src, dst, b"", ni, embedded=True))
    packet = draw(ip(family, src, dst, proto, l4, simple=True))[0].data
    return packet[: draw(st.integers(0, len(packet)))] + marker


@st.composite
def icmp(  # noqa: PLR0913, PLR0917
    draw: st.DrawFn,
    family: int,
    src: Address,
    dst: Address,
    marker: bytes,
    ni: str,
    *,
    embedded: bool,
) -> tuple[int, bytes]:
    """Return an ICMP or ICMPv6 message of any type, as a known type has it mostly."""
    types = ICMP4 if family == 4 else ICMP6  # noqa: PLR2004
    errors = ICMP4_ERRORS if family == 4 else ICMP6_ERRORS  # noqa: PLR2004
    kind = draw(st.one_of(st.sampled_from(sorted(types)), st.integers(0, 255)))
    code = draw(st.one_of(st.sampled_from(types.get(kind, [0])), st.integers(0, 255)))
    if kind in errors and not embedded:
        # MTU, pointer, gateway or unused; then the packet that caused it.
        rest = draw(st.one_of(st.just(bytes(4)), st.binary(min_size=4, max_size=4)))
        body = rest + draw(inner(family, ni, marker))
    elif kind in ND and family == 6 and not embedded:  # noqa: PLR2004
        fixed = draw(st.binary(min_size=ND[kind], max_size=ND[kind]))
        options = draw(st.lists(nd_option(inner(family, ni, marker)), max_size=4))
        body = fixed + b"".join(options) + bytes([MARKER_OPTION, 2]) + marker
    else:
        # Echo: identifier and sequence; others: their fields, or anything.
        body = draw(st.binary(min_size=4, max_size=4)) + marker
        body += draw(st.binary(max_size=64))
    message = struct.pack("!BBH", kind, code, 0) + body
    if family == 4:  # noqa: PLR2004
        return 1, draw(summed(message, 2))
    return 58, draw(summed(message, 2, pseudo(src, dst, 58, len(message))))


@st.composite
def udp(draw: st.DrawFn, src: Address, dst: Address, marker: bytes) -> bytes:
    """Return a UDP datagram: a DNS answer from port 53 mostly, else anything."""
    sport = draw(port())
    dport = draw(port())
    if sport == 53 or draw(st.integers(0, 4)) == 0:  # noqa: PLR2004
        payload = draw(
            dns_strategies.answer(draw(st.sampled_from(sorted(dns.QTYPES.values()))))
        )[1]
    else:
        payload = draw(st.binary(max_size=200))
    payload += marker
    return draw(datagram(src, dst, sport, dport, payload))


@st.composite
def datagram(  # noqa: PLR0913, PLR0917
    draw: st.DrawFn, src: Address, dst: Address, sport: int, dport: int, payload: bytes
) -> bytes:
    """Return a UDP datagram of payload, its length and checksum true or not."""
    length = draw(mostly(8 + len(payload), st.integers(0, 0xFFFF)))
    data = struct.pack("!HHHH", sport, dport, length, 0) + payload
    return draw(summed(data, 6, pseudo(src, dst, 17, len(data))))


@st.composite
def tcp(draw: st.DrawFn, src: Address, dst: Address, marker: bytes) -> bytes:
    """Return a TCP segment of any flags and options."""
    options = draw(
        st.one_of(
            st.just(b""),
            st.just(
                b"\x02\x04\x05\xb4\x04\x02\x08\x0a" + bytes(8) + b"\x01\x03\x03\x07"
            ),
            st.binary(max_size=40),
        ),
    )
    options += bytes(-len(options) % 4)
    offset = draw(mostly(5 + len(options) // 4, st.integers(0, 15)))
    flags = draw(
        st.one_of(
            st.sampled_from([0x02, 0x12, 0x10, 0x04, 0x14, 0x11, 0x18]),
            st.integers(0, 0xFFF),
        )
    )
    segment = struct.pack(
        "!HHIIHHHH",
        draw(port()),
        draw(port()),
        draw(st.integers(0, 0xFFFFFFFF)),
        draw(st.integers(0, 0xFFFFFFFF)),
        offset << 12 | flags,
        draw(st.integers(0, 0xFFFF)),
        0,
        draw(st.integers(0, 0xFFFF)),
    )
    segment += options + marker + draw(st.binary(max_size=100))
    return draw(summed(segment, 16, pseudo(src, dst, 6, len(segment))))


@st.composite
def transport(  # noqa: PLR0913, PLR0917
    draw: st.DrawFn,
    family: int,
    src: Address,
    dst: Address,
    marker: bytes,
    ni: str,
    *,
    embedded: bool = False,
) -> tuple[int, bytes]:
    """Return a protocol and its message: ICMP, UDP, TCP or anything."""
    kind = draw(st.sampled_from(["icmp", "icmp", "udp", "udp", "tcp", "other"]))
    if kind == "icmp":
        return draw(icmp(family, src, dst, marker, ni, embedded=embedded))
    if kind == "udp":
        return 17, draw(udp(src, dst, marker))
    if kind == "tcp":
        return 6, draw(tcp(src, dst, marker))
    proto = draw(
        st.one_of(
            st.sampled_from([4, 41, 47, 50, 51, 2, 103, 112, 132, 59]),
            st.integers(0, 255),
        )
    )
    return proto, marker + draw(st.binary(max_size=100))


# IP


@st.composite
def ipv4_options(draw: st.DrawFn) -> bytes:
    """Return IPv4 options: none mostly, else known ones or anything."""
    options = draw(
        mostly(
            b"",
            st.one_of(
                st.just(b"\x01\x01\x01\x00"),
                # Record route, timestamp, loose and strict source route, router alert.
                st.just(bytes([7, 39, 4]) + bytes(36)),
                st.just(bytes([68, 12, 5, 0]) + bytes(8)),
                st.binary(min_size=4, max_size=4).map(lambda a: bytes([131, 7, 4]) + a),
                st.binary(min_size=4, max_size=4).map(lambda a: bytes([137, 7, 4]) + a),
                st.just(bytes([148, 4, 0, 0])),
                st.binary(max_size=40),
            ),
        ),
    )
    return (options + bytes(-len(options) % 4))[:40]


def split(payload: bytes, parts: int, first: int) -> list[tuple[int, bytes]]:
    """Return payload in parts at multiples of 8 bytes (the first at least first)."""
    if parts == 1 or len(payload) <= first + 8:
        return [(0, payload)]
    size = max(first, (len(payload) // parts + 7) // 8 * 8)
    return [(at, payload[at : at + size]) for at in range(0, len(payload), size)]


@st.composite
def fragments(
    draw: st.DrawFn, payload: bytes, first: int
) -> list[tuple[int, bytes, bool]]:
    """Return payload as one or more fragments: offset, data, more; maybe odd."""
    parts = split(payload, draw(mostly(1, st.integers(2, 4))), first)
    pieces = [(at, data, i < len(parts) - 1) for i, (at, data) in enumerate(parts)]
    if len(pieces) > 1:
        odd = draw(
            st.sampled_from(["", "", "reversed", "duplicate", "overlap", "missing"])
        )
        if odd == "reversed":
            pieces.reverse()
        elif odd == "duplicate":
            pieces.append(pieces[-1])
        elif odd == "overlap":
            at, data, more = pieces[-1]
            pieces[-1] = (at - 8, data, more)
        elif odd == "missing":
            pieces.pop(draw(st.integers(0, len(pieces) - 1)))
    return pieces


def is_split(pieces: list[tuple[int, bytes, bool]]) -> bool:
    """Return whether pieces are fragments (some may be missing)."""
    return len(pieces) > 1 or pieces[0][0] > 0 or pieces[0][2]


@st.composite
def ipv4(  # noqa: PLR0913
    draw: st.DrawFn,
    src: Address,
    dst: Address,
    proto: int,
    payload: bytes,
    *,
    simple: bool = False,
    first: int = 8,
    honest: bool = False,
) -> list[Fragment]:
    """Return an IPv4 packet, odd in any field, maybe as fragments."""
    options = b"" if simple else draw(ipv4_options())
    version = 4 if honest else draw(mostly(4, st.integers(0, 15)))
    tos = draw(st.integers(0, 255))
    ident = draw(st.integers(0, 0xFFFF))
    # honest: as a host sends it (true lengths and checksum), but for the options
    # and fragments.
    flags = draw(
        st.sampled_from([0, 2])
        if honest
        else st.one_of(st.just(0), st.just(2), st.integers(0, 7))
    )
    ttl = (
        64
        if honest
        else draw(st.one_of(st.sampled_from([64, 1, 0, 255]), st.integers(0, 255)))
    )
    pieces = [(0, payload, False)] if simple else draw(fragments(payload, first))
    lie = None if honest else draw(mostly(None, st.integers(0, 0xFFFF)))
    ihl = 5 + len(options) // 4
    ihl = ihl if honest else draw(mostly(ihl, st.integers(0, 15)))
    split_up = is_split(pieces)
    result = []
    for at, data, more in pieces:
        offset = (
            at // 8 if split_up or honest else draw(mostly(0, st.integers(0, 8191)))
        )
        bits = flags & 0b110 | (1 if more else 0 if split_up else flags & 1)
        header = (
            struct.pack(
                "!BBHHHBBH4s4s",
                version << 4 | ihl,
                tos,
                lie if lie is not None else 20 + len(options) + len(data),
                ident,
                bits << 13 | offset,
                ttl,
                proto,
                0,
                src.packed,
                dst.packed,
            )
            + options
        )
        header = (
            header[:10] + struct.pack("!H", checksum(header)) + header[12:]
            if honest
            else draw(summed(header, 10))
        )
        result.append(Fragment(header + data, 16, len(header) if at == 0 else None, 10))
    return result


@st.composite
def extension(draw: st.DrawFn, *, sound: bool = False) -> tuple[int, bytes]:
    """Return an IPv6 extension header without its next header: type and the rest.

    sound: hop-by-hop or destination options that a host passes on.
    """
    kind = draw(st.sampled_from([0, 60] if sound else [0, 60, 43, 44]))
    if sound:
        body = draw(st.sampled_from([bytes(4), b"\x01\x02\x00\x00", b"\x00" * 4]))
        return kind, bytes([0]) + body + bytes(-(len(body) + 2) % 8)
    if kind in (0, 60):
        # Options: Pad1, PadN, router alert, jumbo payload, tunnel limit, anything.
        options = draw(
            st.lists(
                st.one_of(
                    st.just(b"\x00"),
                    st.just(b"\x01\x02\x00\x00"),
                    st.just(b"\x05\x02\x00\x00"),
                    st.binary(min_size=4, max_size=4).map(lambda j: b"\xc2\x04" + j),
                    st.just(b"\x04\x01\x04"),
                    st.tuples(st.integers(0, 255), st.binary(max_size=12)).map(
                        lambda o: bytes([o[0], len(o[1])]) + o[1]
                    ),
                ),
                max_size=4,
            ),
        )
        body = b"".join(options)
        body += bytes(-(len(body) + 2) % 8)
    elif kind == 43:  # noqa: PLR2004
        # Routing: type 0, 2, 3, 4 (segment routing) or any; segments left; addresses.
        routing = draw(st.one_of(st.sampled_from([0, 2, 3, 4]), st.integers(0, 255)))
        addresses = draw(st.lists(st.binary(min_size=16, max_size=16), max_size=3))
        left = draw(st.one_of(st.just(len(addresses)), st.just(0), st.integers(0, 255)))
        body = bytes([routing, left]) + bytes(4) + b"".join(addresses)
    else:
        # An atomic fragment mostly, else any offset and identification.
        body = bytes(1) + draw(mostly(bytes(2), st.binary(min_size=2, max_size=2)))
        body += draw(st.binary(min_size=4, max_size=4))
        return kind, body
    length = draw(mostly((len(body) + 2) // 8 - 1, st.integers(0, 255)))
    return kind, bytes([length]) + body


@st.composite
def ipv6(  # noqa: PLR0913
    draw: st.DrawFn,
    src: Address,
    dst: Address,
    proto: int,
    payload: bytes,
    *,
    simple: bool = False,
    first: int = 8,
    honest: bool = False,
) -> list[Fragment]:
    """Return an IPv6 packet, odd in any field, with extension headers, maybe split."""
    headers = (
        []
        if simple
        else draw(st.lists(extension(sound=honest), max_size=1 if honest else 3))
    )
    pieces = [(0, payload, False)] if simple else draw(fragments(payload, first))
    fragmented = is_split(pieces)
    kinds = [kind for kind, _ in headers] + ([44] if fragmented else []) + [proto]
    chain = b"".join(
        bytes([kinds[i + 1]]) + rest for i, (_, rest) in enumerate(headers)
    )
    version = 6 if honest else draw(mostly(6, st.integers(0, 15)))
    flow = draw(st.integers(0, 0xFFFFF))
    traffic = draw(st.integers(0, 255))
    hops = (
        64
        if honest
        else draw(st.one_of(st.sampled_from([64, 1, 0, 255]), st.integers(0, 255)))
    )
    lie = None if honest else draw(mostly(None, st.integers(0, 0xFFFF)))
    ident = draw(st.integers(0, 0xFFFFFFFF))
    result = []
    for at, data, more in pieces:
        fragment = struct.pack("!BxHI", proto, at | more, ident) if fragmented else b""
        rest = chain + fragment + data
        header = struct.pack(
            "!IHBB16s16s",
            version << 28 | traffic << 20 | flow,
            lie if lie is not None else len(rest),
            kinds[0],
            hops,
            src.packed,
            dst.packed,
        )
        l4_at = 40 + len(chain) + len(fragment) if at == 0 else None
        result.append(Fragment(header + rest, 24, l4_at, None))
    return result


def ip(  # noqa: PLR0913
    family: int,
    src: Address,
    dst: Address,
    proto: int,
    payload: bytes,
    *,
    simple: bool = False,
    first: int = 8,
    honest: bool = False,
) -> st.SearchStrategy[list[Fragment]]:
    """Return an IPv4 or IPv6 packet (fragments) of payload."""
    build = ipv4 if family == 4 else ipv6  # noqa: PLR2004
    return build(src, dst, proto, payload, simple=simple, first=first, honest=honest)


@st.composite
def packet(draw: st.DrawFn, ni: str, marker: bytes) -> tuple[str, list[bytes]]:
    """Return what a packet is (for the statistics) and its fragments."""
    family = draw(st.sampled_from([4, 6]))
    source, src = draw(endpoint(family, ni))
    target, dst = draw(endpoint(family, ni))
    proto, l4 = draw(transport(family, src, dst, marker, ni))
    pieces = draw(ip(family, src, dst, proto, l4))
    return f"IPv{family} {source} -> {target}, protocol {proto}", [
        p.data for p in pieces
    ]


# What hub00 does with them


def hub_addresses() -> set[str]:
    """Return hub00's addresses, in all its network instances."""
    text = conftest.run_cmd_shell(
        conftest.HOST,
        'bash -c \'ip -j addr; for ns in $(ip netns list | cut -d" " -f1); do'
        " ip -n $ns -j addr; done'",
    )
    decoder = json.JSONDecoder()
    found, at = set(), 0
    text = text.strip()
    while at < len(text):
        links, end = decoder.raw_decode(text, at)
        found |= {
            str(ipaddress.ip_address(a["local"]))
            for link in links
            for a in link.get("addr_info", [])
        }
        at = end
        while at < len(text) and text[at].isspace():
            at += 1
    return found


class Sniffed(NamedTuple):
    """A packet with the marker, as a network instance of hub00 had it."""

    ni: str
    interface: str
    outgoing: bool
    data: bytes

    def example(self) -> int:
        """Return the number of the example that sent it (with SENTINEL: its last)."""
        at = self.data.index(MAGIC) + len(MAGIC)
        return int.from_bytes(self.data[at : at + 4].ljust(4, b"\0"))


def describe(data: bytes) -> tuple[int, str, int, int | None]:
    """Return a packet's IP version, source, protocol and ICMP type (if any)."""
    version = data[0] >> 4 if data else 0
    if version == 4 and len(data) >= 20:  # noqa: PLR2004
        start = (data[0] & 15) * 4
        proto = data[9]
        kind = data[start] if proto == 1 and len(data) > start else None
        return 4, str(ipaddress.IPv4Address(data[12:16])), proto, kind
    if version == 6 and len(data) >= 40:  # noqa: PLR2004
        proto, at = data[6], 40
        while proto in (0, 43, 60, 44) and at + 8 <= len(data):
            if proto == 44:  # noqa: PLR2004
                if struct.unpack_from("!H", data, at + 2)[0] >> 3:
                    break
                proto, at = data[at], at + 8
            else:
                proto, at = data[at], at + (data[at + 1] + 1) * 8
        kind = data[at] if proto == 58 and len(data) > at else None  # noqa: PLR2004
        return 6, str(ipaddress.IPv6Address(data[8:24])), proto, kind
    return version, "?", -1, None


# hub00's own answers to a packet: ICMP errors, echo replies, redirects.
REFLECTIONS = {(4, 1): {0, 3, 4, 5, 11, 12}, (6, 58): {1, 2, 3, 4, 129, 137}}


def leaked(sniffed: Sniffed, ni: str, hub: set[str]) -> str | None:
    """Return how a packet left a tenant's network instance, if it did."""
    if not sniffed.outgoing:
        return None
    version, src, proto, kind = describe(sniffed.data)
    own = src in hub and kind in REFLECTIONS.get((version, proto), set())
    back = sniffed.ni == ni or (sniffed.ni == "CORE" and sniffed.interface == f"{ni}_C")
    if own and back:
        return None
    return (
        f"{sniffed.ni} sent on {sniffed.interface}: IPv{version} from {src},"
        f" protocol {proto}, ICMP type {kind}: {sniffed.data.hex()}"
    )


def ping(link: Link, number: int, dst: str | None = None) -> bytes:
    """Return an echo request through a link, to hub00's address on it or dst."""
    src, to = ipaddress.ip_address(link.tenant), ipaddress.ip_address(dst or link.hub)
    message = struct.pack("!BBHHH", 128, 0, 0, 1, 1) + MAGIC + number.to_bytes(4)
    message = (
        message[:2]
        + struct.pack("!H", checksum(pseudo(src, to, 58, len(message)) + message))
        + message[4:]
    )
    header = struct.pack(
        "!IHBB16s16s", 6 << 28, len(message), 58, 64, src.packed, to.packed
    )
    return header + message


class Lab:
    """The sniffer in hub00, the links' injectors and the DNS spoofer on cli00."""

    def __init__(self) -> None:
        """Start the sniffer, the injectors and the spoofer."""
        self.sent: dict[int, str] = {}
        self.hub = hub_addresses()
        self.prefixes = dns.translated_prefixes()
        names = conftest.run_cmd(conftest.HOST, "ip netns list").splitlines()
        instances = ["root", *(line.split()[0] for line in names if line.strip())]
        self.packets: collections.deque[Sniffed] = collections.deque()
        self.arrived = threading.Condition()
        self.sniffer = subprocess.Popen(  # noqa: S603
            [  # noqa: S607
                "docker", "exec", "-i", f"{conftest.CONTAINER_PREFIX}{conftest.HOST}",
                "python3", "-u", "-c", SNIFFER, MAGIC.hex(), *instances,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )  # fmt: skip
        assert self.sniffer.stdout is not None
        assert self.sniffer.stdout.readline().strip() == "ready", "no sniffer"
        threading.Thread(target=self.read, daemon=True).start()
        self.injectors = {
            name: conftest.Agent(link.node, netns=link.netns, setup=INJECTOR)
            for name, link in LINKS.items()
        }
        self.spoofer = conftest.Agent("cli00", setup=SPOOFER)
        self.spoofer.run("")
        self.sentinels: dict[tuple[str, int], str] = {}
        self.errors: dns.Errors | None = None
        self.answered: collections.deque[tuple[float, int]] = collections.deque()
        self.vitals = conftest.vitals()

    def read(self) -> None:
        """Take the sniffer's packets as they come."""
        assert self.sniffer.stdout is not None
        for line in self.sniffer.stdout:
            ni, interface, kind, data = line.split()
            packet = Sniffed(ni, interface, int(kind) == OUTGOING, bytes.fromhex(data))
            with self.arrived:
                self.packets.append(packet)
                self.arrived.notify_all()

    def sniffed(self) -> list[Sniffed]:
        """Return the packets the sniffer saw since the last call."""
        with self.arrived:
            found = list(self.packets)
            self.packets.clear()
        return found

    def send(self, name: str, packets: list[bytes], example: int) -> list[Sniffed]:
        """Send an example's packets into hub00 through a link, then its sentinel.

        Return what the sniffer saw until the sentinel got to hub00: the tunnel
        keeps their order, and hub00 forwards a packet before it reads the next.
        """
        link = LINKS[name]
        self.sent[example] = link.ni
        number = example | SENTINEL
        self.injectors[name].run(
            "inject(*args)",
            [
                link.interface,
                [*(p.hex() or "00" for p in packets), ping(link, number).hex()],
            ],
        )

        def there() -> bool:
            return any(
                p.ni == link.ni and not p.outgoing and p.example() == number
                for p in self.packets
            )

        with self.arrived:
            carried = self.arrived.wait_for(there, timeout=SENTINEL_TIMEOUT)
        assert carried, f"packets through {name} don't get to hub00 any more"
        # What hub00 did with it in another network instance may come a moment
        # after: the sniffer reads them in turn.
        time.sleep(0.005)
        return self.sniffed()

    def leaks(self, packets: list[Sniffed]) -> list[str]:
        """Return how packets of the examples left their tenant."""
        found = []
        for sniffed in packets:
            ni = self.sent.get(sniffed.example())
            if ni and (leak := leaked(sniffed, ni, self.hub)):
                found.append(f"example {sniffed.example()}: {leak}")
        return found

    @staticmethod
    def dead() -> list[str]:
        """Return the links through which hub00's pings aren't answered: both ways."""
        pings = [
            conftest.command(
                f"ip netns exec {link.ni} ping -c 1 -W 1 {link.host}".split(),
            )
            for link in LINKS.values()
        ]
        dead = list(LINKS)
        for _ in range(CARRY_TRIES):
            answers = conftest.batch(conftest.HOST, pings)
            dead = [
                name
                for name, answer in zip(LINKS, answers, strict=True)
                if name in dead and answer.get("rc") != 0
            ]
            if not dead:
                break
        return dead

    def stop(self) -> None:
        """Stop the sniffer, the injectors and the spoofer."""
        self.sniffer.kill()
        for agent in (*self.injectors.values(), self.spoofer):
            agent.stop()
        conftest.sh(
            "cli00",
            "".join(
                f" ip address del {held}/{128 if ':' in held else 32} dev lo;"
                for _, held in DNS_PATHS.values()
            )
            + " true",
        )


@pytest.fixture(scope="module")
def lab(deployed: conftest.Deployed) -> Iterator[Lab]:
    """Run the sniffer and the spoofer; check that packets get through each link."""
    lab = Lab()
    to_core = ipaddress.ip_address(CORE[2]).packed
    try:
        conftest.sh(
            "cli00",
            "".join(
                f" ip address add {held}/{128 if ':' in held else 32} dev lo;"
                for _, held in DNS_PATHS.values()
            ),
        )
        seen: list[Sniffed] = []

        def through(name: str, link: Link) -> bool:
            # To any destination, not only hub00's own address.
            lab.injectors[name].run(
                "inject(*args)",
                [link.interface, [ping(link, 0, CORE[2]).hex()]],
            )
            seen.extend(lab.send(name, [], 0))
            return True

        for name, link in LINKS.items():
            conftest.wait_until(
                lambda name=name, link=link: through(name, link),
                timeout=30,
                message=f"a ping through {name} to reach hub00",
            )
            assert any(
                p.ni == link.ni and not p.outgoing and p.data[24:40] == to_core
                for p in seen
            ), f"a packet to the core through {name} doesn't get to hub00"
        assert not lab.dead(), f"hub00's pings through {lab.dead()} aren't answered"
        for path, (target, _) in DNS_PATHS.items():
            conftest.wait_until(
                lambda target=target: conftest.dns_ask(target, dns.QNAME, 1, "")[0],
                timeout=30,
                message=f"the spoofer's answer through {path}",
            )
            for qtype in dns.QTYPES.values():
                lab.sentinels[path, qtype] = dns.translated_sentinel(target, qtype)
        lab.errors = dns.Errors.now()
        # The checks' own packets aren't an example's.
        time.sleep(0.1)
        lab.sniffed()
        lab.sent.clear()
        yield lab
    finally:
        lab.stop()
        deployed.healthy()


@st.composite
def dns_answer(
    draw: st.DrawFn, path: str, qtype: int
) -> tuple[bool, bytes, list[Fragment]]:
    """Return a DNS answer as cli00 spoofs it: the query's id or not; it; fragments.

    Its destination address and port are zero: the spoofer puts the query's in.
    """
    keep_id, message = draw(dns_strategies.answer(qtype))
    src = ipaddress.ip_address(DNS_PATHS[path][1])
    dst = ipaddress.ip_address(0) if src.version == 4 else ipaddress.IPv6Address(0)  # noqa: PLR2004
    # Mostly sound IP and UDP headers, so that the answer gets to vpncmangle.
    honest = draw(st.integers(0, 3)) > 0
    if honest:
        data = struct.pack("!HHHH", 53, 0, 8 + len(message), 0) + message
        sum_ = checksum(pseudo(src, dst, 17, len(data)) + data)
        data = data[:6] + struct.pack("!H", sum_) + data[8:]
    else:
        data = draw(datagram(src, dst, 53, 0, message))
    # The first fragment holds the UDP header and the DNS id, which get patched.
    pieces = draw(ip(src.version, src, dst, 17, data, first=16, honest=honest))
    # Through the SSH tunnel: the version a tun device takes (see the test).
    return (
        keep_id,
        message,
        [
            p._replace(data=bytes([src.version << 4 | p.data[0] & 15]) + p.data[1:])
            for p in pieces
        ],
    )


@FUZZ
@given(data=st.data())
def test_tenant_traffic(lab: Lab, data: st.DataObject) -> None:
    """Nothing a tenant sends leaves its network instance; hub00 keeps running."""
    if data.draw(st.integers(0, 3), label="DNS answer") == 0:
        path = data.draw(st.sampled_from(sorted(DNS_PATHS)), label="path")
        qtype = dns.QTYPES[
            data.draw(st.sampled_from(sorted(dns.QTYPES)), label="qtype")
        ]
        keep_id, message, pieces = data.draw(dns_answer(path, qtype), label="answer")
        dns.ANSWERS.append(message.hex())
        spec = {
            "keep_id": keep_id,
            "fragments": [
                [p.data.hex(), p.dst_at, p.l4_at, p.ipsum_at] for p in pieces
            ],
        }
        lab.spoofer.run("SPEC = args", spec)
        dns.within_rate(lab.answered, sum(len(p.data) for p in pieces))
        received, sentinel, late = conftest.dns_observe(
            DNS_PATHS[path][0],
            dns.QNAME,
            qtype,
            lab.sentinels[path, qtype],
            grace=dns.GRACE,
        )
        event(f"DNS answer through {path}: {'answered' if received else 'dropped'}")
        dns.check_late(late, lab.prefixes)
        untranslated = dns_wire.untranslated(received, lab.prefixes)
        assert not untranslated, (
            f"untranslated tenant addresses reached mgt00: {untranslated}"
        )
        assert sentinel, "vpncmangle didn't translate the answer after it"
    else:
        link = data.draw(st.sampled_from(sorted(LINKS)), label="link")
        example = next(EXAMPLES)
        marker = MAGIC + example.to_bytes(4)
        drawn = data.draw(
            st.lists(packet(LINKS[link].ni, marker), min_size=1, max_size=6),
            label="packets",
        )
        for what, _ in drawn:
            event(f"{link}: {what.rsplit(',', 1)[0]}")
        packets = [p for _, pieces in drawn for p in pieces]
        if link == "SSH":
            # The server's kernel only writes IP packets into its tun device.
            # Another version stops the tunnel: hub00's tun device refuses it,
            # and ssh stops writing to it.
            packets = [p for p in packets if p and p[0] >> 4 in IP_VERSIONS]
        leaks = lab.leaks(lab.send(link, packets, example))
        assert not leaks, "\n".join(["left the tenant's network instance:", *leaks])

    dead = lab.dead()
    assert not dead, f"hub00's pings through {', '.join(dead)} aren't answered"
    lab.vitals.check()


def test_tenant_traffic_end(lab: Lab) -> None:
    """Nothing left late, vpncmangle translated what it could, all still answer."""
    lab.spoofer.run("SPEC = None")
    # E.g. hub00's errors about fragments that never became a packet.
    time.sleep(1)
    leaks = lab.leaks(lab.sniffed())
    assert not leaks, "\n".join(["left the tenant's network instance:", *leaks])
    try:
        for target, _ in DNS_PATHS.values():
            dns.check_late(conftest.dns_drain(target), lab.prefixes)
        assert lab.errors is not None
        lab.errors.check()
    except AssertionError:
        print(f"The run's answers: {dns.save_answers()}")
        raise
    conftest.check_answering()
