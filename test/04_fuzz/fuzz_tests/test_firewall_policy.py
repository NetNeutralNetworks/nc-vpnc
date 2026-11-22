"""hub00's firewall against the policy (fuzz_common/policy_oracle.py).

Its rulesets' structure, and one packet per row of the policy, sent through the
lab's tenants (C0001-00, C0001-01) with the tenant traffic test's injectors and
sniffer. A forbidden packet must come in, be counted or answered with an ICMP
error, and not leave. The management row shows that the checks can't pass on a
firewall that drops everything.
"""

from __future__ import annotations

import ipaddress
import struct
import threading
import time
from typing import TYPE_CHECKING

import pytest
from fuzz_common import packet_observer, policy_oracle

from . import conftest
from . import test_dns_answers as dns
from . import test_ike_packets as ike
from .test_tenant_traffic import (
    EXAMPLES,
    LINKS,
    MAGIC,
    Lab,
    Link,
    Sent,
    Sniffed,
    check_control,
    checksum,
    control,
    describe,
    lab,  # noqa: F401 (the fixture)
    pseudo,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# hub00's ICMP errors.
ICMP_ERRORS = {4: {3, 11, 12}, 6: {1, 2, 3, 4}}
STRANGERS = {4: "192.0.2.212", 6: "2001:db8::212"}
PREFIX_LENGTHS = {4: 24, 6: 64}
# mgt01's own address: a configured peer of hub00.
PEER = "2001:db8::4"
UDP, TCP, ICMP6 = 17, 6, 58


def ip_packet(src: str, dst: str, proto: int, data: bytes) -> bytes:
    """Return an IPv4 or IPv6 packet of a transport segment."""
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if s.version == 6:  # noqa: PLR2004
        return (
            struct.pack(
                "!IHBB16s16s", 6 << 28, len(data), proto, 64, s.packed, d.packed
            )
            + data
        )
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(data), 1, 0, 64, proto, 0, s.packed, d.packed
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + data


def summed(src: str, dst: str, proto: int, data: bytes, at: int) -> bytes:
    """Return a segment with its checksum (at) over the pseudo header."""
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    value = checksum(pseudo(s, d, proto, len(data)) + data) or 0xFFFF
    return data[:at] + struct.pack("!H", value) + data[at + 2 :]


def udp(src: str, dst: str, dport: int, marker: bytes) -> bytes:
    """Return a UDP packet with the marker."""
    data = struct.pack("!HHHH", 40002, dport, 8 + len(marker), 0) + marker
    return ip_packet(src, dst, UDP, summed(src, dst, UDP, data, 6))


def tcp(src: str, dst: str, dport: int, marker: bytes) -> bytes:
    """Return a TCP SYN with the marker as its data."""
    data = struct.pack("!HHIIBBHHH", 40003, dport, 1, 0, 5 << 4, 0x02, 65535, 0, 0)
    return ip_packet(src, dst, TCP, summed(src, dst, TCP, data + marker, 16))


def echo(src: str, dst: str, marker: bytes) -> bytes:
    """Return an ICMPv6 echo request with the marker."""
    data = struct.pack("!BBHHH", 128, 0, 0, 1, 1) + marker
    return ip_packet(src, dst, ICMP6, summed(src, dst, ICMP6, data, 2))


def send(lab: Lab, link: str, build: list) -> tuple[int, Sent]:  # noqa: F811
    """Send packets (built from the marker) through a link; check the control."""
    example = next(EXAMPLES)
    marker = MAGIC + example.to_bytes(4)
    sent = lab.send(link, [[make(marker)] for make in build], example)
    leaks = lab.observe(sent.sniffed)
    assert not leaks, "\n".join(["left the tenant's network instance:", *leaks])
    check_control(link, example, sent)
    lab.observer.finish(example)
    return example, sent


def mine(sent: Sent, example: int) -> list[Sniffed]:
    """Return the sniffed packets of an example's packets, not its control's."""
    return [p for p in sent.sniffed if p.example() == example]


def check_stopped(lab: Lab, link: str, build: list) -> None:  # noqa: F811
    """Send packets that hub00 must stop: they came in, and were counted or refused."""
    example, sent = send(lab, link, build)
    for number in range(len(build)):
        seen = lab.observer.seen[example, number]
        assert packet_observer.INGRESS_SEEN in seen, f"packet {number} not seen: {seen}"
    refused = sum(
        1
        for p in mine(sent, example)
        if p.outgoing
        and describe(p.data)[3] in ICMP_ERRORS.get(describe(p.data)[0], ())
    )
    # The control raises forward, the sentinel input.
    counted = sent.forwarded - 1 + sent.received - 1
    assert counted + refused >= len(build), (
        f"{len(build)} packets, {counted} counted, {refused} refused"
    )


def test_structure(lab: Lab) -> None:  # noqa: ARG001, F811
    """The tenants' and EXTERNAL's rulesets are as the policy has them."""
    state = conftest.snapshot()
    translations = dns.translations()
    problems = policy_oracle.tenant(
        state["C0001-00"]["nftables"], "C0001-00", translations["dns64"][0][0]
    )
    problems += policy_oracle.tenant(state["C0001-01"]["nftables"], "C0001-01")
    problems += policy_oracle.external(
        state["EXTERNAL"]["nftables"], {PEER}, set(), set(STRANGERS.values())
    )
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("link", sorted(LINKS))
def test_tenant_core(lab: Lab, link: str) -> None:  # noqa: F811
    """A tenant's new traffic to a CORE address never leaves its network instance."""
    tenant = LINKS[link].tenant
    check_stopped(
        lab,
        link,
        [
            lambda m: udp(tenant, "fd00::3", 53, m),
            lambda m: tcp(tenant, "fd00:1:2::1", 22, m),
            lambda m: echo(tenant, "fd01:3::1", m),
        ],
    )


def test_tenant_tenant(lab: Lab) -> None:  # noqa: F811
    """A tenant reaches no other tenant's routes, NAT64 or NPTv6 prefix."""
    for link, targets in (
        ("IPSEC", ("2001:db8:c58::1", "fdcc:0:c:1:1::a00:1", "fd6c:1:1::1")),
        ("WIREGUARD", ("2001:db8:c57::1", "fdcc:0:c:1::a00:1", "fd6c:1::1")),
    ):
        tenant = LINKS[link].tenant
        check_stopped(
            lab, link, [lambda m, t=t, s=tenant: udp(s, t, 9, m) for t in targets]
        )


def test_tenant_own(lab: Lab) -> None:  # noqa: F811
    """A tenant reaches none of its own other connections through hub00."""
    check_stopped(
        lab, "IPSEC", [lambda m: tcp(LINKS["IPSEC"].tenant, "2001:db8:c57::1", 22, m)]
    )
    check_stopped(lab, "SSH", [lambda m: udp("172.16.31.1", "172.16.30.1", 9, m)])


@pytest.mark.parametrize("link", sorted(LINKS))
def test_tenant_hub_echo(lab: Lab, link: str) -> None:  # noqa: F811
    """hub00 answers a tenant's echo request to its own address."""
    to = LINKS[link]
    example, sent = send(lab, link, [lambda m: echo(to.tenant, to.hub, m)])
    replies = [
        p
        for p in mine(sent, example)
        if p.outgoing and p.ni == to.ni and describe(p.data)[2:] == (ICMP6, 129)
    ]
    assert replies, f"no echo reply through {link}"


@pytest.mark.parametrize("link", sorted(LINKS))
def test_tenant_hub_ports(lab: Lab, link: str) -> None:  # noqa: F811
    """A tenant's TCP and UDP to hub00's own address get no answer but an ICMP error."""
    to: Link = LINKS[link]
    build = [
        *(lambda m, p=p: udp(to.tenant, to.hub, p, m) for p in (9, 53, 179, 500)),
        *(lambda m, p=p: tcp(to.tenant, to.hub, p, m) for p in (22, 179, 80)),
    ]
    example, sent = send(lab, link, build)
    answers = [
        describe(p.data)
        for p in mine(sent, example)
        if p.outgoing
        and describe(p.data)[3] not in ICMP_ERRORS.get(describe(p.data)[0], ())
    ]
    assert not answers, f"hub00 answered: {answers}"


def test_management() -> None:
    """Management reaches a tenant's host through NAT64 and NPTv6: ICMP, TCP, UDP."""
    targets = ("fdcc:0:c:1::172.16.31.1", "fd6c:1:0:31::1")
    code = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET6); s.settimeout(2); s.connect((args, 22))\n"
        "result = len(s.recv(4))"
    )
    client = conftest.Agent("mgt00")
    try:
        for target in targets:
            conftest.sh("mgt00", f"ping -c 1 -W 2 {target}")
            assert client.run(code, target), f"no TCP answer from {target}"
    finally:
        client.stop()
    answers, _ = conftest.dns_ask(conftest.DNS_SERVER, conftest.DNS_NAME, 1)
    assert answers, "no DNS answer through NAT64"


@pytest.fixture(scope="module")
def sender(deployed: conftest.Deployed) -> Iterator[conftest.Agent]:  # noqa: ARG001
    """Send IKE from mgt01's EXTERNAL: its own address (a peer) and strangers'."""
    for family, address in STRANGERS.items():
        ike.in_sender(
            f"ip address add {address}/{PREFIX_LENGTHS[family]} dev eth1 nodad"
        )
    agent = conftest.Agent(ike.SENDER, netns="EXTERNAL", setup=ike.SENDER_CODE)
    try:
        yield agent
    finally:
        agent.stop()
        for family, address in STRANGERS.items():
            ike.in_sender(
                f"ip address del {address}/{PREFIX_LENGTHS[family]} dev eth1; true"
            )


def test_peer(sender: conftest.Agent) -> None:
    """A configured peer's IKE reaches charon."""
    answered = sender.run(
        "result = send(*args)", [PEER, ike.HUB[6], 500, [], [], ike.sentinel().hex()]
    )[2]
    assert answered, f"charon didn't answer {PEER}"


def test_stranger(sender: conftest.Agent) -> None:
    """IKE from an address of no peer gets no answer."""
    for family, address in STRANGERS.items():
        for port in (500, 4500):
            answered = sender.run(
                "result = send(*args)",
                [address, ike.HUB[family], port, [], [], ike.sentinel().hex()],
            )[2]
            assert not answered, f"charon answered {address} on port {port}"


class Watch:
    """Sends the first row's packet through C0001-00 every 50 ms; none may leave."""

    INTERVAL = 0.05

    def __init__(self) -> None:
        """Start the sniffer, and the packets."""
        self.lab = Lab()
        self.leaks: list[str] = []
        self.sent = 0
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self) -> None:
        """Send a packet to CORE, look at what was seen, until stopped."""
        link = LINKS["IPSEC"]
        # One at once: a sequence may end at once.
        first = True
        while first or not self.stopping.wait(self.INTERVAL):
            first = False
            example = next(EXAMPLES)
            packet = control(link, example)
            self.lab.sent[example] = link.ni
            self.lab.observer.record(example, [[packet]])
            try:
                self.lab.injectors["IPSEC"].run(
                    "result = inject(*args)", [link.interface, [packet.hex()]]
                )
            except (conftest.AgentError, conftest.CommandError):
                continue
            self.sent += 1
            self.leaks += self.lab.observe(self.lab.sniffed())

    def finish(self) -> list[str]:
        """Stop; return how packets left C0001-00."""
        self.stopping.set()
        self.thread.join()
        time.sleep(0.2)
        self.leaks += self.lab.observe(self.lab.sniffed())
        self.lab.stop()
        return self.leaks
