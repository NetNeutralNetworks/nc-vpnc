"""Translate the addresses in a DNS response: the packet in, a verdict out.

No netfilter queue, nftables or files here, so it can be tested on its own.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING

import dns.exception
import dns.flags
import dns.message
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.IN.HTTPS
import dns.rdtypes.IN.SVCB
import dns.rrset
from dns.rdtypes.svcbbase import ParamKey

from .stats import (
    NO_TRANSLATIONS,
    NOT_DNS,
    OVERSIZED,
    QUERY_WITH_ADDRESSES,
    REBUILD_INVALID,
    TOO_MANY_RECORDS,
    UNKNOWN_SOURCE,
)

if TYPE_CHECKING:
    from ipaddress import IPv6Network

    from .config import Limits, VpncMangleConfig

    AclMatch = list[tuple[IPv6Network, str, VpncMangleConfig]]

logger = logging.getLogger("vpncmangle")

# dnspython looks a type's parser up per class, and once a class-ANY A record
# was read, it reads class-IN ones with the generic parser. Look them up now.
for _rdtype in dns.rdatatype.RdataType:
    dns.rdata.get_rdata_class(dns.rdataclass.IN, _rdtype)

IN = dns.rdataclass.IN
A, AAAA = dns.rdatatype.A, dns.rdatatype.AAAA
SVCB, HTTPS, RRSIG = dns.rdatatype.SVCB, dns.rdatatype.HTTPS, dns.rdatatype.RRSIG
# Records a client may take addresses from, and their class-IN parsers.
ADDRESS_TYPES = {
    A: dns.rdtypes.IN.A.A,
    AAAA: dns.rdtypes.IN.AAAA.AAAA,
    SVCB: dns.rdtypes.IN.SVCB.SVCB,
    HTTPS: dns.rdtypes.IN.HTTPS.HTTPS,
}
HINTS = (ParamKey.IPV4HINT, ParamKey.IPV6HINT)

# IPv6 extension headers nftables looks past for the UDP header.
HOP_BY_HOP, ROUTING, FRAGMENT, AUTHENTICATION, DESTINATION = 0, 43, 44, 51, 60
EXTENSION_HEADERS = (HOP_BY_HOP, ROUTING, FRAGMENT, AUTHENTICATION, DESTINATION)
UDP = 17
IPV6_HEADER = 40
UDP_HEADER = 8
DNS_HEADER = 12
# A name's compression pointer: its first byte's top two bits.
POINTER = 0xC0
MAX_NAME = 255
# Pointers a name may follow; more is a loop or an attack.
MAX_POINTERS = 20
# What parsing a malformed message raises.
PARSE_ERRORS = (dns.exception.DNSException, ValueError, struct.error, IndexError)

ACCEPT, DROP = "accept", "drop"


@dataclass(frozen=True)
class Result:
    """What to do with a packet. payload: the packet to send, None: as it came."""

    action: str
    payload: bytes | None = None
    reason: str | None = None
    ni: str | None = None


class _MisparsedError(Exception):
    """A class-IN address record read with another type's parser."""


def dns_offset(packet: bytes) -> int | None:
    """Return where the DNS message of an IPv6 UDP packet starts; None: it has none."""
    if len(packet) < IPV6_HEADER:
        return None
    header, offset = packet[6], IPV6_HEADER
    while header in EXTENSION_HEADERS:
        if len(packet) < offset + 8:
            return None
        if header == FRAGMENT:
            length = 8
        elif header == AUTHENTICATION:
            length = (packet[offset + 1] + 2) * 4
        else:
            length = (packet[offset + 1] + 1) * 8
        header, offset = packet[offset], offset + length
    if header != UDP or len(packet) < offset + UDP_HEADER + DNS_HEADER:
        return None
    return offset + UDP_HEADER


def _routed(packet: bytes) -> bool:
    """Return whether a packet has a routing header: then another address is its end."""
    header, offset = packet[6], IPV6_HEADER
    while header in EXTENSION_HEADERS:
        if header == ROUTING:
            return True
        if header == FRAGMENT:
            length = 8
        elif header == AUTHENTICATION:
            length = (packet[offset + 1] + 2) * 4
        else:
            length = (packet[offset + 1] + 1) * 8
        header, offset = packet[offset], offset + length
    return False


def too_costly(packet: bytes, offset: int, limits: Limits) -> str | None:
    """Return why a response isn't parsed: one thread handles every tenant's."""
    if len(packet) > limits.max_size:
        return OVERSIZED
    # The answer, authority and additional counts, as the response claims.
    if sum(struct.unpack_from("!3H", packet, offset + 6)) > limits.max_records:
        return TOO_MANY_RECORDS
    return None


def _name_end(packet: bytes, pos: int, start: int) -> int | None:
    """Return where a name ends; None if it breaks RFC 1035 or the packet ends.

    Pointers go back, not into the header, and the name they make is valid too:
    a message passed as it came must be read the same by every client.
    """
    end = None
    length = pointers = 0
    while pos < len(packet):
        byte = packet[pos]
        if byte == 0:
            return pos + 1 if end is None else end
        if byte & POINTER == POINTER:
            if pos + 2 > len(packet):
                return None
            target = start + (struct.unpack_from("!H", packet, pos)[0] & 0x3FFF)
            pointers += 1
            # Back, so no loops.
            if target < start + DNS_HEADER or target >= pos or pointers > MAX_POINTERS:
                return None
            if end is None:
                end = pos + 2
            pos = target
            continue
        # 0x40 and 0x80: reserved label types, read as lengths by some clients.
        if byte & POINTER:
            return None
        pos += 1 + byte
        length += 1 + byte
        if length + 1 > MAX_NAME:
            return None
    return None


def well_formed(packet: bytes, offset: int) -> bool:
    """Return whether a DNS message's question and records fill it as RFC 1035 has.

    Otherwise clients may read other records from it than vpncmangle does.
    """
    questions, *records = struct.unpack_from("!4H", packet, offset + 4)
    pos = offset + DNS_HEADER
    for _ in range(questions):
        end = _name_end(packet, pos, offset)
        if end is None or end + 4 > len(packet):
            return False
        pos = end + 4
    for _ in range(sum(records)):
        end = _name_end(packet, pos, offset)
        if end is None or end + 10 > len(packet):
            return False
        pos = end + 10 + struct.unpack_from("!H", packet, end + 8)[0]
    return pos == len(packet)


def _network_instance(
    source: IPv6Address,
    acl_match: AclMatch,
) -> tuple[str | None, VpncMangleConfig | None]:
    """Return the network instance a source address is translated for."""
    for local_network, name, translations in acl_match:
        if source in local_network:
            return name, translations
    return None, None


def _translated(  # noqa: C901, PLR0911 (per type)
    rrset: dns.rrset.RRset,
    translations: VpncMangleConfig,
) -> dns.rrset.RRset | None:
    """Return a record as the client must see it, or None to leave it out."""
    rdtype, rdata = rrset.rdtype, rrset[0]
    if rdtype in ADDRESS_TYPES:
        if rrset.rdclass != IN:
            return None
        if not isinstance(rdata, ADDRESS_TYPES[rdtype]):
            raise _MisparsedError
    if rdtype == A:
        if not translations.dns64:
            return None
        nat64_network, _ = translations.dns64[0]
        address = IPv6Address(
            int(nat64_network.network_address) + int(IPv4Address(rdata.address)),
        )
        return dns.rrset.from_text(rrset.name, rrset.ttl, IN, AAAA, str(address))
    if rdtype == AAAA:
        remote = IPv6Address(rdata.address)
        for local_network, remote_network in translations.dns66:
            if remote in remote_network:
                address = IPv6Address(
                    int(local_network.network_address)
                    + int(remote)
                    - int(remote_network.network_address),
                )
                return dns.rrset.from_text(
                    rrset.name, rrset.ttl, IN, AAAA, str(address)
                )
        return None
    if rdtype in (SVCB, HTTPS):
        if not any(key in rdata.params for key in HINTS):
            return rrset
        mandatory = rdata.params.get(ParamKey.MANDATORY)
        if mandatory and any(key in mandatory.keys for key in HINTS):
            return None
        params = {k: v for k, v in rdata.params.items() if k not in HINTS}
        rebuilt = type(rdata)(IN, rdtype, rdata.priority, rdata.target, params)
        return dns.rrset.from_rdata(rrset.name, rrset.ttl, rebuilt)
    if rdtype == RRSIG and rdata.type_covered in ADDRESS_TYPES:
        return None
    return rrset


def _packet(packet: bytes, offset: int, message: bytes) -> bytes:
    """Return the packet with another DNS message, and its lengths and checksum."""
    udp = offset - UDP_HEADER
    segment = bytearray(packet[udp:offset] + message)
    struct.pack_into("!H", segment, 4, len(segment))
    struct.pack_into("!H", segment, 6, 0)
    head = bytearray(packet[:udp])
    payload_length = struct.unpack_from("!H", head, 4)[0]
    struct.pack_into(
        "!H", head, 4, payload_length + len(message) - (len(packet) - offset)
    )
    pseudo = head[8:40] + struct.pack("!IxxxB", len(segment), UDP)
    data = pseudo + segment + b"\0" * (len(segment) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    # 0: no checksum, which IPv6 doesn't allow.
    struct.pack_into("!H", segment, 6, (~total & 0xFFFF) or 0xFFFF)
    return bytes(head + segment)


def process(  # noqa: C901, PLR0911, PLR0912 (one pass, in order)
    packet: bytes,
    acl_match: AclMatch,
    limits: Limits,
) -> Result:
    """Return what to do with a DNS packet leaving CORE.

    A records become the AAAA records of their NAT64 addresses, AAAA records get
    their NPTv6 prefix or are left out, and SVCB/HTTPS address hints go.
    """
    if (offset := dns_offset(packet)) is None:
        logger.warning("Dropping a packet from port 53 that isn't DNS.")
        return Result(DROP, reason=NOT_DNS)
    ni, translations = _network_instance(IPv6Address(packet[8:24]), acl_match)
    if reason := too_costly(packet, offset, limits):
        logger.debug("Dropping a response: %s.", reason)
        return Result(DROP, reason=reason, ni=ni)
    # Lengths that agree, so all read the same message.
    lengths = (
        struct.unpack_from("!H", packet, 4)[0] + IPV6_HEADER,
        struct.unpack_from("!H", packet, offset - UDP_HEADER + 4)[0]
        + offset
        - UDP_HEADER,
    )
    if lengths != (len(packet), len(packet)) or not well_formed(packet, offset):
        logger.debug("Dropping a DNS packet that doesn't follow RFC 1035.")
        return Result(DROP, reason=NOT_DNS, ni=ni)
    try:
        message = dns.message.from_wire(packet[offset:], one_rr_per_rrset=True)
    except PARSE_ERRORS as error:
        logger.debug("Dropping a DNS packet that can't be read: %s", error)
        return Result(DROP, reason=NOT_DNS, ni=ni)
    # The question (or an update's zone) holds no addresses.
    sections = message.sections[1:]
    # Of any class: a client may ignore it.
    addressed = any(r.rdtype in ADDRESS_TYPES for s in sections for r in s)
    # A client that doesn't look at QR may use a query's addresses.
    if not message.flags & dns.flags.QR:
        if addressed:
            logger.debug("Dropping a query with addresses from port 53.")
            return Result(DROP, reason=QUERY_WITH_ADDRESSES, ni=ni)
        return Result(ACCEPT, ni=ni)
    if not acl_match:
        logger.error("No configuration loaded.")
        return Result(DROP, reason=NO_TRANSLATIONS)
    if translations is None:
        logger.error(
            "Source address '%s' matches no network instance's translations.",
            IPv6Address(packet[8:24]),
        )
        return Result(DROP, reason=UNKNOWN_SOURCE)
    if not addressed:
        return Result(ACCEPT, ni=ni)
    # The checksum would be of the wrong destination.
    if _routed(packet):
        return Result(DROP, reason=NOT_DNS, ni=ni)
    try:
        for number, section in enumerate(sections, 1):
            message.sections[number] = [
                translated
                for rrset in section
                if (translated := _translated(rrset, translations)) is not None
            ]
    except _MisparsedError:
        logger.warning("Dropping an answer with an address record read wrongly.")
        return Result(DROP, reason=NOT_DNS, ni=ni)
    # Without the signatures of what changed, it's no longer validated.
    message.flags &= ~dns.flags.AD
    try:
        wire = message.to_wire(max_size=65535 - offset)
        dns.message.from_wire(wire, one_rr_per_rrset=True)
    except Exception as error:  # noqa: BLE001 (any is a failed rebuild)
        logger.warning("Dropping an answer that can't be rebuilt: %s", error)
        return Result(DROP, reason=REBUILD_INVALID, ni=ni)
    return Result(ACCEPT, _packet(packet, offset, wire), ni=ni)
