"""Mangle/doctor DNS responses."""

import contextlib
import logging
import struct
import sys
from ipaddress import IPv4Address, IPv6Address
from logging.handlers import SysLogHandler
from time import sleep

import scapy.all as sc
from netfilterqueue import NetfilterQueue, Packet

from . import config, helpers, nftables, observers, stats

logger = logging.getLogger("vpncmangle")


QUERY_A = 1
QUERY_AAAA = 28
# A response's sections (answer, authority, additional) and their record counts.
SECTIONS = (("an", "ancount"), ("ns", "nscount"), ("ar", "arcount"))


# IPv6 extension headers nftables looks past for the UDP header.
HOP_BY_HOP, ROUTING, FRAGMENT, AUTHENTICATION, DESTINATION = 0, 43, 44, 51, 60
EXTENSION_HEADERS = (HOP_BY_HOP, ROUTING, FRAGMENT, AUTHENTICATION, DESTINATION)
UDP = 17
IPV6_HEADER = 40
UDP_HEADER = 8
DNS_HEADER = 12
# The QR bit in the header's third byte: a response.
RESPONSE = 0x80


def _journal_handler() -> logging.Handler:
    """Return a handler to the journal (syslog), or stderr where it isn't running."""
    try:
        handler = SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_DAEMON)
    except OSError:
        return logging.StreamHandler()
    # The journal's SYSLOG_IDENTIFIER, which vpnctl reads.
    handler.ident = "vpncmangle: "
    handler.append_nul = False
    return handler


def setup_nftables(queue_number: int) -> None:
    """Queue DNS responses to vpncmangle, and drop the old ip6tables rule."""
    nftables.apply(queue_number)
    logger.info("Queueing DNS responses to netfilter queue %s.", queue_number)


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


def network_instance(source: IPv6Address) -> str | None:
    """Return the network instance a source address is translated for."""
    for local_network, name, _ in config.ACL_MATCH:
        if source in local_network:
            return name
    return None


def too_costly(packet: bytes, offset: int) -> str | None:
    """Return why a response isn't parsed: one thread handles every tenant's."""
    limits = config.LIMITS
    if len(packet) > limits.max_size:
        return stats.OVERSIZED
    # The answer, authority and additional counts, as the response claims.
    if sum(struct.unpack_from("!3H", packet, offset + 6)) > limits.max_records:
        return stats.TOO_MANY_RECORDS
    return None


def translate(
    record: sc.DNSRR,
    ni_config: config.VpncMangleConfig,
) -> sc.DNSRR | None:
    """Return a record as the client must see it, or None to leave it out.

    An A record becomes the AAAA record of its NAT64 address (also in answer to an
    A query, which is how clients reach IPv4-only hosts). An AAAA record is
    translated to its NPTv6 prefix, and left out if it isn't reachable through the
    network instance. Other records (e.g. CNAME) are kept as they are.
    """
    if record.type == QUERY_A:
        if not ni_config.dns64:
            logger.debug("Leaving out A record %s: no NAT64.", record.rdata)
            return None
        nat64_network, _ = ni_config.dns64[0]
        address = IPv6Address(
            int(nat64_network.network_address) + int(IPv4Address(record.rdata)),
        )
    elif record.type == QUERY_AAAA:
        remote = IPv6Address(record.rdata)
        for local_network, remote_network in ni_config.dns66:
            if remote in remote_network:
                address = IPv6Address(
                    int(local_network.network_address)
                    + int(remote)
                    - int(remote_network.network_address),
                )
                break
        else:
            logger.debug("Leaving out unreachable AAAA record %s.", remote)
            return None
    else:
        return record
    logger.debug(
        "DNS answer for %r translated from '%s' to '%s'.",
        record.rrname,
        record.rdata,
        address,
    )
    return sc.DNSRR(
        rrname=record.rrname,
        type="AAAA",
        rclass=record.rclass,
        ttl=record.ttl,
        rdata=str(address),
    )


def mangle_dns(pkt: Packet) -> None:
    """Translate a DNS response; drop it if that fails.

    An exception here would end the queue, and with it DNS for every tenant.
    """
    try:
        _mangle_dns(pkt)
    except Exception:
        logger.warning(
            "Dropping a DNS response that can't be translated.", exc_info=True
        )
        stats.dropped(stats.ERROR)
        # Fails if it already got a verdict.
        with contextlib.suppress(Exception):
            pkt.drop()


def _mangle_dns(pkt: Packet) -> None:  # noqa: C901, PLR0911, PLR0912, PLR0915 (one pass)
    """Translate the addresses in a DNS response to ones reachable from CORE."""
    payload = pkt.get_payload()
    # Before parsing, which costs most.
    if (offset := dns_offset(payload)) is None:
        logger.warning("Dropping a packet from port 53 that isn't DNS.")
        stats.dropped(stats.NOT_DNS)
        pkt.drop()
        return
    # A query (e.g. of a forwarder) passes; with records it's looked into.
    if not payload[offset + 2] & RESPONSE and not any(
        payload[offset + 6 : offset + 12]
    ):
        logger.debug("Packet is a query without records.")
        pkt.accept()
        return
    if reason := too_costly(payload, offset):
        logger.debug("Dropping a response: %s.", reason)
        stats.dropped(reason, network_instance(IPv6Address(payload[8:24])))
        pkt.drop()
        return
    pkt_sc = sc.IPv6(payload)

    # Unparsable: a client may still read addresses from it.
    if not pkt_sc.haslayer(sc.DNS):
        logger.warning("Dropping a packet from port 53 that isn't DNS: %s", pkt_sc)
        stats.dropped(stats.NOT_DNS)
        pkt.drop()
        return
    # Addresses in any section, whatever the return code: a client may use them.
    dns = pkt_sc[sc.DNS]
    has_addresses = any(
        record.type in (QUERY_A, QUERY_AAAA)
        for section, _ in SECTIONS
        for record in getattr(dns, section) or []
    )
    # Not a response (QR 0): it passes, but not with addresses, which a client
    # that doesn't look at QR could use untranslated.
    if dns.qr != 1:
        if has_addresses:
            logger.debug("Dropping a query with addresses from port 53.")
            stats.dropped(
                stats.QUERY_WITH_ADDRESSES,
                network_instance(IPv6Address(pkt_sc.src)),
            )
            pkt.drop()
            return
        logger.debug("Packet is a query without addresses.")
        pkt.accept()
        return
    if not has_addresses:
        logger.debug("Packet response contains no addresses.")
        pkt.accept()
        return

    # The source address of the response (basically the DNS resolver). This IP is
    # most likely translated by NAT64 or NPTv6
    ipv6_src_addr = IPv6Address(pkt_sc.src)

    # vpncmangle has no idea where the response comes from. It requires the mapping
    # configuration to know this.

    # Read once: a reload replaces it.
    acl_match = config.ACL_MATCH
    if not acl_match:
        logger.error("No configuration loaded.")
        stats.dropped(stats.NO_TRANSLATIONS)
        pkt.drop()
        return
    ni_config: config.VpncMangleConfig | None = None
    ni_id = ""
    for local_network, name, translations in acl_match:
        if ipv6_src_addr in local_network:
            ni_config, ni_id = translations, name
            break

    if ni_config is None:
        logger.error(
            "Source address '%s' matches no network instance's translations.",
            ipv6_src_addr,
        )
        stats.dropped(stats.UNKNOWN_SOURCE)
        pkt.drop()
        return

    # Without answers left the name still exists: NODATA (NOERROR, no answers).
    for section, count in SECTIONS:
        records = [
            translated
            for record in getattr(dns, section) or []
            if (translated := translate(record, ni_config)) is not None
        ]
        setattr(dns, section, records)
        setattr(dns, count, len(records))

    # Reset/calculate the correct values for lower layers.
    del pkt_sc[sc.IPv6].plen
    del pkt_sc[sc.UDP].len
    del pkt_sc[sc.UDP].chksum

    try:
        pkt.set_payload(bytes(pkt_sc))
        pkt.accept()
        stats.translated(ni_id)
        logger.debug("Packet sent.")
    except Exception:
        logger.warning("Error occurred mangling DNS.", exc_info=True)
        stats.dropped(stats.ERROR, ni_id)
        pkt.drop()


def main() -> None:
    """Set up netfilter and try to keep the mangle_dns function alive."""
    logger.setLevel(level=logging.INFO)
    logger.addHandler(_journal_handler())

    nfqueue = NetfilterQueue()
    retries = 10

    helpers.load_config()

    mangle_obs = observers.observe()
    mangle_obs.start()
    stats.start()

    while True:
        for queue_number in range(retries):
            try:
                nfqueue.bind(queue_number, mangle_dns)
                setup_nftables(queue_number)
                break
            except OSError:
                logger.debug(
                    "Attaching to netfilter queue %s failed, retrying.",
                    queue_number,
                )
            if queue_number >= retries - 1:
                logger.critical("Could not find an available netfilter queue.")
                sys.exit(1)
        try:
            logger.info("Starting mangle process.")
            nfqueue.run()
        except KeyboardInterrupt:
            logger.info("Exiting mangle process.")
            sys.exit(0)
        except Exception:
            logger.critical(
                "Mangle process ended prematurely. Restarting.",
                exc_info=True,
            )
        finally:
            # The table stays: without a listener its queue drops DNS responses
            # instead of passing them untranslated. setup_nftables replaces it.
            nfqueue.unbind()

        sleep(0.1)


if __name__ == "__main__":
    main()
