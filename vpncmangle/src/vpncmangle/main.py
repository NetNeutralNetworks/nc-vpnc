"""Mangle/doctor DNS responses."""

import contextlib
import logging
import sys
from ipaddress import IPv4Address, IPv6Address
from logging.handlers import RotatingFileHandler
from time import sleep

import scapy.all as sc
from netfilterqueue import NetfilterQueue, Packet

from . import config, helpers, nftables, observers

logger = logging.getLogger("vpncmangle")


QUERY_A = 1
QUERY_AAAA = 28


TABLE = "ip6 vpncmangle"


def setup_nftables(queue_number: int) -> None:
    """Queue DNS responses to vpncmangle, and drop the old ip6tables rule."""
    # TODO@draggeta: fix DNS over TCP
    nftables.run(
        f"""
table {TABLE}
delete table {TABLE}
destroy table ip6 mangle
table {TABLE} {{
    chain postrouting {{
        type filter hook postrouting priority mangle; policy accept;
        udp sport 53 queue num {queue_number}
    }}
}}
""",
    )
    logger.info("Queueing DNS responses to netfilter queue %s.", queue_number)


def clean_nftables() -> None:
    """Remove vpncmangle's table."""
    nftables.run(f"destroy table {TABLE}\n")
    logger.info("Removed table %s.", TABLE)


def translate(
    record: sc.DNSRR,
    ni_config: config.VpncMangleConfig,
) -> sc.DNSRR | None:
    """Return an answer record as the client must see it, or None to leave it out.

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
        logger.warning("Dropping a DNS response that can't be translated.", exc_info=True)
        # Fails if it already got a verdict.
        with contextlib.suppress(Exception):
            pkt.drop()


def _mangle_dns(pkt: Packet) -> None:
    """Translate the addresses in a DNS response to ones reachable from CORE."""
    pkt_sc = sc.IPv6(pkt.get_payload())

    # If not DNS record.
    if not pkt_sc.haslayer(sc.DNS):
        logger.warning("Captured packet without DNS response.")
        logger.warning(pkt_sc)
        pkt.accept()
        return
    # If not a response (QR field, query is 0, response 1).
    if pkt_sc[sc.DNS].qr != 1:
        logger.debug("Packet is not of type response.")
        pkt.accept()
        return
    # If return code is not ok.
    if pkt_sc[sc.DNS].rcode != 0:
        logger.debug("Packet response indicates error.\n%s", pkt_sc[sc.DNS])
        pkt.accept()
        return
    # If no answers in DNS.
    if not pkt_sc[sc.DNS].an:
        logger.debug("Packet response contains no answers.")
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
        pkt.drop()
        return
    ni_config: config.VpncMangleConfig | None = None
    for local_network, _, translations in acl_match:
        if ipv6_src_addr in local_network:
            ni_config = translations
            break

    if ni_config is None:
        logger.error(
            "IPv6 source address '%s' doesn't seem to match any configured address/network instance",
            ipv6_src_addr,
        )
        pkt.drop()
        return

    answers = [
        translated
        for record in pkt_sc[sc.DNS].an
        if (translated := translate(record, ni_config)) is not None
    ]

    # Without answers left the name still exists: NODATA (NOERROR, no answers).
    pkt_sc[sc.DNS].an = answers
    pkt_sc[sc.DNS].ancount = len(answers)

    # Reset/calculate the correct values for lower layers.
    del pkt_sc[sc.IPv6].plen
    del pkt_sc[sc.UDP].len
    del pkt_sc[sc.UDP].chksum

    try:
        pkt.set_payload(bytes(pkt_sc))
        pkt.accept()
        logger.debug("Packet sent.")
    except Exception:
        logger.warning("Error occurred mangling DNS.", exc_info=True)
        pkt.drop()


def main() -> None:
    """Set up netfilter and try to keep the mangle_dns function alive."""
    # LOGGER
    # Configure logging
    logger.setLevel(level=logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s(File:%(name)s,Line:%(lineno)d, %(funcName)s) - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %H:%M:%S %p",
    )
    rothandler = RotatingFileHandler(
        "/var/log/ncubed/vpnc/vpncmangle.log",
        maxBytes=100000,
        backupCount=5,
    )
    rothandler.setFormatter(formatter)
    logger.addHandler(rothandler)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    nfqueue = NetfilterQueue()
    retries = 10

    helpers.load_config()

    mangle_obs = observers.observe()
    mangle_obs.start()

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
            clean_nftables()
            nfqueue.unbind()

        sleep(0.1)


if __name__ == "__main__":
    main()
