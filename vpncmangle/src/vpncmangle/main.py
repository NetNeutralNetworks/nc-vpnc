#!/usr/bin/env python3

import logging
import subprocess
import sys
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from logging.handlers import RotatingFileHandler
from time import sleep

import scapy.all as sc
from netfilterqueue import NetfilterQueue, Packet

logger = logging.getLogger("vpncmangle")


def setup_ip6tables():
    """
    Configure ip6tables to capture DNS responses.
    """

    sp = subprocess.run(
        """
        # Configure DNS64 mangle
        ip6tables -t mangle -F
        ip6tables -t mangle -A POSTROUTING -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1
        # ip6tables -t mangle -A POSTROUTING -p tcp -m tcp --sport 53 -j NFQUEUE --queue-num 1
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )
    logger.info(sp.args)
    logger.info(sp.stdout.decode())


def clean_ip6tables():
    """
    Remove ip6tables rules.
    """

    sp = subprocess.run(
        """
        # Configure DNS64 mangle
        ip6tables -t mangle -F
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )
    logger.info(sp.args)
    logger.info(sp.stdout.decode())


def mangle_dns(pkt: Packet):
    """
    Mangle DNS responses of the 'A' type.
    """
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
        logger.debug("Packet response indicates error.")
        pkt.accept()
        return
    # If no answers in DNS.
    if not pkt_sc[sc.DNS].an:
        logger.debug("Packet response contains no answers.")
        pkt.accept()
        return

    # IPv6 address to perform DNS64 mangling with.
    ipv6_net = IPv6Network(pkt_sc.src).supernet(new_prefix=96)[0]

    # Temporary list to store all desired DNS responses.
    temp_list = []
    temp_v4_list = []
    rrname = pkt_sc[sc.DNS].an.rrname
    for i in pkt_sc[sc.DNS].an.iterpayloads():
        # # If AAAA record response, don't include it.
        # if i.type == 28:
        #     logger.debug("DNS response answer is 'AAAA'. Ignoring.")
        #     continue
        # # If CNAME record, get all addresses
        # if i.type == 5:
        #     logger.debug("DNS response answer is 'CNAME'. Ignoring.")
        #     continue
        # If not A record response, then include unedited
        if i.type != 1:
            logger.debug("DNS response answer is not 'A'. Ignoring.")
            # temp_list.append(i)
            continue

        # # Include an invalid IPv4 address just to make sure that Windows caches it correctly.
        # # This seems to break in Linux if preference isn't set.
        # if not temp_v4_list:
        #     temp_v4_dict = {
        #         "rrname": rrname,
        #         "type": i.type,
        #         "rclass": i.rclass,
        #         "ttl": i.ttl,
        #         "rdata": "0.0.0.254",
        #     }
        #     temp_v4_list.append(temp_v4_dict)

        # Calculate address.
        ipv4_addr = IPv4Address(i.rdata)
        ipv6_addr = IPv6Address(int(ipv6_net) + int(ipv4_addr))
        logger.debug(
            "DNS response answer for '%s' translated from '%s' to '%s'.",
            i.rrname.decode(),
            ipv4_addr,
            ipv6_addr,
        )
        # Change the response type and answer.
        temp_dict = {
            "rrname": rrname,
            "type": "AAAA",
            "rclass": i.rclass,
            "ttl": i.ttl,
            "rdata": str(ipv6_addr),
        }

        # Append the result to the list.
        temp_list.append(temp_dict)

    temp_list.extend(temp_v4_list)
    dns_mangle = sc.DNSRR()
    for i, val in enumerate(temp_list):
        # pdb.set_trace()
        if i > 0:
            dns_mangle = dns_mangle / sc.DNSRR()
        dns_mangle[i].rrname = val["rrname"]
        dns_mangle[i].type = val["type"]
        dns_mangle[i].rclass = val["rclass"]
        dns_mangle[i].ttl = val["ttl"]
        dns_mangle[i].rdata = val["rdata"]

    # If there are no valid responses (can happen if only AAAA records are returned and
    # discarded), return NXDOMAIN.
    if len(temp_list) == 0:
        pkt_sc[sc.DNS].ancount = 0
        pkt_sc[sc.DNS].an = None
        pkt_sc[sc.DNS].rcode = 3
    else:
        # Set the list as the answers value and edit the count.
        # pdb.set_trace()
        pkt_sc[sc.DNS].an = dns_mangle
        pkt_sc[sc.DNS].ancount = len(temp_list)

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


def main():
    """
    Main function. Binds to netfilter.
    """

    # LOGGER
    # Configure logging
    logger.setLevel(level=logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s(File:%(name)s,Line:%(lineno)d, %(funcName)s) - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %H:%M:%S %p",
    )
    rothandler = RotatingFileHandler(
        "/var/log/ncubed/vpnc/vpncmangle.log", maxBytes=100000, backupCount=5
    )
    rothandler.setFormatter(formatter)
    logger.addHandler(rothandler)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    setup_ip6tables()

    nfqueue = NetfilterQueue()
    while True:
        nfqueue.bind(1, mangle_dns)
        try:
            logger.info("Starting mangle process.")
            nfqueue.run()
        except KeyboardInterrupt:
            logger.info("Exiting mangle process.")
            sys.exit(0)
        except Exception:
            logger.critical(
                "Mangle process ended prematurely. Restarting.", exc_info=True
            )
        finally:
            clean_ip6tables()
            nfqueue.unbind()

        sleep(0.1)


if __name__ == "__main__":
    main()
