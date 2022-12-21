#!/usr/bin/env python3

# import pdb
import logging
from ipaddress import IPv4Address, IPv6Address, IPv6Network

import scapy.all as sc
from netfilterqueue import NetfilterQueue, Packet

logger = logging.getLogger('vpnc')

def mangle_dns(pkt: Packet):
    pkt_sc = sc.IPv6(pkt.get_payload())

    # If not DNS record.
    if not pkt_sc.haslayer(sc.DNSRR):
        logger.warning("Captured packet without DNS response.")
        print("Captured packet without DNS response.")
        pkt.accept()
        return
    # If not a response (QR field, query is 0, response 1).
    if pkt_sc[sc.DNS].qr != 1:
        logger.warning("Packet is not of type response.")
        print("Packet is not of type response.")
        pkt.accept()
        return
    # If return code is not ok.
    if pkt_sc[sc.DNS].rcode != 0:
        logger.warning("Packet response indicates error.")
        print("Packet response indicates error.")
        pkt.accept()
        return
    # If no answers in DNS.
    if not pkt_sc[sc.DNS].an:
        logger.warning("Packet response contains no answers.")
        print("Packet response contains no answers.")
        pkt.accept()
        return

    # IPv6 address to perform DNS64 mangling with.
    ipv6_net = IPv6Network(pkt_sc.src).supernet(new_prefix=96)[0]

    # Temporary list to store all desired DNS responses.
    temp_list = []
    temp_v4_list = []
    for i in pkt_sc[sc.DNS].an.iterpayloads():
        # If AAAA record response, don't include it.
        if i.type == 28:
            logger.debug("DNS response answer is 'AAAA'. Ignoring.")
            print("DNS response answer is 'AAAA'. Ignoring.")
            continue
        # If not A record response, then include unedited
        if i.type != 1:
            logger.debug("DNS response answer is not 'A'. Passing as-is.")
            print("DNS response answer is not 'A'. Passing as-is.")
            temp_list.append(i)
            continue

        # # Include an invalid IPv4 address just to make sure that Windows caches it correctly.
        # # This seems to break in Linux if preference isn't set. 
        # if not temp_v4_list:
        #     temp_v4_dict = {
        #         "rrname": i.rrname,
        #         "type": i.type,
        #         "rclass": i.rclass,
        #         "ttl": i.ttl,
        #         "rdata": "0.0.0.1",
        #     }
        #     temp_v4_list.append(temp_v4_dict)

        # Calculate address.
        ipv4_addr = IPv4Address(i.rdata)
        ipv6_addr = IPv6Address(int(ipv6_net) + int(ipv4_addr))
        logger.info("DNS response answer for '%s' translated from '%s' to '%s'.", i.rrname, ipv4_addr, ipv6_addr)
        print("DNS response answer for '%s' translated from '%s' to '%s'.", i.rrname, ipv4_addr, ipv6_addr)
        # Change the response type and answer.
        temp_dict = {
            "rrname": i.rrname,
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

    logger.debug("Packet sent.")
    print("Packet sent.")
    pkt.set_payload(bytes(pkt_sc))

    pkt.accept()


def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, mangle_dns)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Exiting")

    nfqueue.unbind()


if __name__ == "__main__":
    main()
