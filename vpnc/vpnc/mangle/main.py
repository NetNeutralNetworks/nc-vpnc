#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue, Packet
from scapy.all import *


def mangle_dns(pkt: Packet):
    pkt_sc = IP(pkt.get_payload())
    # If not DNS record
    if not pkt_sc.haslayer(DNSRR):
        pkt.accept()
        return
    # if not a response (QR field, query is 0, response 1)
    if pkt_sc[DNS].qr != 1:
        pkt.accept()
        return
    # if return code is not ok
    if pkt_sc[DNS].rcode != 0:
        pkt.accept()
        return

    # rrname = pkt_sc[DNSQR].qname
    if pkt_sc[DNS].an:
        for i in range(pkt_sc[DNS].ancount):
            # if not A record response
            if pkt_sc[DNS].an[i].type != 1:
                continue

            rdata = pkt_sc[DNS].an[i].rdata
            pkt_sc[DNS].an[i].type = "AAAA"
            pkt_sc[DNS].an[i].rdata = f"fd00::{rdata}"
            del pkt_sc[DNS].an[i].rdlen

        del pkt_sc[IP].len
        del pkt_sc[IP].chksum
        del pkt_sc[UDP].len
        del pkt_sc[UDP].chksum

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
