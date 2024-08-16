#!/usr/bin/env python3

import logging
import subprocess
import sys
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from logging.handlers import RotatingFileHandler
from time import sleep

import scapy.all as sc
from netfilterqueue import NetfilterQueue, Packet

from . import config, helpers, observers

logger = logging.getLogger("vpncmangle")


def setup_ip6tables(queue_number: int):
    """
    Configure ip6tables to capture DNS responses.
    """

    sp = subprocess.run(
        f"""
        # Configure DNS64 mangle
        ip6tables -t mangle -F
        ip6tables -t mangle -A POSTROUTING -p udp -m udp --sport 53 -j NFQUEUE --queue-num {queue_number}
        # ip6tables -t mangle -A POSTROUTING -p tcp -m tcp --sport 53 -j NFQUEUE --queue-num {queue_number}
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
        logger.debug("Packet response indicates error.\n%s", pkt_sc[sc.DNS])
        pkt.accept()
        return
    # If no answers in DNS.
    if not pkt_sc[sc.DNS].an:
        logger.debug("Packet response contains no answers.")
        pkt.accept()
        return

    # IPv6 address to perform DNS64 mangling with.
    # ipv6_net = IPv6Network(pkt_sc.src).supernet(new_prefix=96)[0]

    # The source address of the response (basically the DNS resolver). This IP is most likely
    # translated by NAT64 or NPTv6
    ipv6_src_addr = IPv6Address(pkt_sc.src)

    # vpncmangle has no idea where the response comes from. It requires the mapping configuration
    # to know this.

    if not config.CONFIG:
        logger.error("No configuration loaded.")
        pkt.drop()
        return
    network_instance_name: str | None = None
    for local_network, ni_name in config.ACL_MATCH:
        if ipv6_src_addr in local_network:
            network_instance_name = ni_name
            break

    if network_instance_name is None:
        logger.error(
            "IPv6 source address '%s' doesn't seem to match any configured address/network instance",
            ipv6_src_addr,
        )
        pkt.drop()
        return

    # Temporary list to store all desired DNS responses.
    temp_list = []
    temp_v4_list = []
    rrname = pkt_sc[sc.DNS].an.rrname
    for dns_query in pkt_sc[sc.DNS].an.iterpayloads():
        # # If AAAA record response, don't include it.
        # if i.type == 28:
        #     logger.debug("DNS response answer is 'AAAA'. Ignoring.")
        #     continue
        # # If CNAME record, get all addresses
        # if i.type == 5:
        #     logger.debug("DNS response answer is 'CNAME'. Ignoring.")
        #     continue
        # If not A record response, then include unedited
        # if i.type != 1:
        #     logger.debug("DNS response answer is not 'A'. Ignoring.")
        #     # temp_list.append(i)
        #     continue

        dns_response_doctored: IPv6Address | None = None
        if dns_query.type == 1:
            logger.debug("DNS response '%s' answer is 'A'.", dns_query.rdata)
            ipv6_local_network, _ = config.CONFIG[network_instance_name].dns64[0]
            # Calculate address.
            dns_response = IPv4Address(dns_query.rdata)
            dns_response_doctored = IPv6Address(
                int(ipv6_local_network.network_address) + int(dns_response)
            )
        elif dns_query.type == 28:
            logger.debug("DNS response '%s' answer is 'AAAA'.", dns_query.rdata)
            for ipv6_local_network, ipv6_remote_network in config.CONFIG[
                network_instance_name
            ].dns66:
                dns_response = IPv6Address(dns_query.rdata)
                if dns_response in ipv6_remote_network:
                    # Quit early if it is a network that isn't translated.
                    if ipv6_remote_network == ipv6_local_network:
                        dns_response_doctored = dns_response
                        break
                    host_part = int(dns_response) - int(
                        ipv6_remote_network.network_address
                    )
                    dns_response_doctored = IPv6Address(
                        int(ipv6_local_network.network_address) + host_part
                    )
                    break
        else:
            logger.debug(
                "DNS response answer type '%s' is not of a configured type. Ignoring.",
                dns_query.type,
            )
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

        if not dns_response_doctored:
            logger.error(
                "DNS response answer type '%s' with response '%s' couldn't be mangled. Ignorting",
                dns_query.type,
                dns_query.rdata,
            )
            continue

        logger.debug(
            "DNS response answer for '%s' translated from '%s' to '%s'.",
            dns_query.rrname.decode(),
            dns_response,
            dns_response_doctored,
        )
        # Change the response type and answer.
        temp_dict = {
            "rrname": rrname,
            "type": "AAAA",
            "rclass": dns_query.rclass,
            "ttl": dns_query.ttl,
            "rdata": str(dns_response_doctored),
        }

        # Append the result to the list.
        temp_list.append(temp_dict)

    temp_list.extend(temp_v4_list)
    dns_mangle = sc.DNSRR()
    for dns_query, val in enumerate(temp_list):
        # pdb.set_trace()
        if dns_query > 0:
            dns_mangle = dns_mangle / sc.DNSRR()
        dns_mangle[dns_query].rrname = val["rrname"]
        dns_mangle[dns_query].type = val["type"]
        dns_mangle[dns_query].rclass = val["rclass"]
        dns_mangle[dns_query].ttl = val["ttl"]
        dns_mangle[dns_query].rdata = val["rdata"]

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

    nfqueue = NetfilterQueue()
    retries = 10

    helpers.load_config()

    mangle_obs = observers.observe()
    mangle_obs.start()

    while True:
        for queue_number in range(retries):
            try:
                nfqueue.bind(queue_number, mangle_dns)
                setup_ip6tables(queue_number)
                break
            except ImportError:
                logger.debug(
                    "Attaching to netfilter queue %s failed, retrying.", queue_number
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
                "Mangle process ended prematurely. Restarting.", exc_info=True
            )
        finally:
            clean_ip6tables()
            nfqueue.unbind()

        sleep(0.1)


if __name__ == "__main__":
    main()
