#! /bin/python3
# import time
import json
import logging
import os
import re
import subprocess
import sys  # , glob
from logging.handlers import RotatingFileHandler
from typing import Union

import vici
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer

TRUSTED_NETNS = "TRUST"
UNTRUSTED_NETNS = "UNTRUST"
UNTRUSTED_IF_NAME = "eth4"  # ens4
UNTRUSTED_IF_IP = "192.168.0.150/20"
UNTRUSTED_IF_GW = "192.168.0.1"
TRUSTED_TRANSIT = "fd33:2:f"
MGMT_PREFIX = "fd33::/16"
CUST_TUNNEL_PREFIX = "100.99"
CUST_PREFIX = "fdcc::/16"
CUST_CONN_PATH = "/etc/swanctl/conf.d"
DEFAULT_NETNS_LIST = ["ROOT", TRUSTED_NETNS, UNTRUSTED_NETNS]


# LOGGER
logger = logging.getLogger("ncubed vpnc daemon")
logger.setLevel(level=logging.DEBUG)
formatter = logging.Formatter(
    fmt="%(asctime)s(File:%(name)s,Line:%(lineno)d, %(funcName)s) - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %H:%M:%S %p",
)
rothandler = RotatingFileHandler(
    "/var/log/ncubed.vpnc.log", maxBytes=100000, backupCount=5
)
rothandler.setFormatter(formatter)
logger.addHandler(rothandler)
logger.addHandler(logging.StreamHandler(sys.stdout))


def _load_ipsec_config():
    """Load all swanctl strongswan configurations. Cannot find a way to do this with vici"""
    subprocess.run(
        "swanctl --load-all",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        # check=True,
    )


def _initiate_ipsec_connection(name: str):
    """Initiate an IKE/IPsec connection"""
    subprocess.run(
        f"swanctl --initiate --ike {name} --child {name}",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        # check=True,
    )


# def _get_ip_netns() -> list[dict[str, str]]:
#     """Retrieves a list of all network namespaces."""
#     run = subprocess.run(
#         "ip -j netns",
#         stdout=subprocess.PIPE,
#         stderr=subprocess.STDOUT,
#         shell=True,
#         check=True,
#     ).stdout.decode()

#     return json.loads(run)


def _get_ip_link(netns: str = None) -> list[dict[str, Union[str, list]]]:
    """Retrieves a list interfaces (in a network namespace)."""
    if netns:
        cmd = f"ip -j -n {netns} link"
    else:
        cmd = "ip -j link"
    run = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        # check=True,
    ).stdout.decode()

    return json.loads(run)


def update_customer_netnamespaces():
    logger.info("Updating customer namespaces")
    # Get all existing customer namespaces (not the three default namespaces)
    diff_netns = {ns for ns in os.listdir("/run/netns") if ns not in DEFAULT_NETNS_LIST}
    # load all connections
    _load_ipsec_config()
    # Retrieves all customer IDs in IPsec config files
    vpns = {
        x.decode()
        for x in vc.get_conns()["conns"]
        if re.match(r"c\d{4}-\d{2}", x.decode())
    }
    ref_netns = {x.split("-")[0] for x in vpns}

    for netns in ref_netns:  # .difference(diff_netns):
        logger.info(f"Creating netns {netns}")
        veth_i = f"{netns}_I"
        veth_e = f"{netns}_E"
        v6_segment_3 = netns[0]  # outputs c
        v6_segment_4 = int(netns.strip("c"))  # outputs 1
        # outputs fdcc:0:c:1:0
        v6_cust_space = f"fdcc:0:{v6_segment_3}:{v6_segment_4}:0"
        subprocess.run(
            f"""
            ip netns add {netns}
            # enable routing
            ip netns exec {netns} sysctl -w net.ipv4.conf.all.forwarding=1
            ip netns exec {netns} sysctl -w net.ipv6.conf.all.forwarding=1
            # add veth interfaces between TRUSTED and CUSTOMER network namespaces
            ip -n {TRUSTED_NETNS} link add {veth_i} type veth peer name {veth_e} netns {netns}
            # bring veth interfaces up
            ip -n {TRUSTED_NETNS} link set dev {veth_i} up
            ip -n {netns} link set dev {veth_e} up
            # assign IP addresses to veth interfaces
            ip -n {TRUSTED_NETNS} -6 address add {v6_cust_space}:1:0:0/127 dev {veth_i}
            ip -n {netns} -6 address add {v6_cust_space}:1:0:1/127 dev {veth_e}
            # add route from CUSTOMER to TRUSTED network namespace
            ip -n {netns} -6 route add fd33::/16 via {v6_cust_space}:1:0:0
            # start NAT64
            modprobe jool
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            # check=True,
        )

    # Remove any configured namespace that isn't in the IPsec configuration.
    for netns in set(diff_netns).difference(ref_netns):
        logger.info(f"Removing netns {netns}")
        subprocess.run(
            f"ip netns del {netns}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            # check=True,
        )

    for vpn in vpns:
        netns, vpn_id = vpn.split("-")
        xfrm = f"xfrm-{vpn}"
        xfrm_id = int(netns.strip("c")) * 100 + int(vpn_id)

        links = {x["ifname"] for x in _get_ip_link(netns) if x["ifname"] != "lo"}
        if not xfrm in links:
            subprocess.run(
                f"""
                ip -n {UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {UNTRUSTED_IF_NAME} if_id {xfrm_id}
                ip -n {UNTRUSTED_NETNS} link set {xfrm} netns {netns}
                ip -n {netns} link set dev {xfrm} up
                ip -n {netns} address add {CUST_TUNNEL_PREFIX}.{int(vpn_id)}.1/24 dev {xfrm}
                """,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                # check=True,
            )  # .stdout.decode().lower()

        _initiate_ipsec_connection(vpn)


observer = Observer()


# Define what should happen when file is created, modified or deleted.
class Handler(PatternMatchingEventHandler):
    def on_created(self, event: FileCreatedEvent):
        logger.info(f"File {event.event_type}: {event.src_path}")
        # update_customer_netnamespaces()

    def on_modified(self, event: FileModifiedEvent):
        logger.info(f"File {event.event_type}: {event.src_path}")
        update_customer_netnamespaces()

    def on_deleted(self, event: FileDeletedEvent):
        logger.info(f"File {event.event_type}: {event.src_path}")
        update_customer_netnamespaces()


# Configure the event handler that watches directories. This doesn't start the handler.
observer.schedule(
    event_handler=Handler(
        patterns=["*.conf"], ignore_patterns=[], ignore_directories=True
    ),
    path=CUST_CONN_PATH,
    recursive=True,
)
# The handler will not be running as a thread.
observer.daemon = False


def main():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """

    # Mounts the default network namespace with the alias ROOT. This makes for consistent operation
    # between all namespaces
    logger.info("Mounting default namespace as ROOT")
    subprocess.run(
        """
        touch /var/run/netns/ROOT
        mount --bind /proc/1/ns/net /var/run/netns/ROOT
    """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        # check=True,
    )  # .stdout.decode().lower()

    # The trusted namespace has no internet connectivity.
    # IPv6 routing is enabled on the namespace.
    # There is a link between the ROOT namespace and the trusted namespace.
    # The management prefix is reachable from this namespace.
    logger.info(f"Setting up {TRUSTED_NETNS} netns")
    subprocess.run(
        f"""
        ip netns add {TRUSTED_NETNS}
        ip netns exec {TRUSTED_NETNS} sysctl -w net.ipv6.conf.all.forwarding=1

        # Creates a veth pair and attaches it directly to the TRUSTED netns
        ip link add {TRUSTED_NETNS}_I type veth peer name {TRUSTED_NETNS}_E netns {TRUSTED_NETNS}

        ip -n {TRUSTED_NETNS} link set dev {TRUSTED_NETNS}_E up
        ip -n {TRUSTED_NETNS} addr add {TRUSTED_TRANSIT}::1/127 dev {TRUSTED_NETNS}_E

        ip link set dev {TRUSTED_NETNS}_I up
        ip addr add {TRUSTED_TRANSIT}::0/127 dev {TRUSTED_NETNS}_I

        ip -6 route add {MGMT_PREFIX} via {TRUSTED_TRANSIT}::1
    """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        # check=True,
    ).stdout.decode().lower()

    # The untrusted namespace has internet connectivity.
    # After creating this namespace, ipsec is restarted in this namespace.
    # No IPv6 routing is enabled on this namespace.
    # There is no connectivity to other namespaces.
    logger.info(f"Setting up {UNTRUSTED_NETNS} netns")
    subprocess.run(
        f"""
        ip netns add {UNTRUSTED_NETNS}
        ip link set {UNTRUSTED_IF_NAME} netns {UNTRUSTED_NETNS}
        ip -n {UNTRUSTED_NETNS} addr add {UNTRUSTED_IF_IP} dev {UNTRUSTED_IF_NAME}
        ip -n {UNTRUSTED_NETNS} link set dev {UNTRUSTED_IF_NAME} up
        ip -n {UNTRUSTED_NETNS} route add default via {UNTRUSTED_IF_GW}
        ip netns exec {UNTRUSTED_NETNS} ipsec start
        sleep 5
    """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        # check=True,
    ).stdout.decode().lower()

    _load_ipsec_config()

    # # Test for the customer prefixes.
    # logger.warning(f"Added route for testing from localhost, disable in production!!!")
    # subprocess.run(f'''
    #     ip -6 route add {CUSTOMER_PREFIX} via {TRUSTED_TRANSIT}::1
    # ''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().lower()


if __name__ == "__main__":
    logger.info("#" * 100)
    logger.info("Started VPNC Strongswan daemon")

    main()
    vc: vici.Session = vici.Session()
    update_customer_netnamespaces()

    # Start the event handler.
    logger.info("Monitoring config changes")
    observer.start()
