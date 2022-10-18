#! /bin/python3
import argparse
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
from logging.handlers import RotatingFileHandler

import vici
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer

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

# Load the configuration
_config_path = pathlib.Path(__file__).parent.joinpath("config.json")
logger.info("Loading configuration from '%s'.", _config_path)
with open(_config_path, encoding="utf-8") as h:
    _config = json.load(h)

TRUSTED_NETNS = "TRUST"  # name of trusted network namespace
UNTRUSTED_NETNS = "UNTRUST"  # name of outside/untrusted network namespace
UNTRUSTED_IF_NAME = _config["untrusted_if_name"]  # name of outside interface
UNTRUSTED_IF_IP = _config["untrusted_if_ip"]  # IP address of outside interface
UNTRUSTED_IF_GW = _config["untrusted_if_gw"]  # default gateway of outside interface
TRUSTED_TRANSIT = _config[
    "trusted_transit"
]  # IPv6 transit network between management/ROOT and trusted ns
MGMT_PREFIX = _config["mgmt_prefix"]  # IPv6 prefix for client traffic from Palo Alto
CUST_TUNNEL_PREFIX = _config[
    "customer_tunnel_prefix"
]  # IP prefix for tunnel interface to customers
CUST_PREFIX = _config["customer_prefix"]  # IPv6 prefix for NAT64 to customer networks
VPN_CONFIG_PATH = "/etc/swanctl/conf.d"
DEFAULT_NETNS_LIST = ["ROOT", TRUSTED_NETNS, UNTRUSTED_NETNS]


# Define what should happen when files are created, modified or deleted.
class Handler(PatternMatchingEventHandler):
    """
    Handler for the event monitoring.
    """

    def on_created(self, event: FileCreatedEvent):
        logger.info("File %s: %s", event.event_type, event.src_path)
        # update_customer_netnamespaces()

    def on_modified(self, event: FileModifiedEvent):
        logger.info("File %s: %s", event.event_type, event.src_path)
        update_customer_netnamespaces()

    def on_deleted(self, event: FileDeletedEvent):
        logger.info("File %s: %s", event.event_type, event.src_path)
        update_customer_netnamespaces()


observer = Observer()

# Configure the event handler that watches directories. This doesn't start the handler.
observer.schedule(
    event_handler=Handler(
        patterns=["*.conf"], ignore_patterns=[], ignore_directories=True
    ),
    path=VPN_CONFIG_PATH,
    recursive=True,
)
# The handler will not be running as a thread.
observer.daemon = False


def _load_swanctl_config():
    """Load all swanctl strongswan configurations. Cannot find a way to do this with vici"""
    subprocess.run(
        "swanctl --load-all",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )


def _initiate_swanctl_connection(name: str):
    """Initiate an IKE/IPsec connection"""
    subprocess.run(
        f"swanctl --initiate --ike {name} --child {name}",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )


def update_customer_netnamespaces():
    """
    Adds customer namespaces and VPN configuration per customer.
    """
    logger.info("Updating customer namespaces")
    # Create a session to manage ipsec programmatically and load all connections.
    v_client: vici.Session = vici.Session()
    _load_swanctl_config()
    # Get all existing customer namespaces (not the three default namespaces)
    diff_netns = {ns for ns in os.listdir("/run/netns") if ns not in DEFAULT_NETNS_LIST}

    # Retrieves all customer VPN connections in IPsec config files
    vpns = {
        x.decode()
        for x in v_client.get_conns()["conns"]
        if re.match(r"c\d{4}-\d{2}", x.decode())
    }
    ref_netns = vpns

    for netns in ref_netns:  # .difference(diff_netns):
        logger.info("Creating %s netns.", netns)
        cust_id, tun_id = netns[1:].split("-")
        veth_i = f"{netns}_I"
        veth_e = f"{netns}_E"
        v6_segment_3 = netns[0]  # outputs c
        v6_segment_4 = int(cust_id)  # outputs 1
        v6_segment_5 = int(tun_id)  # outputs 1
        # outputs fdcc:0:c:1:0
        v6_cust_space = f"fdcc:0:{v6_segment_3}:{v6_segment_4}:{v6_segment_5}"
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
            check=False,
        )

        xfrm = f"xfrm-{netns}"
        xfrm_id = int(cust_id) * 100 + int(tun_id)

        logger.info("Creating %s interface in %s netns.", xfrm, netns)
        subprocess.run(
            f"""
            ip -n {UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {UNTRUSTED_IF_NAME} if_id {xfrm_id}
            ip -n {UNTRUSTED_NETNS} link set {xfrm} netns {netns}
            ip -n {netns} link set dev {xfrm} up
            ip -n {netns} address add {CUST_TUNNEL_PREFIX}.{int(tun_id)}.1/24 dev {xfrm}
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )  # .stdout.decode().lower()

        _initiate_swanctl_connection(netns)

    # Remove any configured namespace that isn't in the IPsec configuration.
    for netns in set(diff_netns).difference(ref_netns):
        logger.info("Removing %s netns.", netns)
        subprocess.run(
            f"ip netns del {netns}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=True,
        )


def main_start():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """
    logger.info("#" * 100)
    logger.info("Starting ncubed VPNC strongSwan daemon.")

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
        check=False,
    )  # .stdout.decode().lower()

    # The trusted namespace has no internet connectivity.
    # IPv6 routing is enabled on the namespace.
    # There is a link between the ROOT namespace and the trusted namespace.
    # The management prefix is reachable from this namespace.
    logger.info("Setting up %s netns.", TRUSTED_NETNS)
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
        check=False,
    ).stdout.decode().lower()

    # The untrusted namespace has internet connectivity.
    # After creating this namespace, ipsec is restarted in this namespace.
    # No IPv6 routing is enabled on this namespace.
    # There is no connectivity to other namespaces.
    logger.info("Setting up %s netns", UNTRUSTED_NETNS)
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
        check=False,
    ).stdout.decode().lower()

    update_customer_netnamespaces()

    # Start the event handler.
    logger.info("Monitoring config changes.")
    observer.start()


def main_stop():
    """
    Cleans up part of the default configuration.
    """
    logger.info("#" * 100)
    logger.info("Stopping ncubed VPNC strongSwan daemon.")

    logger.info("Stopping the monitoring config changes.")
    observer.stop()

    # Removing the route to management as it will be unreachable. Also set the veth interfaces down.
    logger.info("Cleaning up %s netns.", TRUSTED_NETNS)
    subprocess.run(
        f"""
        ip -6 route del {MGMT_PREFIX} via {TRUSTED_TRANSIT}::1
        ip link set dev {TRUSTED_NETNS}_I down
        ip -n {TRUSTED_NETNS} link set dev {TRUSTED_NETNS}_E down
    """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode().lower()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control the VPNC Strongswan daemon")
    subparser = parser.add_subparsers(help="Sub command help")
    parser_start = subparser.add_parser("start", help="Starts the VPN service")
    parser_start.set_defaults(func=main_start)
    parser_stop = subparser.add_parser("stop", help="Stops the VPN service")
    parser_stop.set_defaults(func=main_stop)
    args = parser.parse_args()
    args.func()
