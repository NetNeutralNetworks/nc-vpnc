#! /bin/python3
import argparse
import ipaddress
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
from logging.handlers import RotatingFileHandler

import jinja2
import vici
import yaml
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
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

# Configuration file paths/directories
VPN_CONFIG_DIR = pathlib.Path("/etc/swanctl/conf.d")
VPNC_HUB_CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpnc-hub/config.yaml")
VPNC_VPN_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnc-hub")
# Load the configuration
logger.info("Loading configuration from '%s'.", VPNC_HUB_CONFIG_PATH)
if not VPNC_HUB_CONFIG_PATH.exists():
    logger.critical("Configuration not found at '%s'.", VPNC_HUB_CONFIG_PATH)
    sys.exit(1)

# Global variable containing the configuration items. Should probably be a class.
VPNC_HUB_CONFIG: dict = {}

# Function to load the configuration file
def _load_config():
    global VPNC_HUB_CONFIG
    with open(VPNC_HUB_CONFIG_PATH, encoding="utf-8") as f:
        try:
            VPNC_HUB_CONFIG = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.critical(
                "Configuration is not valid '%s'.", VPNC_HUB_CONFIG_PATH, exc_info=True
            )
            sys.exit(1)


_load_config()


# Load the Jinja templates
VPNC_TEMPLATE_DIR = pathlib.Path(__file__).parent.joinpath("templates")
VPNC_TEMPLATE_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(VPNC_TEMPLATE_DIR))

# Match only customer connections
CUST_RE = re.compile(r"c\d{4}-\d{3}")

TRUSTED_NETNS = "TRUST"  # name of trusted network namespace
UNTRUSTED_NETNS = "UNTRUST"  # name of outside/untrusted network namespace
UNTRUSTED_IF_NAME = VPNC_HUB_CONFIG["untrusted_if_name"]  # name of outside interface
UNTRUSTED_IF_IP = VPNC_HUB_CONFIG["untrusted_if_ip"]  # IP address of outside interface
UNTRUSTED_IF_GW = VPNC_HUB_CONFIG["untrusted_if_gw"]  # default gateway of outside interface
# IPv6 transit network between management/ROOT and trusted net namespace
TRUSTED_TRANSIT_PREFIX = ipaddress.IPv6Network(VPNC_HUB_CONFIG["trusted_transit_prefix"])
MGMT_PREFIX = VPNC_HUB_CONFIG["mgmt_prefix"]  # IPv6 prefix for client traffic from Palo Alto
# IP prefix for tunnel interfaces to customers
CUST_TUNNEL_PREFIX = ipaddress.IPv4Network(VPNC_HUB_CONFIG["customer_tunnel_prefix"])
CUST_PREFIX = "fdcc:0:c::/48"  # IPv6 prefix for NAT64 to customer networks
CUST_PREFIX_START = "fdcc:0:c"  # IPv6 prefix start for NAT64 to customer networks

DEFAULT_NETNS_LIST = ["ROOT", TRUSTED_NETNS, UNTRUSTED_NETNS]

if TRUSTED_TRANSIT_PREFIX.prefixlen != 127:
    logger.critical("Prefix length for trusted transit must be '/127'.")
    sys.exit(1)
if CUST_TUNNEL_PREFIX.prefixlen != 16:
    logger.critical("Prefix length for customer tunnels must be '/16'.")
    sys.exit(1)


def _customer_observer() -> Observer:
    # Define what should happen when customer files are created, modified or deleted.
    class CustomerHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            conn = pathlib.Path(event.src_path).stem
            add_customer_connection(conn)

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            conn = pathlib.Path(event.src_path).stem
            add_customer_connection(conn)

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            conn = pathlib.Path(event.src_path).stem
            delete_customer_connection(conn)

    # Create the observer object. This doesn't start the handler.
    observer = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=CustomerHandler(
            patterns=["*.conf"], ignore_patterns=[], ignore_directories=True
        ),
        path=VPN_CONFIG_DIR,
        recursive=True,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def _uplink_observer() -> Observer:
    # Define what should happen when the config file with uplink data is modified.
    class UplinkHandler(FileSystemEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            _load_config()
            update_uplink_connection()

    # Create the observer object. This doesn't start the handler.
    observer = Observer()
    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=UplinkHandler(), path=VPNC_HUB_CONFIG_PATH, recursive=False
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def _load_swanctl_all_config():
    """Load all swanctl strongswan configurations. Cannot find a way to do this with vici"""
    subprocess.run(
        "swanctl --load-all",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )


def _initiate_swanctl_connection(connection: str):
    """Initiate an IKE/IPsec connection"""
    logger.debug("Initiating connection '%s'.", connection)
    vcs = vici.Session()
    output = vcs.initiate({"ike": connection, "child": connection})
    logger.debug(output)


def _terminate_swanctl_connection(connection: str):
    """Terminate an IKE/IPsec connection"""
    logger.debug("Terminating connection '%s'.", connection)
    vcs = vici.Session()
    output = vcs.terminate({"ike": connection, "child": connection})
    logger.debug(output)


def add_customer_connection(connection):
    """Configures one customer connection, which includes a namespace and VPN connection."""
    # Check first if it's a customer connection
    if not CUST_RE.match(connection):
        logger.info("Connection '%s' is not a customer connection.", connection)
        return

    logger.info("Creating %s netns.", connection)

    netns = connection
    cust_id, tun_id = connection[1:].split("-")
    veth_i = f"{connection}_I"
    veth_e = f"{connection}_E"
    xfrm = f"xfrm-{connection}"
    xfrm_id = int(cust_id) * 1000 + int(tun_id)

    v6_segment_4 = int(cust_id)  # outputs 1
    v6_segment_5 = int(tun_id)  # outputs 1
    # outputs fdcc:0:c:1:0
    v6_cust_space = f"{CUST_PREFIX_START}:{v6_segment_4}:{v6_segment_5}"

    v4_cust_tunnel_offset = ipaddress.IPv4Address(f"0.0.{int(tun_id)}.1")
    v4_cust_tunnel_ip = ipaddress.IPv4Address(
        int(CUST_TUNNEL_PREFIX[0]) + int(v4_cust_tunnel_offset)
    )

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
        # add route from CUSTOMER to MGMT network via TRUSTED namespace
        ip -n {netns} -6 route add {MGMT_PREFIX} via {v6_cust_space}:1:0:0
        # configure XFRM interfaces
        ip -n {UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {UNTRUSTED_IF_NAME} if_id 0x{xfrm_id}
        ip -n {UNTRUSTED_NETNS} link set {xfrm} netns {netns}
        ip -n {netns} link set dev {xfrm} up
        ip -n {netns} address add {v4_cust_tunnel_ip}/24 dev {xfrm}
        # start NAT64
        modprobe jool
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    # Remove the old connection and create the new one
    # load all is inefficient, but it's easier
    _load_swanctl_all_config()
    _initiate_swanctl_connection(connection)


def delete_customer_connection(connection):
    """Configures one customer connection, which includes a namespace and VPN connection."""
    # Check first if it's a customer connection
    if not CUST_RE.match(connection):
        logger.info("Connection '%s' is not a customer connection.", connection)
        return

    logger.info("Terminating connection '%s'.", connection)
    netns = connection
    # Remove the old connection
    # load all is inefficient, but it's easier
    _load_swanctl_all_config()
    _terminate_swanctl_connection(connection)

    logger.info("Removing %s netns.", netns)
    subprocess.run(
        f"ip netns del {netns}",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )


def update_customer_connection():
    """
    Configures and cleans up customer namespaces and VPN connections.
    """
    logger.info("Updating customer namespaces")
    # Create a session to manage ipsec programmatically and load all connections.
    vcs: vici.Session = vici.Session()
    _load_swanctl_all_config()
    # Get all existing customer namespaces (not the three default namespaces)
    diff_netns = {ns for ns in os.listdir("/run/netns") if ns not in DEFAULT_NETNS_LIST}

    # Retrieves all customer VPN connections in IPsec config files. decode is used as the strings
    # in x are binary, not UTF-8
    connections = {
        x.decode() for x in vcs.get_conns()["conns"] if CUST_RE.match(x.decode())
    }

    for connection in connections:  # .difference(diff_netns):
        tun_id = connection[1:].split("-")[1]
        # A customer can have a maximum of 255 interfaces
        if int(tun_id) > 255:
            logger.warning(
                "Skipping VPN connection '%s'. Tunnel index is more than 255.", tun_id
            )
            continue

        # Configure the connection
        add_customer_connection(connection)

    # Remove any configured namespace that isn't in the IPsec configuration.
    for connection in set(diff_netns).difference(connections):
        delete_customer_connection(connection)


def update_uplink_connection():
    """
    Configures uplinks.
    """

    # XFRM INTERFACES
    xfrm_ns_str = subprocess.run(
        f"ip -j -n {TRUSTED_NETNS} link",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    xfrm_ns = json.loads(xfrm_ns_str)

    uplinks_diff = {
        x["ifname"] for x in xfrm_ns if x["ifname"].startswith("xfrm-uplink")
    }
    uplinks_ref = {f"xfrm-uplink{x:03}" for x in VPNC_HUB_CONFIG["uplink_vpns"].keys()}
    uplinks_remove = uplinks_diff.difference(uplinks_ref)

    # Configure XFRM interfaces for uplinks
    logger.info("Setting up uplink xfrm interfaces for %s netns.", TRUSTED_NETNS)
    uplink_xfrm = ""
    for tun_id in VPNC_HUB_CONFIG["uplink_vpns"].keys():
        uplink_xfrm += f"""
        # configure XFRM interfaces
        ip -n {UNTRUSTED_NETNS} link add xfrm-uplink{tun_id:03} type xfrm dev {UNTRUSTED_IF_NAME} if_id 0x9999{tun_id:03}
        ip -n {UNTRUSTED_NETNS} link set xfrm-uplink{tun_id:03} netns {TRUSTED_NETNS}
        ip -n {TRUSTED_NETNS} link set dev xfrm-uplink{tun_id:03} up
        """
    for remove_uplink in uplinks_remove:
        uplink_xfrm += f"ip -n {TRUSTED_NETNS} link del dev {remove_uplink}"

    # run the comands
    subprocess.run(
        uplink_xfrm,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    ).stdout.decode().lower()

    # IP(6)TABLES RULES
    # The trusted netns blocks all traffic originating from the customer namespaces,
    # but does accept traffic originating from the default and management zones.
    iptables_template = VPNC_TEMPLATE_ENV.get_template("iptables.conf.j2")
    iptables_configs = {"trusted_netns": TRUSTED_NETNS, "uplinks": uplinks_ref}
    iptables_render = iptables_template.render(**iptables_configs)
    print(iptables_render)
    subprocess.run(
        iptables_render,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )  # .stdout.decode().lower()

    # VPN UPLINKS
    uplink_template = VPNC_TEMPLATE_ENV.get_template("uplink.conf.j2")
    uplink_configs = []
    for tun_id, tun_config in VPNC_HUB_CONFIG["uplink_vpns"].items():
        uplink_configs.append(
            {
                "remote": "uplink",
                "t_id": f"{tun_id:03}",
                "remote_peer_ip": tun_config["remote_peer_ip"],
                "xfrm_id": f"9999{tun_id:03}",
                "psk": tun_config["psk"],
            }
        )

    uplink_render = uplink_template.render(connections=uplink_configs)
    uplink_path = VPN_CONFIG_DIR.joinpath("uplink.conf")
    print(uplink_path)
    with open(uplink_path, "w", encoding="utf-8") as f:
        f.write(uplink_render)

    _load_swanctl_all_config()

    # FRR/BGP CONFIG
    bgp_template = VPNC_TEMPLATE_ENV.get_template("frr-bgp.conf.j2")
    bgp_configs = {
        "trusted_netns": TRUSTED_NETNS,
        "router_id": VPNC_HUB_CONFIG["router_id"],
        "asn": VPNC_HUB_CONFIG["asn"],
        "uplinks": uplinks_ref,
        "remove_uplinks": uplinks_remove,
        "management_prefix": MGMT_PREFIX,
        "customer_prefix": CUST_PREFIX,
    }
    bgp_render = bgp_template.render(**bgp_configs)
    print(bgp_render)
    with open("/etc/frr/frr.conf", "w+", encoding="utf-8") as f:
        f.write(bgp_render)

    # Load the commands in case FRR was already running
    subprocess.run(
        "vtysh -f /etc/frr/frr.conf",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )


def main_hub():
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

    # The untrusted namespace has internet connectivity.
    # After creating this namespace, ipsec is restarted in this namespace.
    # No IPv6 routing is enabled on this namespace.
    # There is no connectivity to other namespaces.
    logger.info("Setting up %s netns", UNTRUSTED_NETNS)
    subprocess.run(
        f"""
        ip netns add {UNTRUSTED_NETNS}
        ip link set {UNTRUSTED_IF_NAME} netns {UNTRUSTED_NETNS}
        ip -n {UNTRUSTED_NETNS} address add {UNTRUSTED_IF_IP} dev {UNTRUSTED_IF_NAME}
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
        ip -n {TRUSTED_NETNS} address add {TRUSTED_TRANSIT_PREFIX[1]}/127 dev {TRUSTED_NETNS}_E

        ip link set dev {TRUSTED_NETNS}_I up
        ip address add {TRUSTED_TRANSIT_PREFIX[0]}/127 dev {TRUSTED_NETNS}_I

        ip -6 route add {MGMT_PREFIX} via {TRUSTED_TRANSIT_PREFIX[1]}
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    ).stdout.decode().lower()

    update_uplink_connection()

    # Start the event handler.
    logger.info("Monitoring uplink config changes.")
    uplink_observer = _uplink_observer()
    uplink_observer.start()

    update_customer_connection()

    # Start the event handler.
    logger.info("Monitoring customer config changes.")
    customer_observer = _customer_observer()
    customer_observer.start()


# def main_stop():
#     """
#     Cleans up part of the default configuration.
#     """
#     logger.info("#" * 100)
#     logger.info("Stopping ncubed VPNC strongSwan daemon.")

#     # logger.info("Stopping the monitoring config changes.")
#     # observer.stop()

#     # Removing the route to management as it will be unreachable. Also set the veth interfaces down.
#     logger.info("Cleaning up %s netns.", TRUSTED_NETNS)
#     subprocess.run(
#         f"""
#         ip -6 route del {MGMT_PREFIX} via {TRUSTED_TRANSIT_PREFIX[1]}
#         ip link set dev {TRUSTED_NETNS}_I down
#         ip netns exec {TRUSTED_NETNS} ipsec down
#         ip -n {TRUSTED_NETNS} link set dev {TRUSTED_NETNS}_E down
#         """,
#         stdout=subprocess.PIPE,
#         stderr=subprocess.STDOUT,
#         shell=True,
#         check=True,
#     ).stdout.decode().lower()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control the VPNC Strongswan daemon")
    subparser = parser.add_subparsers(help="Sub command help")
    parser_start = subparser.add_parser(
        "hub", help="Starts the VPN service in hub mode"
    )
    parser_start.set_defaults(func=main_hub)
    # parser_stop = subparser.add_parser("stop", help="Stops the VPN service")
    # parser_stop.set_defaults(func=main_stop)
    args = parser.parse_args()
    args.func()
