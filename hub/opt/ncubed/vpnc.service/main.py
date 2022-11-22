#! /bin/python3
import argparse
import ipaddress
import json
import logging
import pathlib
import re
import subprocess
import sys
import time
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
VPNC_SERVICE_CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpnc-service/config.yaml")
VPNC_SERVICE_MODE_PATH = pathlib.Path("/opt/ncubed/config/vpnc-service/mode.yaml")
VPNC_REMOTE_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnc-remote")
# Load the configuration
logger.info("Loading configuration from '%s'.", VPNC_SERVICE_CONFIG_PATH)
if not VPNC_SERVICE_CONFIG_PATH.exists():
    logger.critical("Configuration not found at '%s'.", VPNC_SERVICE_CONFIG_PATH)
    sys.exit(1)

# Global variable containing the configuration items. Should probably be a class.
VPNC_HUB_CONFIG: dict = {}

# Function to load the configuration file
def _load_config():
    global VPNC_HUB_CONFIG
    with open(VPNC_SERVICE_CONFIG_PATH, encoding="utf-8") as f:
        try:
            VPNC_HUB_CONFIG = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.critical(
                "Configuration is not valid '%s'.",
                VPNC_SERVICE_CONFIG_PATH,
                exc_info=True,
            )
            sys.exit(1)


_load_config()


# Load the Jinja templates
VPNC_TEMPLATE_DIR = pathlib.Path(__file__).parent.joinpath("templates")
VPNC_TEMPLATE_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(VPNC_TEMPLATE_DIR)
)

# Match only customer connections
CUST_RE = re.compile(r"c\d{4}-\d{3}")

TRUSTED_NETNS = "TRUST"  # name of trusted network namespace
UNTRUSTED_NETNS = "UNTRUST"  # name of outside/untrusted network namespace
# IPv6 prefix for client initiating administration traffic.
MGMT_PREFIX = ipaddress.IPv6Network(VPNC_HUB_CONFIG.get("mgmt_prefix", "::/16"))
# Tunnel transit IPv6 prefix for link between trusted namespace and root namespace, must be a /127.
TRUSTED_TRANSIT_PREFIX = ipaddress.IPv6Network(
    VPNC_HUB_CONFIG.get("trusted_transit_prefix", "::/127")
)
# IP prefix for tunnel interfaces to customers, must be a /16, will get subnetted into /24s
CUST_TUNNEL_PREFIX = ipaddress.IPv4Network(
    VPNC_HUB_CONFIG.get("customer_tunnel_prefix", "0.0.0.0/16")
)
CUST_PREFIX = "fdcc:0:c::/48"  # IPv6 prefix for NAT64 to customer networks
CUST_PREFIX_START = "fdcc:0:c"  # IPv6 prefix start for NAT64 to customer networks


if MGMT_PREFIX.prefixlen != 16:
    logger.critical("Prefix length for management prefix must be '/16'.")
    sys.exit(1)
if TRUSTED_TRANSIT_PREFIX.prefixlen != 127:
    logger.critical("Prefix length for trusted transit must be '/127'.")
    sys.exit(1)
if CUST_TUNNEL_PREFIX.prefixlen != 16:
    logger.critical("Prefix length for customer tunnels must be '/16'.")
    sys.exit(1)


def _downlink_observer() -> Observer:
    # Define what should happen when downlink files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            cust_config = pathlib.Path(event.src_path)
            add_downlink_connection(cust_config)

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            cust_config = pathlib.Path(event.src_path)
            time.sleep(1)
            add_downlink_connection(cust_config)

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            cust_config = pathlib.Path(event.src_path).stem
            delete_downlink_connection(cust_config)

    # Create the observer object. This doesn't start the handler.
    observer = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(patterns=["c*.yaml"], ignore_directories=True),
        path=VPNC_REMOTE_CONFIG_DIR,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def _downlink_endpoint_observer() -> Observer:
    # Define what should happen when downlink files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            cust_config = pathlib.Path(event.src_path)
            add_endpoint_downlink_connection(cust_config)

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            cust_config = pathlib.Path(event.src_path)
            time.sleep(1)
            add_endpoint_downlink_connection(cust_config)

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            cust_config = pathlib.Path(event.src_path).stem
            delete_endpoint_downlink_connection(cust_config)

    # Create the observer object. This doesn't start the handler.
    observer = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(patterns=["c*.yaml"], ignore_directories=True),
        path=VPNC_REMOTE_CONFIG_DIR,
        recursive=False,
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
        event_handler=UplinkHandler(), path=VPNC_SERVICE_CONFIG_PATH, recursive=False
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


def add_downlink_connection(path: pathlib.Path):
    """
    Configures downlink VPN connections.
    """

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    vpn_id = config["id"]
    vpn_id_int = int(vpn_id[1:])

    # NETWORK NAMESPACES AND XFRM INTERFACES
    ip_netns_str = subprocess.run(
        "ip -j netns",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    ip_netns = json.loads(ip_netns_str)

    netns_diff = {x["name"] for x in ip_netns if x["name"].startswith(vpn_id)}
    netns_ref = {f"{vpn_id}-{x:03}" for x in config["tunnels"].keys()}
    netns_remove = netns_diff.difference(netns_ref)

    # Configure XFRM interfaces for downlinks
    logger.info("Setting up uplink xfrm interfaces for %s netns.", TRUSTED_NETNS)
    for tun_id, tunnel_config in config["tunnels"].items():
        netns = f"{vpn_id}-{tun_id:03}"

        veth_i = f"{netns}_I"
        veth_e = f"{netns}_E"

        xfrm = f"xfrm-{netns}"
        xfrm_id = int(vpn_id_int) * 1000 + int(tun_id)

        v6_segment_4 = int(vpn_id_int)  # outputs 1
        v6_segment_5 = int(tun_id)  # outputs 0
        # outputs fdcc:0:c:1:0
        v6_cust_space = f"{CUST_PREFIX_START}:{v6_segment_4}:{v6_segment_5}"

        if tunnel_config.get("tunnel_ip"):
            v4_cust_tunnel_ip = tunnel_config["tunnel_ip"]
        else:
            v4_cust_tunnel_offset = ipaddress.IPv4Address(f"0.0.{int(tun_id)}.1")
            v4_cust_tunnel_ip = ipaddress.IPv4Address(
                int(CUST_TUNNEL_PREFIX[0]) + int(v4_cust_tunnel_offset)
            )
            v4_cust_tunnel_ip = f"{v4_cust_tunnel_ip}/24"

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
            ip -n {UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {VPNC_HUB_CONFIG["untrusted_if_name"]} if_id 0x{xfrm_id}
            ip -n {UNTRUSTED_NETNS} link set {xfrm} netns {netns}
            ip -n {netns} link set dev {xfrm} up
            ip -n {netns} address add {v4_cust_tunnel_ip} dev {xfrm}
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    for netns in netns_remove:
        # run the netns remove commands
        subprocess.run(
            f"ip netns del {netns}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    # VPN DOWNLINKS
    downlink_template = VPNC_TEMPLATE_ENV.get_template("downlink.conf.j2")
    downlink_configs = []
    for tun_id, tun_config in config["tunnels"].items():
        tunnel_config = {
            "remote": vpn_id,
            "t_id": f"{tun_id:03}",
            "remote_peer_ip": tun_config["remote_peer_ip"],
            "xfrm_id": int(vpn_id_int) * 1000 + int(tun_id),
            "psk": tun_config["psk"],
        }

        if tun_config.get("ike_version") and config.get("ike_version") != 2:
            tunnel_config["ike_version"] = tun_config["ike_version"]
        tunnel_config["ike_proposal"] = tun_config["ike_proposal"]
        tunnel_config["ipsec_proposal"] = tun_config["ipsec_proposal"]

        tunnel_config["local_id"] = VPNC_HUB_CONFIG["local_id"]
        if tun_config.get("remote_id"):
            tunnel_config["remote_id"] = tun_config["remote_id"]
        else:
            tunnel_config["remote_id"] = tun_config["remote_peer_ip"]

        if tun_config.get("traffic_selectors"):
            ts_local = ",".join(tun_config["traffic_selectors"]["local"])
            ts_remote = ",".join(tun_config["traffic_selectors"]["remote"])
            tunnel_config["ts"] = {"local": ts_local, "remote": ts_remote}

        downlink_configs.append(tunnel_config)

    downlink_render = downlink_template.render(
        connections=downlink_configs, updown=True
    )
    downlink_path = VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    print(downlink_path)
    with open(downlink_path, "w", encoding="utf-8") as f:
        f.write(downlink_render)

    _load_swanctl_all_config()


def add_endpoint_downlink_connection(path: pathlib.Path):
    """
    Configures downlink VPN connections.
    """

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    vpn_id = config["id"]
    vpn_id_int = int(vpn_id[1:])

    # NETWORK NAMESPACES AND XFRM INTERFACES
    ip_xfrm_str = subprocess.run(
        "ip -j link",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    ip_xfrm = json.loads(ip_xfrm_str)

    xfrm_diff = {
        x["ifname"] for x in ip_xfrm if x["ifname"].startswith(f"xfrm-{vpn_id}")
    }
    xfrm_ref = {f"xfrm-{vpn_id}-{x:03}" for x in config["tunnels"].keys()}
    xfrm_remove = xfrm_diff.difference(xfrm_ref)

    # Configure XFRM interfaces for downlinks
    logger.info("Setting up uplink xfrm interfaces.")
    for tun_id, tunnel_config in config["tunnels"].items():
        xfrm = f"xfrm-{vpn_id}-{tun_id:03}"
        xfrm_id = int(vpn_id_int) * 1000 + int(tun_id)

        cmd = f"""
        # configure XFRM interfaces
        ip -n {UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {VPNC_HUB_CONFIG["untrusted_if_name"]} if_id 0x{xfrm_id}
        ip -n {UNTRUSTED_NETNS} link set {xfrm} netns 1
        ip link set dev {xfrm} up
        ip address add {tunnel_config["tunnel_ip"]} dev {xfrm}
        """
        if tunnel_config.get("traffic_selectors"):
            for i in tunnel_config["traffic_selectors"]["remote"]:
                cmd += f"\nip route add {i} dev xfrm"
        elif tunnel_config.get("routes"):
            for i in tunnel_config["routes"]:
                cmd += f"\nip route add {i} dev xfrm"

        subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    for xfrm in xfrm_remove:
        # run the netns remove commands
        subprocess.run(
            f"ip link del {xfrm}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    # VPN DOWNLINKS
    downlink_template = VPNC_TEMPLATE_ENV.get_template("downlink.conf.j2")
    downlink_configs = []
    for tun_id, tun_config in config["tunnels"].items():
        tunnel_config = {
            "remote": vpn_id,
            "t_id": f"{tun_id:03}",
            "remote_peer_ip": tun_config["remote_peer_ip"],
            "xfrm_id": int(vpn_id_int) * 1000 + int(tun_id),
            "psk": tun_config["psk"],
        }

        if tun_config.get("ike_version") and config.get("ike_version") != 2:
            tunnel_config["ike_version"] = tun_config["ike_version"]
        tunnel_config["ike_proposal"] = tun_config["ike_proposal"]
        tunnel_config["ipsec_proposal"] = tun_config["ipsec_proposal"]

        tunnel_config["local_id"] = VPNC_HUB_CONFIG["local_id"]
        if tun_config.get("remote_id"):
            tunnel_config["remote_id"] = tun_config["remote_id"]
        else:
            tunnel_config["remote_id"] = tun_config["remote_peer_ip"]

        if tun_config.get("traffic_selectors"):
            ts_local = ",".join(tun_config["traffic_selectors"]["local"])
            ts_remote = ",".join(tun_config["traffic_selectors"]["remote"])
            tunnel_config["ts"] = {"local": ts_local, "remote": ts_remote}

        downlink_configs.append(tunnel_config)

    downlink_render = downlink_template.render(connections=downlink_configs)
    downlink_path = VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    print(downlink_path)
    with open(downlink_path, "w", encoding="utf-8") as f:
        f.write(downlink_render)

    _load_swanctl_all_config()


def delete_downlink_connection(vpn_id: str):
    """
    Removes downlink VPN connections.
    """

    # NETWORK NAMESPACES
    ip_netns_str = subprocess.run(
        "ip -j netns",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    ip_netns = json.loads(ip_netns_str)

    netns_remove = {x["name"] for x in ip_netns if x["name"].startswith(vpn_id)}
    for netns in netns_remove:
        # run the netns remove commands
        subprocess.run(
            f"ip netns del {netns}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    downlink_path = VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    downlink_path.unlink(missing_ok=True)

    _load_swanctl_all_config()


def delete_endpoint_downlink_connection(vpn_id: str):
    """
    Removes downlink VPN connections.
    """

    # NETWORK NAMESPACES
    ip_xfrm_str = subprocess.run(
        "ip -j link",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    ip_xfrm = json.loads(ip_xfrm_str)

    xfrm_remove = {
        x["ifname"] for x in ip_xfrm if x["ifname"].startswith(f"xfrm-{vpn_id}")
    }

    for xfrm in xfrm_remove:
        # run the link remove commands
        subprocess.run(
            f"ip link del {xfrm}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    downlink_path = VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    downlink_path.unlink(missing_ok=True)

    _load_swanctl_all_config()


def update_downlink_connection():
    """
    Configures downlinks.
    """
    config_files = list(VPNC_REMOTE_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files}
    vpn_config_files = list(VPN_CONFIG_DIR.glob(pattern="c*.conf"))
    vpn_config_set = {x.stem for x in vpn_config_files}

    for file_path in config_files:
        add_downlink_connection(file_path)

    for vpn_id in vpn_config_set.difference(config_set):
        delete_downlink_connection(vpn_id)


def update_endpoint_downlink_connection():
    """
    Configures downlinks.
    """
    config_files = list(VPNC_REMOTE_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files}
    vpn_config_files = list(VPN_CONFIG_DIR.glob(pattern="c*.conf"))
    vpn_config_set = {x.stem for x in vpn_config_files}

    for file_path in config_files:
        add_endpoint_downlink_connection(file_path)

    for vpn_id in vpn_config_set.difference(config_set):
        delete_endpoint_downlink_connection(vpn_id)


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
    uplinks_ref = {f"xfrm-uplink{x:03}" for x in VPNC_HUB_CONFIG["uplinks"].keys()}
    uplinks_remove = uplinks_diff.difference(uplinks_ref)

    # Configure XFRM interfaces for uplinks
    logger.info("Setting up uplink xfrm interfaces for %s netns.", TRUSTED_NETNS)

    for tun_id in VPNC_HUB_CONFIG["uplinks"].keys():
        uplink_xfrm_cmd = f"""
        # configure XFRM interfaces
        ip -n {UNTRUSTED_NETNS} link add xfrm-uplink{tun_id:03} type xfrm dev {VPNC_HUB_CONFIG["untrusted_if_name"]} if_id 0x9999{tun_id:03}
        ip -n {UNTRUSTED_NETNS} link set xfrm-uplink{tun_id:03} netns {TRUSTED_NETNS}
        ip -n {TRUSTED_NETNS} link set dev xfrm-uplink{tun_id:03} up
        """
        # run the commands
        subprocess.run(
            uplink_xfrm_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )  # .stdout.decode().lower()
    for remove_uplink in uplinks_remove:
        # run the commands
        subprocess.run(
            f"ip -n {TRUSTED_NETNS} link del dev {remove_uplink}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )  # .stdout.decode().lower()

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
    for tun_id, tun_config in VPNC_HUB_CONFIG["uplinks"].items():
        uplink_configs.append(
            {
                "remote": "uplink",
                "t_id": f"{tun_id:03}",
                "remote_peer_ip": tun_config["remote_peer_ip"],
                "xfrm_id": f"9999{tun_id:03}",
                "psk": tun_config["psk"],
                "local_id": VPNC_HUB_CONFIG["local_id"],
                "remote_id": tun_config["remote_peer_ip"],
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
        "bgp_router_id": VPNC_HUB_CONFIG["bgp_router_id"],
        "bgp_asn": VPNC_HUB_CONFIG["bgp_asn"],
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
    logger.info("Starting ncubed VPNC strongSwan daemon in hub mode.")

    # write a flag that specifies the run mode.
    with open(VPNC_SERVICE_MODE_PATH, "w", encoding="utf-8") as f:
        f.write("---\nmode: hub\n...\n")

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
        ip link set {VPNC_HUB_CONFIG["untrusted_if_name"]} netns {UNTRUSTED_NETNS}
        ip -n {UNTRUSTED_NETNS} address add {VPNC_HUB_CONFIG["untrusted_if_ip"]} dev {VPNC_HUB_CONFIG["untrusted_if_name"]}
        ip -n {UNTRUSTED_NETNS} link set dev {VPNC_HUB_CONFIG["untrusted_if_name"]} up
        ip -n {UNTRUSTED_NETNS} route add default via {VPNC_HUB_CONFIG["untrusted_if_gw"]}
        ip netns exec {UNTRUSTED_NETNS} ipsec start
        # start NAT64
        modprobe jool
        sleep 5
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
        ip -n {TRUSTED_NETNS} address add {TRUSTED_TRANSIT_PREFIX[1]}/127 dev {TRUSTED_NETNS}_E

        ip link set dev {TRUSTED_NETNS}_I up
        ip address add {TRUSTED_TRANSIT_PREFIX[0]}/127 dev {TRUSTED_NETNS}_I

        ip -6 route add {MGMT_PREFIX} via {TRUSTED_TRANSIT_PREFIX[1]}
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )  # .stdout.decode().lower()

    update_uplink_connection()

    # Start the event handler.
    logger.info("Monitoring uplink config changes.")
    uplink_observer = _uplink_observer()
    uplink_observer.start()

    update_downlink_connection()

    # Start the event handler.
    logger.info("Monitoring customer config changes.")
    downlink_observer = _downlink_observer()
    downlink_observer.start()


def main_endpoint():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """
    logger.info("#" * 100)
    logger.info("Starting ncubed VPNC strongSwan daemon in endpoint mode.")

    # write a flag that specifies the run mode.
    with open(VPNC_SERVICE_MODE_PATH, "w", encoding="utf-8") as f:
        f.write("---\nmode: endpoint\n...\n")

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
        ip link set {VPNC_HUB_CONFIG["untrusted_if_name"]} netns {UNTRUSTED_NETNS}
        ip -n {UNTRUSTED_NETNS} address add {VPNC_HUB_CONFIG["untrusted_if_ip"]} dev {VPNC_HUB_CONFIG["untrusted_if_name"]}
        ip -n {UNTRUSTED_NETNS} link set dev {VPNC_HUB_CONFIG["untrusted_if_name"]} up
        ip -n {UNTRUSTED_NETNS} route add default via {VPNC_HUB_CONFIG["untrusted_if_gw"]}
        ip netns exec {UNTRUSTED_NETNS} ipsec start
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    # Enable IPv6 and IPv4 on the default namespace.
    logger.info("Setting up %s netns.", TRUSTED_NETNS)
    subprocess.run(
        """
        sysctl -w net.ipv6.conf.all.forwarding=1
        sysctl -w net.ipv4.conf.all.forwarding=1
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )  # .stdout.decode().lower()

    update_endpoint_downlink_connection()

    # Start the event handler.
    logger.info("Monitoring customer config changes.")
    downlink_observer = _downlink_endpoint_observer()
    downlink_observer.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control the VPNC Strongswan daemon")
    subparser = parser.add_subparsers(help="Sub command help")
    parser_start = subparser.add_parser(
        "hub", help="Starts the VPN service in hub mode"
    )
    parser_start.set_defaults(func=main_hub)
    parser_start = subparser.add_parser(
        "endpoint", help="Starts the VPN service in endpoint mode"
    )
    parser_start.set_defaults(func=main_endpoint)

    args = parser.parse_args()
    # args = parser.parse_args()
    args.func()
