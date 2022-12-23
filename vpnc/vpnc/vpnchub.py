#!/usr/bin/env python3

import ipaddress
import json
import logging
import pathlib
import subprocess
import sys
import time

import jinja2
import yaml
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer

from . import consts, datacls, helpers

logger = logging.getLogger("vpnc")

# Load the Jinja templates
VPNC_TEMPLATE_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(consts.VPNC_TEMPLATES_DIR)
)

# Global variable containing the configuration items. Should probably be a class.
VPNC_HUB_CONFIG: datacls.ServiceHub = datacls.ServiceHub()
# IPv6 prefix for client initiating administration traffic.
PREFIX_UPLINK: ipaddress.IPv6Network = VPNC_HUB_CONFIG.prefix_uplink
# IP prefix for downlinks. Must be a /16, will get subnetted into /24s per downlink tunnel.
PREFIX_DOWNLINK_V4: ipaddress.IPv4Network = VPNC_HUB_CONFIG.prefix_downlink_v4
# IPv6 prefix for downlinks. Must be a /32. Will be subnetted into /96s per downlink per tunnel.
PREFIX_DOWNLINK_V6: ipaddress.IPv6Network = VPNC_HUB_CONFIG.prefix_downlink_v6
# IPv6 prefix start for NAT64 to downlink networks
# returns "fdcc:0000" if prefix is fdcc::/32
PREFIX_DOWNLINK_V6_START = PREFIX_DOWNLINK_V6.exploded[:9]


if PREFIX_UPLINK.prefixlen != 16:
    logger.critical("Prefix length for uplink prefix must be '/16'.")
    sys.exit(1)
if PREFIX_DOWNLINK_V4.prefixlen != 16:
    logger.critical("Prefix length for downlink IPv4 prefix must be '/16'.")
    sys.exit(1)
if PREFIX_DOWNLINK_V6.prefixlen != 32:
    logger.critical("Prefix length for downlink IPv6 prefix must be '/32'.")
    sys.exit(1)


def _load_config(config_path: pathlib.Path):
    """
    Load the global configuration.
    """
    global VPNC_HUB_CONFIG

    new_cfg: datacls.ServiceHub = datacls.ServiceHub()
    with open(config_path, "r", encoding="utf-8") as f:
        try:
            new_cfg_dict = yaml.safe_load(f)
            new_cfg = datacls.ServiceHub(**new_cfg_dict)
        except (yaml.YAMLError, TypeError):
            logger.critical(
                "Configuration is not valid '%s'.",
                config_path,
                exc_info=True,
            )
            sys.exit(1)

    VPNC_HUB_CONFIG = new_cfg
    logger.info("Loaded new configuration.")


def _downlink_observer() -> Observer:
    # Define what should happen when downlink files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            _add_downlink_connection(downlink_config)

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            _add_downlink_connection(downlink_config)

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path).stem
            _delete_downlink_connection(downlink_config)

    # Create the observer object. This doesn't start the handler.
    observer = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(patterns=["c*.yaml"], ignore_directories=True),
        path=consts.VPNC_A_REMOTE_CONFIG_DIR,
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
            _load_config(consts.VPNC_A_SERVICE_CONFIG_PATH)
            time.sleep(0.1)
            _update_uplink_connection()

    # Create the observer object. This doesn't start the handler.
    observer = Observer()
    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=UplinkHandler(),
        path=consts.VPNC_A_SERVICE_CONFIG_PATH,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def _add_downlink_connection(path: pathlib.Path):
    """
    Configures downlink VPN connections.
    """

    with open(path, "r", encoding="utf-8") as f:
        try:
            config_yaml = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
            return

    # Parse the YAML file to a Downlink object and validate the input.
    try:
        config = datacls.Remote(**config_yaml)
    except (TypeError, ValueError):
        logger.error(
            "Invalid configuration found in '%s'. Skipping.", path, exc_info=True
        )
        return

    # Get the downlink ID. This must match the file name.
    vpn_id = config.id
    vpn_id_int = int(vpn_id[1:])

    if vpn_id != path.stem:
        logger.error(
            "VPN identifier '%s' and configuration file name '%s' do not match. Skipping.",
            vpn_id,
            path.stem,
        )
        return

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
    netns_ref = {f"{vpn_id}-{x:03}" for x in config.tunnels.keys()}
    netns_remove = netns_diff.difference(netns_ref)

    # Configure XFRM interfaces for downlinks
    logger.info("Setting up uplink xfrm interfaces for %s netns.", consts.TRUSTED_NETNS)
    for tunnel_id, t_config in config.tunnels.items():
        netns = f"{vpn_id}-{tunnel_id:03}"

        veth_i = f"{netns}_I"
        veth_e = f"{netns}_E"

        xfrm = f"xfrm-{netns}"
        xfrm_id = int(vpn_id_int) * 1000 + int(tunnel_id)

        v6_segment_3 = vpn_id[0]  # outputs c
        v6_segment_4 = int(vpn_id_int)  # outputs 1
        v6_segment_5 = int(tunnel_id)  # outputs 0
        # outputs fdcc:0:c:1:0
        v6_downlink_space = (
            f"{PREFIX_DOWNLINK_V6_START}:{v6_segment_3}:{v6_segment_4}:{v6_segment_5}"
        )

        if t_config.tunnel_ip:
            v4_downlink_tunnel_ip = t_config.tunnel_ip
        else:
            v4_downlink_tunnel_offset = ipaddress.IPv4Address(f"0.0.{int(tunnel_id)}.1")
            v4_downlink_tunnel_ip = ipaddress.IPv4Address(
                int(PREFIX_DOWNLINK_V4[0]) + int(v4_downlink_tunnel_offset)
            )
            v4_downlink_tunnel_ip = f"{v4_downlink_tunnel_ip}/24"

        sp = subprocess.run(
            f"""
            ip netns add {netns}
            # enable routing
            ip netns exec {netns} sysctl -w net.ipv4.conf.all.forwarding=1
            ip netns exec {netns} sysctl -w net.ipv6.conf.all.forwarding=1
            # add veth interfaces between TRUSTED and DOWNLINK network namespaces
            ip -n {consts.TRUSTED_NETNS} link add {veth_i} type veth peer name {veth_e} netns {netns}
            # bring veth interfaces up
            ip -n {consts.TRUSTED_NETNS} link set dev {veth_i} up
            ip -n {netns} link set dev {veth_e} up
            # assign IP addresses to veth interfaces
            ip -n {consts.TRUSTED_NETNS} -6 address add {v6_downlink_space}:1:0:0/127 dev {veth_i}
            ip -n {netns} -6 address add {v6_downlink_space}:1:0:1/127 dev {veth_e}
            # add route from DOWNLINK to MGMT network via TRUSTED namespace
            ip -n {netns} -6 route add {PREFIX_UPLINK} via {v6_downlink_space}:1:0:0
            # configure XFRM interfaces
            ip -n {consts.UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {VPNC_HUB_CONFIG.untrusted_if_name} if_id 0x{xfrm_id}
            ip -n {consts.UNTRUSTED_NETNS} link set {xfrm} netns {netns}
            ip -n {netns} link set dev {xfrm} up
            ip -n {netns} address add {v4_downlink_tunnel_ip} dev {xfrm}
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        logger.info(sp.args)
        logger.info(sp.stdout.decode())

    for netns in netns_remove:
        # run the netns remove commands
        sp = subprocess.run(
            f"ip netns del {netns}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        logger.info(sp.args)
        logger.info(sp.stdout.decode())

    # VPN DOWNLINKS
    downlink_template = VPNC_TEMPLATE_ENV.get_template("downlink.conf.j2")
    downlink_configs = []
    for tunnel_id, tunnel_config in config.tunnels.items():
        t_config = {
            "remote": vpn_id,
            "t_id": f"{tunnel_id:03}",
            "remote_peer_ip": tunnel_config.remote_peer_ip,
            "xfrm_id": int(vpn_id_int) * 1000 + int(tunnel_id),
            "psk": tunnel_config.psk,
        }

        if tunnel_config.ike_version and tunnel_config.ike_version != 2:
            t_config["ike_version"] = tunnel_config.ike_version
        t_config["ike_proposal"] = tunnel_config.ike_proposal
        t_config["ipsec_proposal"] = tunnel_config.ipsec_proposal

        t_config["local_id"] = VPNC_HUB_CONFIG.local_id
        if tunnel_config.remote_id:
            t_config["remote_id"] = tunnel_config.remote_id
        else:
            t_config["remote_id"] = tunnel_config.remote_peer_ip

        if tunnel_config.traffic_selectors:
            ts_loc = ",".join((str(x) for x in tunnel_config.traffic_selectors.local))
            ts_rem = ",".join((str(x) for x in tunnel_config.traffic_selectors.remote))
            t_config["ts"] = {"local": ts_loc, "remote": ts_rem}

        downlink_configs.append(t_config)

    downlink_render = downlink_template.render(
        connections=downlink_configs, updown=True
    )
    downlink_path = consts.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")

    with open(downlink_path, "w", encoding="utf-8") as f:
        f.write(downlink_render)

    helpers.load_swanctl_all_config()


def _delete_downlink_connection(vpn_id: str):
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

    logger.info("Removing all namespace configuration for '%s'.", vpn_id)
    netns_remove = {x["name"] for x in ip_netns if x["name"].startswith(vpn_id)}

    for netns in netns_remove:
        helpers.terminate_swanctl_connection(netns)
        # run the netns remove commands
        sp = subprocess.run(
            f"ip netns del {netns}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        ).stdout
        logger.info(sp)
        print(sp)

    logger.info("Removing VPN configuration for '%s'.", vpn_id)
    downlink_path = consts.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    downlink_path.unlink(missing_ok=True)

    helpers.load_swanctl_all_config()


def _update_downlink_connection():
    """
    Configures downlinks.
    """
    config_files = list(consts.VPNC_A_REMOTE_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files}
    vpn_config_files = list(consts.VPN_CONFIG_DIR.glob(pattern="[abcdef]*.conf"))
    vpn_config_set = {x.stem for x in vpn_config_files}

    for file_path in config_files:
        _add_downlink_connection(file_path)

    for vpn_id in vpn_config_set.difference(config_set):
        _delete_downlink_connection(vpn_id)


def _update_uplink_connection():
    """
    Configures uplinks.
    """

    # XFRM INTERFACES
    xfrm_ns_str = subprocess.run(
        f"ip -j -n {consts.TRUSTED_NETNS} link",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    xfrm_ns = json.loads(xfrm_ns_str)

    uplinks_diff = {
        x["ifname"] for x in xfrm_ns if x["ifname"].startswith("xfrm-uplink")
    }
    uplinks_ref = {f"xfrm-uplink{x:03}" for x in VPNC_HUB_CONFIG.uplinks.keys()}
    uplinks_remove = uplinks_diff.difference(uplinks_ref)

    # Configure XFRM interfaces for uplinks
    logger.info("Setting up uplink xfrm interfaces for %s netns.", consts.TRUSTED_NETNS)

    for tunnel_id, tunnel_config in VPNC_HUB_CONFIG.uplinks.items():
        uplink_xfrm_cmd = f"""
        # configure XFRM interfaces
        ip -n {consts.UNTRUSTED_NETNS} link add xfrm-uplink{tunnel_id:03} type xfrm dev {VPNC_HUB_CONFIG.untrusted_if_name} if_id 0x9999{tunnel_id:03}
        ip -n {consts.UNTRUSTED_NETNS} link set xfrm-uplink{tunnel_id:03} netns {consts.TRUSTED_NETNS}
        ip -n {consts.TRUSTED_NETNS} link set dev xfrm-uplink{tunnel_id:03} up
        """
        if uplink_tun := tunnel_config.prefix_uplink_tunnel:
            uplink_tun_prefix = ipaddress.IPv6Network(uplink_tun)
            uplink_xfrm_cmd += f"ip -n {consts.TRUSTED_NETNS} address add {uplink_tun_prefix} dev xfrm-uplink{tunnel_id:03}"
        print(uplink_xfrm_cmd)
        # run the commands
        subprocess.run(
            uplink_xfrm_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
    for remove_uplink in uplinks_remove:
        # run the commands
        subprocess.run(
            f"ip -n {consts.TRUSTED_NETNS} link del dev {remove_uplink}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    # IP(6)TABLES RULES
    # The trusted netns blocks all traffic originating from the downlink namespaces,
    # but does accept traffic originating from the default and management zones.
    iptables_template = VPNC_TEMPLATE_ENV.get_template("iptables.conf.j2")
    iptables_configs = {
        "trusted_netns": consts.TRUSTED_NETNS,
        "uplinks": uplinks_ref,
    }
    iptables_render = iptables_template.render(**iptables_configs)
    print(iptables_render)
    subprocess.run(
        iptables_render,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )

    # VPN UPLINKS
    uplink_template = VPNC_TEMPLATE_ENV.get_template("uplink.conf.j2")
    uplink_configs = []
    for tunnel_id, tunnel_config in VPNC_HUB_CONFIG.uplinks.items():
        if tunnel_config.prefix_uplink_tunnel:
            xfrm_ip = ipaddress.IPv6Network(tunnel_config.prefix_uplink_tunnel)[1]
        else:
            xfrm_ip = None

        uplink_configs.append(
            {
                "remote": "uplink",
                "t_id": f"{tunnel_id:03}",
                "remote_peer_ip": tunnel_config.remote_peer_ip,
                "xfrm_id": f"9999{tunnel_id:03}",
                "xfrm_name": f"xfrm-uplink{tunnel_id:03}",
                "xfrm_ip": xfrm_ip,
                "asn": tunnel_config.asn,
                "psk": tunnel_config.psk,
                "local_id": VPNC_HUB_CONFIG.local_id,
                "remote_id": tunnel_config.remote_id,
            }
        )

    uplink_render = uplink_template.render(connections=uplink_configs)
    uplink_path = consts.VPN_CONFIG_DIR.joinpath("uplink.conf")

    with open(uplink_path, "w", encoding="utf-8") as f:
        f.write(uplink_render)

    helpers.load_swanctl_all_config()

    # FRR/BGP CONFIG
    bgp_template = VPNC_TEMPLATE_ENV.get_template("frr-bgp.conf.j2")
    bgp_configs = {
        "trusted_netns": consts.TRUSTED_NETNS,
        "untrusted_netns": consts.UNTRUSTED_NETNS,
        "bgp_router_id": VPNC_HUB_CONFIG.bgp.router_id,
        "bgp_asn": VPNC_HUB_CONFIG.bgp.asn,
        "uplinks": uplink_configs,
        "prefix_uplink": PREFIX_UPLINK,
        "prefix_downlink_v6": PREFIX_DOWNLINK_V6,
    }
    bgp_render = bgp_template.render(**bgp_configs)
    print(bgp_render)
    with open("/etc/frr/frr.conf", "w+", encoding="utf-8") as f:
        f.write(bgp_render)

    # Load the commands in case FRR was already running
    output = subprocess.run(
        "/usr/lib/frr/frr-reload.py /etc/frr/frr.conf --reload --stdout",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout
    logger.debug(output)


def main():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """
    logger.info("#" * 100)
    logger.info("Starting ncubed VPNC strongSwan daemon in hub mode.")

    # write a flag that specifies the run mode.
    with open(consts.VPNC_A_SERVICE_MODE_PATH, "w", encoding="utf-8") as f:
        f.write("---\nmode: hub\n...\n")

    # Load the global configuration from file.
    _load_config(consts.VPNC_A_SERVICE_CONFIG_PATH)

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
    )

    # The untrusted namespace has internet connectivity.
    # After creating this namespace, ipsec is restarted in this namespace.
    # No IPv6 routing is enabled on this namespace.
    # There is no connectivity to other namespaces.
    logger.info("Setting up %s netns", consts.UNTRUSTED_NETNS)
    subprocess.run(
        f"""
        ip netns add {consts.UNTRUSTED_NETNS}
        ip link set {VPNC_HUB_CONFIG.untrusted_if_name} netns {consts.UNTRUSTED_NETNS}
        ip -n {consts.UNTRUSTED_NETNS} address flush dev {VPNC_HUB_CONFIG.untrusted_if_name}
        ip -n {consts.UNTRUSTED_NETNS} address add {VPNC_HUB_CONFIG.untrusted_if_ip} dev {VPNC_HUB_CONFIG.untrusted_if_name}
        ip -n {consts.UNTRUSTED_NETNS} link set dev {VPNC_HUB_CONFIG.untrusted_if_name} up
        ip -n {consts.UNTRUSTED_NETNS} route del default
        ip -n {consts.UNTRUSTED_NETNS} route add default via {VPNC_HUB_CONFIG.untrusted_if_gw}
        ip netns exec {consts.UNTRUSTED_NETNS} ipsec start
        # start NAT64
        modprobe jool
        sleep 5
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    # The trusted namespace has no internet connectivity.
    # IPv6 routing is enabled on the namespace.
    logger.info("Setting up %s netns.", consts.TRUSTED_NETNS)
    subprocess.run(
        f"""
        ip netns add {consts.TRUSTED_NETNS}
        ip netns exec {consts.TRUSTED_NETNS} sysctl -w net.ipv6.conf.all.forwarding=1
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    # Start the VPNC mangle process in the TRUSTED net namespace.
    sp = subprocess.Popen(
        ["ip", "netns", "exec", consts.TRUSTED_NETNS, f"{consts.VPNC_INSTALL_DIR}/bin/vpncmangle"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
    )
    logger.info(sp.args)

    _update_uplink_connection()

    # Start the event handler.
    logger.info("Monitoring uplink config changes.")
    uplink_observer = _uplink_observer()
    uplink_observer.start()

    _update_downlink_connection()

    # Start the event handler.
    logger.info("Monitoring downlink config changes.")
    downlink_observer = _downlink_observer()
    downlink_observer.start()

    # Restart FRR to make sure it can load the namespaces
    logger.info("Restarting FRR.")
    subprocess.run(
        """
        systemctl restart frr.service
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )


if __name__ == "__main__":
    main()
