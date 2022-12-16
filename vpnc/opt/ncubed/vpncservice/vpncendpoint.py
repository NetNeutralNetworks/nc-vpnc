#!/usr/bin/env python3

import json
import logging
import pathlib
import subprocess
import time

import sys

import yaml
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer

from . import vpncdata, vpnchelpers, vpncglobals

# Global variable containing the configuration items. Should probably be a class.
VPNC_HUB_CONFIG: vpncdata.Service = vpncdata.Service()


def _load_config(config_path: pathlib.Path):
    """
    Load the global configuration.
    """
    global VPNC_HUB_CONFIG

    error = False
    new_cfg: vpncdata.Service = vpncdata.Service()
    with open(config_path, "r", encoding="utf-8") as f:
        try:
            new_cfg_dict = yaml.safe_load(f)
            new_cfg = vpncdata.Service(**new_cfg_dict)
        except yaml.YAMLError:
            error = True
        except TypeError:
            error = True
    if error:
        logging.critical(
            "Configuration is not valid '%s'.",
            config_path,
            exc_info=True,
        )
        sys.exit(1)
    else:
        VPNC_HUB_CONFIG = new_cfg
        logging.info("Loaded new configuration.")


def _downlink_observer() -> Observer:
    # Define what should happen when downlink files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logging.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            _add_downlink_connection(downlink_config)

        def on_modified(self, event: FileModifiedEvent):
            logging.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(1)
            _add_downlink_connection(downlink_config)

        def on_deleted(self, event: FileDeletedEvent):
            logging.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path).stem
            _delete_downlink_connection(downlink_config)

    # Create the observer object. This doesn't start the handler.
    observer = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(patterns=["c*.yaml"], ignore_directories=True),
        path=vpncglobals.VPNC_REMOTE_CONFIG_DIR,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def _add_downlink_connection(path: pathlib.Path):
    """
    Configures downlink VPN connections.
    """

    # Open the configuration file and check if it's valid YAML.
    with open(path, "r", encoding="utf-8") as f:
        try:
            config_yaml = yaml.safe_load(f)
        except yaml.YAMLError:
            logging.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
            return

    # Parse the YAML file to a Downlink object and validate the input.
    try:
        config = vpncdata.Downlink(**config_yaml)
    except (TypeError, ValueError):
        logging.error(
            "Invalid configuration found in '%s'. Skipping.", path, exc_info=True
        )
        return

    # Get the downlink ID. This must match the file name.
    vpn_id = config.id
    vpn_id_int = int(vpn_id[1:])

    if vpn_id != path.stem:
        logging.error(
            "VPN identifier '%s' and configuration file name '%s' do not match. Skipping.",
            vpn_id,
            path.stem,
        )
        return

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
    xfrm_ref = {f"xfrm-{vpn_id}-{x:03}" for x in config.tunnels.keys()}
    xfrm_remove = xfrm_diff.difference(xfrm_ref)

    # Configure XFRM interfaces for downlinks
    logging.info("Setting up uplink xfrm interfaces.")
    for tunnel_id, tunnel_config in config.tunnels.items():
        xfrm = f"xfrm-{vpn_id}-{tunnel_id:03}"
        xfrm_id = int(vpn_id_int) * 1000 + int(tunnel_id)

        cmd = f"""
        # configure XFRM interfaces
        ip -n {vpncglobals.UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {VPNC_HUB_CONFIG.untrusted_if_name} if_id 0x{xfrm_id}
        ip -n {vpncglobals.UNTRUSTED_NETNS} link set {xfrm} netns 1
        ip link set dev {xfrm} up
        """
        for i in tunnel_config.traffic_selectors.remote:
            cmd += f"\nip route add {i} dev xfrm"
        for i in tunnel_config.routes:
            cmd += f"\nip route add {i} dev xfrm"

        subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    logging.info("Removing old uplink xfrm interfaces.")
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
    logging.info("Setting up VPN tunnels.")
    downlink_template = vpncglobals.VPNC_TEMPLATE_ENV.get_template("downlink.conf.j2")
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

    downlink_render = downlink_template.render(connections=downlink_configs)
    downlink_path = vpncglobals.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")

    with open(downlink_path, "w", encoding="utf-8") as f:
        f.write(downlink_render)

    vpnchelpers.load_swanctl_all_config()


def _delete_downlink_connection(vpn_id: str):
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

    logging.info("Removing all namespace configuration for '%s'.", vpn_id)
    xfrm_remove = {
        x["ifname"] for x in ip_xfrm if x["ifname"].startswith(f"xfrm-{vpn_id}")
    }

    for xfrm in xfrm_remove:
        vpnchelpers.terminate_swanctl_connection(xfrm)
        # run the link remove commands
        subprocess.run(
            f"ip link del {xfrm}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    logging.info("Removing VPN configuration for '%s'.", vpn_id)
    downlink_path = vpncglobals.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    downlink_path.unlink(missing_ok=True)

    vpnchelpers.load_swanctl_all_config()


def _update_endpoint_downlink_connection():
    """
    Configures downlinks.
    """
    config_files = list(vpncglobals.VPNC_REMOTE_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files}
    vpn_config_files = list(vpncglobals.VPN_CONFIG_DIR.glob(pattern="*.conf"))
    vpn_config_set = {x.stem for x in vpn_config_files}

    for file_path in config_files:
        _add_downlink_connection(file_path)

    for vpn_id in vpn_config_set.difference(config_set):
        _delete_downlink_connection(vpn_id)


def main():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """
    logging.info("#" * 100)
    logging.info("Starting ncubed VPNC strongSwan daemon in endpoint mode.")

    # write a flag that specifies the run mode. This is used by the CLI to determine the
    # capabilities.
    with open(vpncglobals.VPNC_SERVICE_MODE_PATH, "w", encoding="utf-8") as f:
        f.write("---\nmode: endpoint\n...\n")

    # Load the global configuration from file.
    _load_config(vpncglobals.VPNC_SERVICE_CONFIG_PATH)

    # Mounts the default network namespace with the alias ROOT. This makes for consistent operation
    # between all namespaces
    logging.info("Mounting default namespace as ROOT")
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
    # After creating this namespace, ipsec is (re)started in this namespace.
    # No IPv6 routing is enabled on this namespace.
    # There is no connectivity to other namespaces.
    logging.info("Setting up %s netns", vpncglobals.UNTRUSTED_NETNS)
    subprocess.run(
        f"""
        ip netns add {vpncglobals.UNTRUSTED_NETNS}
        ip link set {VPNC_HUB_CONFIG.untrusted_if_name} netns {vpncglobals.UNTRUSTED_NETNS}
        ip -n {vpncglobals.UNTRUSTED_NETNS} address add {VPNC_HUB_CONFIG.untrusted_if_ip} dev {VPNC_HUB_CONFIG.untrusted_if_name}
        ip -n {vpncglobals.UNTRUSTED_NETNS} link set dev {VPNC_HUB_CONFIG.untrusted_if_name} up
        ip -n {vpncglobals.UNTRUSTED_NETNS} route add default via {VPNC_HUB_CONFIG.untrusted_if_gw}
        ip netns exec {vpncglobals.UNTRUSTED_NETNS} ipsec start
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    # Enable IPv6 and IPv4 on the default namespace.
    logging.info("Setting up ROOT netns.")
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

    _update_endpoint_downlink_connection()

    # Start the event handler.
    logging.info("Monitoring downlink config changes.")
    downlink_observer = _downlink_observer()
    downlink_observer.start()


if __name__ == "__main__":
    main()
