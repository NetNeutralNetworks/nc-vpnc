#!/usr/bin/env python3
"""
Runs the service in endpoint mode
"""


import json
import logging
import pathlib
import subprocess

import yaml

from . import config, helpers, models, observers

logger = logging.getLogger("vpnc")


# Global variable containing the configuration items. Should probably be a class.
config.VPNC_SERVICE_CONFIG = models.Service()


def add_downlink_connection(path: pathlib.Path):
    """
    Configures downlink VPN connections.
    """

    # Open the configuration file and check if it's valid YAML.
    with open(path, "r", encoding="utf-8") as f:
        try:
            config_yaml = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
            return

    # Parse the YAML file to a Downlink object and validate the input.
    try:
        config = models.Remote(**config_yaml)
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

    # XFRM INTERFACES
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
    xfrm_ref = {f"xfrm-{vpn_id}-{x:03}" for x in config.tunnels}
    xfrm_remove = xfrm_diff.difference(xfrm_ref)

    # Configure XFRM interfaces for downlinks
    logger.info("Setting up downlink xfrm interfaces.")
    for tunnel_id, tunnel_config in config.tunnels.items():
        xfrm = f"xfrm-{vpn_id}-{tunnel_id:03}"
        xfrm_id = int(vpn_id_int) * 1000 + int(tunnel_id)

        cmd = f"""
        # configure XFRM interfaces
        ip -n {config.UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {config.VPNC_SERVICE_CONFIG.untrusted_if_name} if_id 0x{xfrm_id}
        ip -n {config.UNTRUSTED_NETNS} link set {xfrm} netns 1
        ip link set dev {xfrm} up
        """
        for i in tunnel_config.traffic_selectors.remote:
            cmd += f"\nip route add {i} dev {xfrm}"
        for i in tunnel_config.routes:
            cmd += f"\nip route add {i} dev {xfrm}"

        subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    logger.info("Removing old uplink xfrm interfaces.")
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
    logger.info("Setting up VPN tunnels.")
    downlink_template = config.VPNC_TEMPLATES_ENV.get_template("downlink.conf.j2")
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

        t_config["local_id"] = config.VPNC_SERVICE_CONFIG.local_id
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
    downlink_path = config.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")

    with open(downlink_path, "w", encoding="utf-8") as f:
        f.write(downlink_render)

    helpers.load_swanctl_all_config()


def _update_downlink_connection():
    """
    Configures downlinks.
    """
    config_files = list(config.VPNC_A_REMOTE_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files}
    vpn_config_files = list(config.VPN_CONFIG_DIR.glob(pattern="[aAbBcCdDeEfF]*.conf"))
    vpn_config_set = {x.stem for x in vpn_config_files}

    for file_path in config_files:
        add_downlink_connection(file_path)

    for vpn_id in vpn_config_set.difference(config_set):
        delete_downlink_connection(vpn_id)


def delete_downlink_connection(vpn_id: str):
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

    logger.info("Removing all tunnel configuration for '%s'.", vpn_id)
    xfrm_remove = {
        x["ifname"] for x in ip_xfrm if x["ifname"].startswith(f"xfrm-{vpn_id}")
    }

    for xfrm in xfrm_remove:
        helpers.terminate_swanctl_connection(xfrm)
        # run the link remove commands
        subprocess.run(
            f"ip link del {xfrm}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    logger.info("Removing VPN configuration for '%s'.", vpn_id)
    downlink_path = config.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    downlink_path.unlink(missing_ok=True)

    helpers.load_swanctl_all_config()


def main():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """
    logger.info("#" * 100)
    logger.info("Starting ncubed VPNC strongSwan daemon in endpoint mode.")

    # Set a flag that specifies the run mode.
    config.VPNC_SERVICE_MODE = models.ServiceMode("endpoint")
    # Load the global configuration from file.
    helpers.load_config(config.VPNC_A_SERVICE_CONFIG_PATH)

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
    # After creating this namespace, ipsec is (re)started in this namespace.
    # No IPv6 routing is enabled on this namespace.
    # There is no connectivity to other namespaces.
    logger.info("Setting up %s netns", config.UNTRUSTED_NETNS)
    subprocess.run(
        f"""
        ip netns add {config.UNTRUSTED_NETNS}
        ip link set {config.VPNC_SERVICE_CONFIG.untrusted_if_name} netns {config.UNTRUSTED_NETNS}
        ip -n {config.UNTRUSTED_NETNS} address flush dev {config.VPNC_SERVICE_CONFIG.untrusted_if_name}
        ip -n {config.UNTRUSTED_NETNS} address add {config.VPNC_SERVICE_CONFIG.untrusted_if_ip} dev {config.VPNC_SERVICE_CONFIG.untrusted_if_name}
        ip -n {config.UNTRUSTED_NETNS} link set dev {config.VPNC_SERVICE_CONFIG.untrusted_if_name} up
        ip -n {config.UNTRUSTED_NETNS} route del default
        ip -n {config.UNTRUSTED_NETNS} route add default via {config.VPNC_SERVICE_CONFIG.untrusted_if_gw}
        ip netns exec {config.UNTRUSTED_NETNS} ipsec start
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )

    # Enable IPv6 and IPv4 on the default namespace.
    logger.info("Setting up ROOT netns.")
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

    _update_downlink_connection()

    # Start the event handler.
    logger.info("Monitoring downlink config changes.")
    downlink_observer = observers.downlink_observer()
    downlink_observer.start()


if __name__ == "__main__":
    main()
