"""
Manages VPN connections and observers used to monitor file changes
"""

import ipaddress
import json
import logging
import pathlib
import subprocess
import time

import yaml
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from .. import config, helpers, models

logger = logging.getLogger("vpnc")


def gen_swanctl_cfg(
    name: str, id_: int, configs: dict[int, models.Connection | models.ConnectionUplink]
):
    """
    Generates swanctl configurations

    Args:
        name (str): _description_
        id (int): _description_
        configs (dict[str, models.Tunnel  |  models.Uplink]): _description_
        updown (bool, optional): _description_. Defaults to False.
    """

    swanctl_template = config.VPNC_TEMPLATES_ENV.get_template("swanctl.conf.j2")
    swanctl_cfgs = []
    for connection_id, connection_config in configs.items():
        swanctl_cfg = {
            "remote": name,
            "t_id": f"{connection_id:03}",
            "local_id": config.VPNC_SERVICE_CONFIG.local_id,
            "remote_peer_ip": connection_config.connection.remote_peer_ip,
            "remote_id": connection_config.connection.remote_peer_ip,
            "xfrm_id": id_ * 1000 + connection_id,
            "ike_version": connection_config.connection.ike_version,
            "ike_proposal": connection_config.connection.ike_proposal,
            "ike_lifetime": connection_config.connection.ike_lifetime,
            "ipsec_proposal": connection_config.connection.ipsec_proposal,
            "ipsec_lifetime": connection_config.connection.ipsec_lifetime,
            "initiation": connection_config.connection.initiation.value,
            "psk": connection_config.connection.psk,
        }

        # Check for the connection specific remote id
        if connection_config.connection.remote_id is not None:
            swanctl_cfg["remote_id"] = connection_config.connection.remote_id
        # Check for the connection specific local id
        if connection_config.connection.local_id is not None:
            swanctl_cfg["local_id"] = connection_config.connection.local_id

        if connection_config.connection.traffic_selectors:
            ts_loc = ",".join(
                (str(x) for x in connection_config.connection.traffic_selectors.local)
            )
            ts_rem = ",".join(
                (str(x) for x in connection_config.connection.traffic_selectors.remote)
            )
            swanctl_cfg["ts"] = {"local": ts_loc, "remote": ts_rem}

        swanctl_cfgs.append(swanctl_cfg)

    swanctl_render = swanctl_template.render(connections=swanctl_cfgs)
    swanctl_path = config.VPN_CONFIG_DIR.joinpath(f"{name}.conf")

    with open(swanctl_path, "w", encoding="utf-8") as f:
        f.write(swanctl_render)


def load_swanctl_all_config():
    """Load all swanctl strongswan configurations. Cannot find a way to do this with vici"""
    logger.debug("Loading all swanctl connections.")
    output = subprocess.run(
        "swanctl --load-all --clear",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    ).stdout
    logger.debug(output)


def init_swanctl_connection(connection: str):
    """Initiate an IKE/IPsec connection"""
    logger.debug("Initiating connection '%s'.", connection)
    vcs = vici.Session()
    output = vcs.initiate({"ike": connection, "child": connection})
    logger.debug(output)


def term_swanctl_connection(connection: str):
    """Terminate an IKE/IPsec connection"""
    logger.debug("Terminating connection '%s'.", connection)
    vcs = vici.Session()
    output = vcs.terminate({"ike": connection, "child": connection})
    logger.debug(output)


def update_uplink_connection():
    """
    Configures uplinks.
    """

    # XFRM INTERFACES
    # Get all interfaces in the trusted namespace.
    xfrm_ns_str: str = subprocess.run(
        f"ip -j -n {config.TRUSTED_NETNS} link",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    xfrm_ns: dict = json.loads(xfrm_ns_str)

    # Active XFRM interfaces connected to the provider.
    uplinks_diff: set[str] = {
        x["ifname"] for x in xfrm_ns if x["ifname"].startswith("xfrm-uplink")
    }
    # Configured XFRM interfaces for provider connections.
    uplinks_ref: set[str] = {
        f"xfrm-uplink{x:03}" for x in config.VPNC_SERVICE_CONFIG.connections
    }
    uplinks_remove: set[str] = uplinks_diff.difference(uplinks_ref)

    # Configure XFRM interfaces for uplinks
    logger.info("Setting up uplink xfrm interfaces for %s netns.", config.TRUSTED_NETNS)

    for (
        connection_id,
        connection_config,
    ) in config.VPNC_SERVICE_CONFIG.connections.items():
        uplink_xfrm_cmd = f"""
        # Configure XFRM interfaces. Use 9999 as the customer identifier when the provider side is concerned.
        ip -n {config.UNTRUSTED_NETNS} link add xfrm-uplink{connection_id:03} type xfrm dev {config.VPNC_SERVICE_CONFIG.network.untrust.interface} if_id 0x9999{connection_id:03}
        ip -n {config.UNTRUSTED_NETNS} link set xfrm-uplink{connection_id:03} netns {config.TRUSTED_NETNS}
        ip -n {config.TRUSTED_NETNS} link set dev xfrm-uplink{connection_id:03} up
        """
        # Add the configured IPv6 address to the XFRM interface.
        if uplink_tun := connection_config.interface_ip:
            uplink_tun_prefix = ipaddress.IPv6Network(uplink_tun, strict=False)
            uplink_xfrm_cmd += f"ip -n {config.TRUSTED_NETNS} address add {uplink_tun_prefix} dev xfrm-uplink{connection_id:03}"
        # run the commands
        sp = subprocess.run(
            uplink_xfrm_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        logger.info(sp.stdout)
    for remove_uplink in uplinks_remove:
        # run the commands
        subprocess.run(
            f"ip -n {config.TRUSTED_NETNS} link del dev {remove_uplink}",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )

    # IP(6)TABLES RULES
    # The trusted netns blocks all traffic originating from the downlink namespaces,
    # but does accept traffic originating from the default and management zones.
    iptables_template = config.VPNC_TEMPLATES_ENV.get_template(
        "iptables-uplink.conf.j2"
    )
    iptables_configs = {
        "trusted_netns": config.TRUSTED_NETNS,
        "uplinks": uplinks_ref,
    }
    iptables_render = iptables_template.render(**iptables_configs)
    logger.info(iptables_render)
    subprocess.run(
        iptables_render,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )

    # VPN
    gen_swanctl_cfg(
        name="uplink",
        id_=9999,
        configs=config.VPNC_SERVICE_CONFIG.connections,
    )

    load_swanctl_all_config()

    # FRR
    helpers.generate_frr_cfg(configs=config.VPNC_SERVICE_CONFIG.connections)

    # Load the commands in FRR
    helpers.load_frr_all_config()


def add_downlink_connection_ipsec(netns, vpn_id_int, tunnel_id, v4_downlink_tunnel_ip):
    """
    Creates a downlink XFRM interface
    """
    xfrm = f"xfrm-{netns}"
    xfrm_id = int(vpn_id_int) * 1000 + int(tunnel_id)
    sp = subprocess.run(
        f"""
            # configure XFRM interfaces
            ip -n {config.UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {config.VPNC_SERVICE_CONFIG.network.untrust.interface} if_id 0x{xfrm_id}
            ip -n {config.UNTRUSTED_NETNS} link set {xfrm} netns {netns}
            ip -n {netns} link set dev {xfrm} up
            ip -n {netns} -4 address flush dev {xfrm}
            ip -n {netns} -6 address flush dev {xfrm}
            ip -n {netns} address add {v4_downlink_tunnel_ip} dev {xfrm}
            ip -n {netns} route add 0.0.0.0/0 dev {xfrm}
            ip -n {netns} route add ::/0 dev {xfrm}
            """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(sp.args)
    logger.info(sp.stdout.decode())


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
        remote_config = models.Remote(**config_yaml)
    except (TypeError, ValueError):
        logger.error(
            "Invalid configuration found in '%s'. Skipping.", path, exc_info=True
        )
        return

    # Get the downlink ID. This must match the file name.
    vpn_id = remote_config.id
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
    netns_ref = {f"{vpn_id}-{x:03}" for x in remote_config.connections}
    netns_remove = netns_diff.difference(netns_ref)

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

    # Configure XFRM interfaces for downlinks
    logger.info("Setting up uplink xfrm interfaces for %s netns.", config.TRUSTED_NETNS)
    for tunnel_id, t_config in remote_config.connections.items():
        netns = f"{vpn_id}-{tunnel_id:03}"

        veth_i = f"{netns}_I"
        veth_e = f"{netns}_E"

        v6_segment_3 = vpn_id[0]  # outputs c
        v6_segment_4 = int(vpn_id_int)  # outputs 1
        v6_segment_5 = int(tunnel_id)  # outputs 0
        # outputs fdcc:0:c:1:0
        v6_downlink_space = f"{config.VPNC_SERVICE_CONFIG.prefix_downlink_v6.exploded[:9]}:{v6_segment_3}:{v6_segment_4}:{v6_segment_5}"

        if t_config.interface_ip:
            v4_downlink_tunnel_ip = t_config.interface_ip
        else:
            v4_downlink_tunnel_offset = ipaddress.IPv4Address(f"0.0.{int(tunnel_id)}.1")
            v4_downlink_tunnel_ip = ipaddress.IPv4Address(
                int(config.VPNC_SERVICE_CONFIG.prefix_downlink_v4[0])
                + int(v4_downlink_tunnel_offset)
            )
            v4_downlink_tunnel_ip = f"{v4_downlink_tunnel_ip}/24"

        sp = subprocess.run(
            f"""
            ip netns add {netns}
            # enable routing
            ip netns exec {netns} sysctl -w net.ipv4.conf.all.forwarding=1
            ip netns exec {netns} sysctl -w net.ipv6.conf.all.forwarding=1
            # add veth interfaces between TRUSTED and DOWNLINK network namespaces
            ip -n {config.TRUSTED_NETNS} link add {veth_i} type veth peer name {veth_e} netns {netns}
            # bring veth interfaces up
            ip -n {config.TRUSTED_NETNS} link set dev {veth_i} up
            ip -n {netns} link set dev {veth_e} up
            # assign IP addresses to veth interfaces
            ip -n {config.TRUSTED_NETNS} -6 address add fe80::0/64 dev {veth_i}
            ip -n {netns} -6 address add fe80::1/64 dev {veth_e}
            # add route from DOWNLINK to MGMT network via TRUSTED namespace
            ip -n {netns} -6 route add {config.VPNC_SERVICE_CONFIG.prefix_uplink} via fe80::0 dev {veth_e}
            # start NAT64
            ip netns exec {netns} jool instance add {netns} --netfilter --pool6 {v6_downlink_space}::/96
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        logger.info(sp.args)
        logger.info(sp.stdout.decode())

        # IP(6)TABLES RULES
        # The customer netns blocks all traffic except for traffic from the TRUSTED namespace and
        # ICMPv6
        iptables_template = config.VPNC_TEMPLATES_ENV.get_template(
            "iptables-downlink.conf.j2"
        )
        iptables_configs = {"netns": netns, "veth": veth_e}
        iptables_render = iptables_template.render(**iptables_configs)
        logger.info(iptables_render)
        subprocess.run(
            iptables_render,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=True,
        )

        add_downlink_connection_ipsec(
            netns, vpn_id_int, tunnel_id, v4_downlink_tunnel_ip
        )

    # VPN
    logger.info("Setting up VPN tunnels.")
    gen_swanctl_cfg(
        name=vpn_id,
        id_=vpn_id_int,
        configs=remote_config.connections,
    )

    load_swanctl_all_config()


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

    logger.info("Removing all namespace configuration for '%s'.", vpn_id)
    netns_remove = {x["name"] for x in ip_netns if x["name"].startswith(vpn_id)}

    for netns in netns_remove:
        term_swanctl_connection(netns)
        # run the netns remove commands
        sp = subprocess.run(
            f"""
            ip -n {netns}
            # remove NAT64
            ip netns exec {netns} jool instance remove {netns}
            # remove netns
            ip netns del {netns}
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        ).stdout
        logger.info(sp)

    logger.info("Removing VPN configuration for '%s'.", vpn_id)
    downlink_path = config.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    downlink_path.unlink(missing_ok=True)

    load_swanctl_all_config()


def update_downlink_connection():
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


def add_downlink_connection_endpoint(path: pathlib.Path):
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
        remote_config = models.Remote(**config_yaml)
    except (TypeError, ValueError):
        logger.error(
            "Invalid configuration found in '%s'. Skipping.", path, exc_info=True
        )
        return

    # Get the downlink ID. This must match the file name.
    vpn_id = remote_config.id
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
    xfrm_ref = {f"xfrm-{vpn_id}-{x:03}" for x in remote_config.connections}
    xfrm_remove = xfrm_diff.difference(xfrm_ref)

    # Configure XFRM interfaces for downlinks
    logger.info("Setting up downlink xfrm interfaces.")
    for tunnel_id, tunnel_config in remote_config.connections.items():
        xfrm = f"xfrm-{vpn_id}-{tunnel_id:03}"
        xfrm_id = int(vpn_id_int) * 1000 + int(tunnel_id)

        cmd = f"""
        # configure XFRM interfaces
        ip -n {config.UNTRUSTED_NETNS} link add {xfrm} type xfrm dev {config.VPNC_SERVICE_CONFIG.network.untrust.interface} if_id 0x{xfrm_id}
        ip -n {config.UNTRUSTED_NETNS} link set {xfrm} netns 1
        ip link set dev {xfrm} up
        ip -4 address flush dev {xfrm}
        ip -6 address flush dev {xfrm}
        """
        for i in tunnel_config.connection.traffic_selectors.remote:
            cmd += f"\nip route add {i} dev {xfrm}"
        for i in tunnel_config.connection.routes:
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

    # VPN
    logger.info("Setting up VPN tunnels.")
    gen_swanctl_cfg(
        name=vpn_id,
        id_=vpn_id_int,
        configs=remote_config.connections,
    )

    load_swanctl_all_config()


def delete_downlink_connection_endpoint(vpn_id: str):
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
        term_swanctl_connection(xfrm)
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

    load_swanctl_all_config()


def update_downlink_connection_endpoint():
    """
    Configures downlinks.
    """
    config_files = list(config.VPNC_A_REMOTE_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files}
    vpn_config_files = list(config.VPN_CONFIG_DIR.glob(pattern="[aAbBcCdDeEfF]*.conf"))
    vpn_config_set = {x.stem for x in vpn_config_files}

    for file_path in config_files:
        add_downlink_connection_endpoint(file_path)

    for vpn_id in vpn_config_set.difference(config_set):
        delete_downlink_connection_endpoint(vpn_id)


def uplink_observer() -> BaseObserver:
    """
    Create the observer for uplink connections configuration
    """

    # Define what should happen when the config file with uplink data is modified.
    class UplinkHandler(FileSystemEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            helpers.load_config(config.VPNC_A_SERVICE_CONFIG_PATH)
            time.sleep(0.1)
            vpn.update_uplink_connection()

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()
    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=UplinkHandler(),
        path=config.VPNC_A_SERVICE_CONFIG_PATH,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def downlink_observer() -> BaseObserver:
    """
    Create the observer for downlink connections configuration
    """
    if config.VPNC_SERVICE_CONFIG.mode.name == "HUB":
        add_downlink = add_downlink_connection
        del_downlink = delete_downlink_connection
    else:
        add_downlink = add_downlink_connection_endpoint
        del_downlink = delete_downlink_connection_endpoint

    # Define what should happen when downlink files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            add_downlink(downlink_config)

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            add_downlink(downlink_config)

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path).stem
            del_downlink(downlink_config)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(
            patterns=["[aAbBcCdDeEfF]*.yaml"], ignore_directories=True
        ),
        path=config.VPNC_A_REMOTE_CONFIG_DIR,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer
