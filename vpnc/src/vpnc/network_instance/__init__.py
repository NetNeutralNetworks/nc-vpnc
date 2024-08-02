"""
Manages VPN connections and observers used to monitor file changes
"""

import json
import logging
import pathlib
import subprocess
import time

import yaml
from jinja2 import Environment, FileSystemLoader
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from .. import config, frr, helpers, models, strongswan
from . import general

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR))


def add_external_iptables(network_instance: models.NetworkInstance):
    """
    The EXTERNAL network instance blocks all traffic except for IKE, ESP and IPsec.
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-external.conf.j2")
    iptables_configs = {
        "network_instance_name": network_instance.name,
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


def update_core_network_instance():
    """
    Configures the CORE network instance (Linux namespace).
    """

    # Remove network instance connections that aren't configured
    network_instance = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    general.delete_network_instance_connection(network_instance)

    # Configure connection
    logger.info("Setting up core connections for %s network instance.", config.CORE_NI)

    network_instance = config.VPNC_SERVICE_CONFIG.network_instances[config.CORE_NI]
    interfaces = general.add_network_instance_connection(network_instance)

    # IP(6)TABLES RULES
    add_core_iptables(config.VPNC_SERVICE_CONFIG.mode, config.CORE_NI, interfaces)

    # VPN
    logger.info("Setting up VPN tunnels.")
    strongswan.gen_swanctl_cfg(network_instance=network_instance)

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        # FRR
        frr.generate_frr_cfg()


def add_core_iptables(
    mode: models.ServiceMode,
    network_instance_name: str,
    interfaces,
):
    """
    The CORE network instance blocks all traffic originating from the DOWNLINK network instance
    (Linux namespace), but does accept traffic originating from its uplink.
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-core.conf.j2")
    iptables_configs = {
        "mode": mode,
        "network_instance_name": network_instance_name,
        "interfaces": interfaces,
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


def observe_core() -> BaseObserver:
    """
    Create the observer for CORE network instance configuration
    """

    # Define what should happen when the config file with CORE data is modified.
    class CoreHandler(FileSystemEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            helpers.load_config(config.VPNC_A_SERVICE_CONFIG_PATH)
            time.sleep(0.1)
            update_core_network_instance()

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()
    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=CoreHandler(),
        path=config.VPNC_A_SERVICE_CONFIG_PATH,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def update_downlink_network_instance():
    """
    Configures DOWNLINK network instances.
    """

    # TODO: Standardize parsing
    config_files = list(config.VPNC_A_TENANT_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files}
    vpn_config_files = list(
        config.VPN_CONFIG_DIR.glob(pattern="[23456789aAbBcCdDeEfF]*.conf")
    )
    vpn_config_set = {x.stem for x in vpn_config_files}

    for file_path in config_files:
        add_downlink_network_instance(file_path)

    for vpn_id in vpn_config_set.difference(config_set):
        delete_downlink_network_instance(vpn_id)


def add_downlink_network_instance(path: pathlib.Path):
    """
    Configures DOWNLINK connections.
    """

    if not config.DOWNLINK_TEN_RE.match(path.stem):
        logger.error("Invalid filename found in %s. Skipping.", path, exc_info=True)
        return

    # Open the configuration file and check if it's valid YAML.
    with open(path, "r", encoding="utf-8") as f:
        try:
            config_yaml = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
            return

    # Parse the YAML file to a DOWNLINK object and validate the input.
    try:
        tenant = models.Tenant(**config_yaml)
    except (TypeError, ValueError):
        logger.error(
            "Invalid configuration found in '%s'. Skipping.", path, exc_info=True
        )
        return

    if tenant.id != path.stem:
        logger.error(
            "VPN identifier '%s' and configuration file name '%s' do not match. Skipping.",
            tenant.id,
            path.stem,
        )
        return

    # NETWORK INSTANCES AND INTERFACES
    # Get all network instances created for the configuration file
    ip_ni_str = subprocess.run(
        "ip -j netns",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    ip_ni = json.loads(ip_ni_str)

    ni_diff = {x["name"] for x in ip_ni if x["name"].startswith(tenant.id)}
    ni_ref = {
        x.name
        for _, x in tenant.network_instances.items()
        if x.name.startswith(tenant.id)
    }

    # Calculate network instances that need to be removed and remove them.
    ni_remove = ni_diff.difference(ni_ref)
    for ni in ni_remove:
        # delete links to the CORE network instance
        general.delete_network_instance_link(ni)
        # run the network instance remove commands
        general.delete_network_instance(ni)

    logger.info("Setting up tenant %s netns.", tenant.id)
    update_check: list[bool] = []
    for key, network_instance in tenant.network_instances.items():
        if not key.startswith(tenant.id):
            logger.warning(
                "Invalid network instance '%s' found for tenant '%s'.", key, tenant.id
            )
            continue
        if not network_instance.name == key:
            logger.warning(
                "Network instance name '%s' must be the same as key  '%s'.",
                network_instance.name,
                key,
            )
            continue

        core_interfaces = [f"{network_instance.name}_D"]
        downlink_interfaces = general.get_network_instance_connections(network_instance)

        # Create the network instance
        general.add_network_instance(network_instance, cleanup=True)

        # Add a link between the DOWNLINK and CORE network instance
        general.add_network_instance_link(network_instance)

        # Delete unconfigured connections
        general.delete_network_instance_connection(network_instance)

        # Configure NAT64
        general.add_network_instance_nat64(network_instance)

        # IP(6)TABLES RULES including NAT-PT
        updated, _ = add_downlink_iptables(
            config.VPNC_SERVICE_CONFIG.mode,
            network_instance,
            core_interfaces,
            downlink_interfaces,
        )

        update_check.append(updated)
        # VPN
        logger.info("Setting up VPN tunnels.")
        strongswan.gen_swanctl_cfg(network_instance)

    if any(update_check):
        # Check if the configuration file needs to be updated.
        # TODO: check if there is a way to make it so that the file isn't reloaded.
        with open(path, "w", encoding="utf-8") as f:
            output = tenant.model_dump(mode="json")
            try:
                f.write(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
            except yaml.YAMLError:
                logger.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
                return


def delete_downlink_network_instance(vpn_id: str):
    """
    Removes downlink VPN connections.
    """

    if not config.DOWNLINK_TEN_RE.match(vpn_id):
        logger.error("Invalid filename found in %s. Skipping.", vpn_id, exc_info=True)
        return

    # NETWORK INSTANCES
    ip_ni_str = subprocess.run(
        "ip -j netns",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    ).stdout.decode()
    ip_ni = json.loads(ip_ni_str)

    logger.info("Removing all network instance configuration for '%s'.", vpn_id)
    ni_remove = {x["name"] for x in ip_ni if x["name"].startswith(vpn_id)}

    for ni in ni_remove:
        # delete links to the CORE network instance
        general.delete_network_instance_link(ni)
        # run the network instance remove commands
        general.delete_network_instance(ni)

    # remove VPN configs if exist
    logger.info("Removing VPN configuration for '%s'.", vpn_id)
    downlink_path = config.VPN_CONFIG_DIR.joinpath(f"{vpn_id}.conf")
    downlink_path.unlink(missing_ok=True)


def add_downlink_iptables(
    mode: models.ServiceMode,
    network_instance: models.NetworkInstance,
    core_interfaces: list[str],
    downlink_interfaces: list[str],
):
    """
    The DOWNLINK network instance blocks all traffic except for traffic from the CORE network instance and
    ICMPv6
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-downlink.conf.j2")
    updated, natpt_networks = general.get_network_instance_natpt_networks(
        network_instance
    )
    iptables_configs = {
        "mode": mode,
        "network_instance_name": network_instance.name,
        "core_interfaces": core_interfaces,
        "downlink_interfaces": downlink_interfaces,
        "natpt_networks": natpt_networks,
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

    return updated, natpt_networks


def observe_downlink() -> BaseObserver:
    """
    Create the observer for DOWNLINK network instances configuration
    """

    # Define what should happen when DOWNLINK files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            add_downlink_network_instance(downlink_config)

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            add_downlink_network_instance(downlink_config)

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path).stem
            time.sleep(0.1)
            delete_downlink_network_instance(downlink_config)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(patterns=["*.yaml"], ignore_directories=True),
        path=config.VPNC_A_TENANT_CONFIG_DIR,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer
