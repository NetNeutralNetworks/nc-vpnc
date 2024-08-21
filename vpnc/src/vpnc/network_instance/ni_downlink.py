"""
Code to manage DOWNLINK network instances.
"""

import json
import logging
import pathlib
import subprocess
import time

import yaml
from jinja2 import Environment, FileSystemLoader
from watchdog.events import FileSystemEvent, PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from .. import config, helpers, models, strongswan, vpncmangle
from . import general

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR))


def observe_downlink() -> BaseObserver:
    """
    Create the observer for DOWNLINK network instances configuration
    """

    # Define what should happen when DOWNLINK files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileSystemEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            add_downlink_network_instance(downlink_config)

        def on_modified(self, event: FileSystemEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            add_downlink_network_instance(downlink_config)

        def on_deleted(self, event: FileSystemEvent):
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
    # The handler should exit on main thread close
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

    if not (tenant := helpers.load_tenant_config(path)):
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
        for _, x in tenant.network_instances.items()  # pylint: disable=no-member
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
    for (
        key,
        network_instance,
    ) in tenant.network_instances.items():  # pylint: disable=no-member
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
        add_downlink_nat64(network_instance)

        # IP(6)TABLES RULES including NPTv6
        updated, _ = add_downlink_iptables(
            config.VPNC_SERVICE_CONFIG.mode,
            network_instance,
            core_interfaces,
            downlink_interfaces,
        )

        update_check.append(updated)
        # VPN
        logger.info("Setting up VPN tunnels.")
        strongswan.generate_config(network_instance)

    if config.VPNC_SERVICE_CONFIG.mode == models.ServiceMode.HUB:
        # FRR
        vpncmangle.generate_config()

    if any(update_check):
        # Check if the configuration file needs to be updated.
        # TODO: check if there is a way to make it so that the file isn't reloaded.
        file_name = path.name
        candidate_config = path.parent.parent.parent.joinpath(
            "candidate", "tenant", file_name
        )
        with open(path, "w", encoding="utf-8") as fha, open(
            candidate_config, "w", encoding="utf-8"
        ) as fhb:
            output = tenant.model_dump(mode="json")
            try:
                fha.write(
                    yaml.safe_dump(output, explicit_start=True, explicit_end=True)
                )
            except yaml.YAMLError:
                logger.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
                return
            try:
                fhb.write(
                    yaml.safe_dump(output, explicit_start=True, explicit_end=True)
                )
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

    config.VPNC_TENANT_CONFIG.pop(vpn_id, None)
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


def add_downlink_nat64(network_instance: models.NetworkInstance) -> None:
    """
    Add NAT64 rules to a network instance (Linux namespace).
    """
    if config.VPNC_SERVICE_CONFIG.mode != models.ServiceMode.HUB:
        return

    nat64_scope = general.get_network_instance_nat64_scope(network_instance.name)

    # configure NAT64 for the DOWNLINK network instance
    output_nat64 = subprocess.run(
        f"""
        # start NAT64
        ip netns exec {network_instance.name} jool instance flush
        ip netns exec {network_instance.name} jool instance add {network_instance.name} --netfilter --pool6 {nat64_scope}
        """,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )
    logger.info(output_nat64.args)
    logger.info(output_nat64.stdout.decode())


def get_network_instance_nptv6_networks(
    network_instance: models.NetworkInstance,
) -> tuple[bool, list[models.RouteIPv6]]:
    """
    Calculates the NPTv6 translations to perform for a network instance (Linux namespace).
    """

    updated = False
    nptv6_list: list[models.RouteIPv6] = []
    if config.VPNC_SERVICE_CONFIG.mode != models.ServiceMode.HUB:
        return updated, nptv6_list
    if network_instance.type != models.NetworkInstanceType.DOWNLINK:
        return updated, nptv6_list

    # Get NPTv6 prefix for this network instance
    nptv6_scope = general.get_network_instance_nptv6_scope(network_instance.name)

    for connection in network_instance.connections:
        nptv6_list.extend(
            [route for route in connection.routes.ipv6 if route.nptv6 is True]
        )

    # Calculate how to perform the NPTv6 translation.
    for configured_nptv6 in nptv6_list:
        nptv6_prefix = configured_nptv6.to.prefixlen
        # Check if the translation is possibly correct. This is a basic check
        if (
            configured_nptv6.nptv6_prefix
            and configured_nptv6.to.prefixlen == configured_nptv6.nptv6_prefix.prefixlen
        ):
            if configured_nptv6.nptv6_prefix.subnet_of(nptv6_scope):
                logger.debug(
                    "Route '%s' already has NPTv6 prefix '%s'",
                    configured_nptv6.to,
                    configured_nptv6.nptv6_prefix,
                )
                continue
            logger.warning(
                "Route '%s' has invalid NPTv6 prefix '%s' applied. Not part of assigned scope '%s'. Recalculating",
                configured_nptv6.to,
                configured_nptv6.nptv6_prefix,
                nptv6_scope,
            )
            configured_nptv6.nptv6_prefix = None
        if (
            configured_nptv6.nptv6_prefix
            and configured_nptv6.to.prefixlen < nptv6_scope.prefixlen
        ):
            logger.warning(
                "Route '%s' is too big for NPTv6 scope '%s'. Ignoring",
                configured_nptv6.to,
                nptv6_scope,
            )
            continue

        # Calculate the NPTv6 translations if not already calculated.
        for candidate_nptv6_prefix in nptv6_scope.subnets(new_prefix=nptv6_prefix):
            # if the highest IP of the subnet is lower than the most recently added network
            free = True
            for npt in nptv6_list:
                if not npt.nptv6_prefix:
                    continue
                # Check to be sure that the subnet isn't a supernet. That would break it
                # otherwise.
                if not npt.nptv6_prefix.subnet_of(nptv6_scope):
                    continue
                # If the addresses overlap, it isn't free and cannot be used.
                if (
                    npt.nptv6_prefix[0]
                    >= candidate_nptv6_prefix[-1]
                    >= npt.nptv6_prefix[-1]
                    or npt.nptv6_prefix[0]
                    <= candidate_nptv6_prefix[0]
                    <= npt.nptv6_prefix[-1]
                ):
                    free = False
                    break

            if not free:
                continue

            configured_nptv6.nptv6_prefix = candidate_nptv6_prefix
            updated = True
            break

    return updated, [x for x in nptv6_list if x.nptv6_prefix]


def add_downlink_iptables(
    mode: models.ServiceMode,
    network_instance: models.NetworkInstance,
    core_interfaces: list[str],
    downlink_interfaces: list[str],
):
    """
    The DOWNLINK network instance blocks all traffic except for traffic from the CORE network
    instance and ICMPv6
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-downlink.conf.j2")
    updated, nptv6_networks = get_network_instance_nptv6_networks(network_instance)
    iptables_configs = {
        "mode": mode,
        "network_instance_name": network_instance.name,
        "core_interfaces": core_interfaces,
        "downlink_interfaces": downlink_interfaces,
        "nptv6_networks": nptv6_networks,
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

    return updated, nptv6_networks
