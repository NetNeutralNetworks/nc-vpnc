"""Code to manage DOWNLINK network instances."""

from __future__ import annotations

import json
import logging
import pathlib
import subprocess
import time
from typing import TYPE_CHECKING

import yaml
from jinja2 import Environment, FileSystemLoader
from watchdog.events import (
    FileSystemEvent,
    RegexMatchingEventHandler,
)
from watchdog.observers import Observer

from vpnc import config, helpers, models
from vpnc.network_instance import general
from vpnc.services import strongswan, vpncmangle

if TYPE_CHECKING:
    from watchdog.observers.api import BaseObserver

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


def observe_downlink() -> BaseObserver:
    """Create the observer for DOWNLINK network instances configuration."""

    # Define what should happen when DOWNLINK files are created, modified or deleted.
    class DownlinkHandler(RegexMatchingEventHandler):
        """Handler for the event monitoring."""

        def on_created(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            manage_downlink_network_instance(downlink_config)

        def on_modified(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            manage_downlink_network_instance(downlink_config)

        def on_deleted(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path).stem
            time.sleep(0.1)
            delete_downlink_network_instance(downlink_config)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories.
    # This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(
            regexes=[config.DOWNLINK_TEN_FILE_RE],
            ignore_directories=True,
        ),
        path=config.VPNC_A_CONFIG_DIR,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


def manage_downlink_tenants() -> None:
    """Configure DOWNLINK network instances."""
    # TODO@draggeta: Standardize parsing
    config_files = list(config.VPNC_A_CONFIG_DIR.glob(pattern="*.yaml"))
    config_set = {x.stem for x in config_files if x.stem != config.DEFAULT_TENANT}
    vpn_config_files = list(
        config.VPN_CONFIG_DIR.glob(pattern="[23456789aAbBcCdDeEfF]*.conf"),
    )
    vpn_config_set = {
        x.stem for x in vpn_config_files if x.stem != config.DEFAULT_TENANT
    }

    for vpn_id in vpn_config_set.difference(config_set):
        delete_downlink_network_instance(vpn_id)

    for file_path in config_files:
        manage_downlink_network_instance(file_path)


def manage_downlink_network_instance(path: pathlib.Path) -> None:
    """Configure DOWNLINK connections."""
    if not (tenant_info := helpers.load_tenant_config(path)):
        return

    tenant, active_tenant = tenant_info
    if not tenant:
        return

    if not active_tenant:
        active_network_instance_ids: set[str] = set()
    else:
        active_network_instance_ids = {
            x.id for x in active_tenant.network_instances.values()
        }
    network_instance_ids = {x.id for x in tenant.network_instances.values()}  # pylint: disable=no-member

    # Calculate network instances that need to be removed and remove them.
    ni_remove = active_network_instance_ids.difference(network_instance_ids)
    for ni in ni_remove:
        # delete links to the CORE network instance
        general.delete_network_instance_link(ni)
        # run the network instance remove commands
        general.delete_network_instance(ni)

    logger.info("Setting up tenant %s netns.", tenant.id)
    active_tenant_network_instances: dict[str, models.NetworkInstance] = {}
    if active_tenant:
        active_tenant_network_instances = active_tenant.network_instances
    update_check: list[bool] = [
        set_downlink_network_instance(
            network_instance,
            active_tenant_network_instances.get(network_instance.id),
        )
        for network_instance in tenant.network_instances.values()
    ]

    if config.VPNC_CONFIG_SERVICE.mode == models.ServiceMode.HUB:
        # DNS mangling
        vpncmangle.generate_config()

    if any(update_check):
        # Check if the configuration file needs to be updated.
        # TODO@draggeta: check if there is a way to make it so that the file isn't
        # reloaded.
        file_name = path.name
        candidate_config = path.parent.parent.joinpath(
            "candidate",
            file_name,
        )
        with path.open("w", encoding="utf-8") as fha, candidate_config.open(
            "w",
            encoding="utf-8",
        ) as fhb:
            output = tenant.model_dump(mode="json")
            try:
                fha.write(
                    yaml.safe_dump(output, explicit_start=True, explicit_end=True),
                )
            except yaml.YAMLError:
                logger.exception("Invalid YAML found in %s. Skipping.", path)
                return
            try:
                fhb.write(
                    yaml.safe_dump(output, explicit_start=True, explicit_end=True),
                )
            except yaml.YAMLError:
                logger.exception("Invalid YAML found in %s. Skipping.", path)
                return


def set_downlink_network_instance(
    network_instance: models.NetworkInstance,
    active_network_instance: models.NetworkInstance | None,
) -> bool:
    """Configure the DOWNLINKnetwork instance (Linux namespace)."""
    if network_instance == active_network_instance:
        logger.info(
            "Network instance '%s' is already in the correct state",
            network_instance.id,
        )
        return False

    # Set the network instance
    general.set_network_instance(
        network_instance,
        active_network_instance,
        cleanup=True,
    )

    # Configure NAT64
    add_downlink_nat64(network_instance)

    core_interfaces = [f"{network_instance.id}_D"]
    downlink_interfaces = general.get_network_instance_connections(network_instance)

    # IP(6)TABLES RULES including NPTv6
    updated, _ = add_downlink_iptables(
        config.VPNC_CONFIG_SERVICE.mode,
        network_instance,
        core_interfaces,
        downlink_interfaces,
    )

    # VPN
    logger.info("Setting up VPN tunnels.")
    strongswan.generate_config(network_instance)

    return updated


def delete_downlink_network_instance(vpn_id: str) -> None:
    """Remove downlink VPN connections."""
    if not config.DOWNLINK_TEN_RE.match(vpn_id):
        logger.error("Invalid filename found in %s. Skipping.", vpn_id, exc_info=True)
        return

    config.VPNC_CONFIG_TENANT.pop(vpn_id, None)
    # NETWORK INSTANCES
    proc = subprocess.run(  # noqa: S603
        ["/usr/sbin/ip", "-json", "netns"],
        stdout=subprocess.PIPE,
        check=True,
    )
    ip_ni = json.loads(proc.stdout)

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
    """Add NAT64 rules to a network instance (Linux namespace)."""
    if config.VPNC_CONFIG_SERVICE.mode != models.ServiceMode.HUB:
        return

    if not (
        nat64_scope := general.get_network_instance_nat64_scope(network_instance.id)
    ):
        return

    # configure NAT64 for the DOWNLINK network instance
    proc = subprocess.run(  # noqa: S602
        f"""
        # start NAT64
        /usr/sbin/ip netns exec {network_instance.id} jool instance flush
        /usr/sbin/ip netns exec {network_instance.id} jool instance add {network_instance.id} --netfilter --pool6 {nat64_scope}
        """,  # noqa: E501
        capture_output=True,
        shell=True,
        check=False,
    )
    logger.info(proc.args)
    logger.debug(proc.stdout, proc.stderr)


def calculate_network_instance_nptv6_mappings(
    network_instance: models.NetworkInstance,
) -> tuple[bool, list[models.RouteIPv6]]:
    """Calculate the NPTv6 translations for a network instance (Linux namespace)."""
    updated = False
    nptv6_list: list[models.RouteIPv6] = []
    if config.VPNC_CONFIG_SERVICE.mode != models.ServiceMode.HUB:
        return updated, nptv6_list
    if network_instance.type != models.NetworkInstanceType.DOWNLINK:
        return updated, nptv6_list

    # Get NPTv6 prefix for this network instance
    if not (
        nptv6_scope := general.get_network_instance_nptv6_scope(network_instance.id)
    ):
        return updated, []

    # Get only routes that should have NPTv6 performed.
    for connection in network_instance.connections.values():
        nptv6_list.extend(
            [route for route in connection.routes.ipv6 if route.nptv6 is True],
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
                (
                    "Route '%s' has invalid NPTv6 prefix '%s' applied."
                    " Not part of assigned scope '%s'. Recalculating"
                ),
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
            # if the highest IP of the subnet is lower than the most recently
            # added network
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
) -> tuple[bool, list[models.RouteIPv6]]:
    """Configure ip(6)table rules for a downlink.

    The DOWNLINK network instance blocks all traffic except for traffic from the CORE
    network instance and ICMPv6.
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-downlink.conf.j2")
    updated, nptv6_networks = calculate_network_instance_nptv6_mappings(
        network_instance,
    )
    iptables_configs = {
        "mode": mode,
        "network_instance_name": network_instance.id,
        "core_interfaces": sorted(core_interfaces),
        "downlink_interfaces": sorted(downlink_interfaces),
        "nptv6_networks": nptv6_networks,
    }
    iptables_render = iptables_template.render(**iptables_configs)
    logger.info(iptables_render)
    proc = subprocess.run(  # noqa: S602
        iptables_render,
        stdout=subprocess.PIPE,
        shell=True,
        check=True,
    )
    logger.debug(proc.stdout)

    return updated, nptv6_networks
