"""Code to manage DOWNLINK network instances."""

from __future__ import annotations

import logging
import pathlib
import subprocess
import time
from ipaddress import AddressValueError, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING

import yaml
from watchdog.events import (
    FileSystemEvent,
    RegexMatchingEventHandler,
)
from watchdog.observers import Observer

import vpnc.models.network_instance
import vpnc.models.tenant
from vpnc import config
from vpnc.models import enums, info
from vpnc.services import frr, vpncmangle

if TYPE_CHECKING:
    from watchdog.observers.api import BaseObserver

logger = logging.getLogger("vpnc")


def observe_configuration() -> BaseObserver:
    """Create the observer for DOWNLINK network instances configuration."""

    # Define what should happen when DOWNLINK files are created, modified or deleted.
    class ConfigurationHandler(RegexMatchingEventHandler):
        """Handler for the event monitoring."""

        def on_created(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            config_file_path = pathlib.Path(event.src_path)
            time.sleep(0.1)
            manage_tenant(config_file_path)

        def on_modified(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            config_file_path = pathlib.Path(event.src_path)
            time.sleep(0.1)
            manage_tenant(config_file_path)

        def on_deleted(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            config_file_path = pathlib.Path(event.src_path)
            time.sleep(0.1)
            delete_downlink_tenant(config_file_path)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories.
    # This doesn't start the handler.
    observer.schedule(
        event_handler=ConfigurationHandler(
            regexes=[config.DOWNLINK_TEN_FILE_RE, r".+\/DEFAULT.yaml$"],
            ignore_directories=True,
        ),
        path=config.VPNC_A_CONFIG_DIR,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


def manage_tenant(path: pathlib.Path) -> None:
    """Configure tenants."""
    default_tenant = vpnc.models.tenant.get_default_tenant()
    tenant_info = None
    tenant_info = vpnc.models.tenant.load_tenant_config(path)

    if not tenant_info:
        return

    tenant, active_tenant = tenant_info
    if not tenant:
        return

    if default_tenant.mode == enums.ServiceMode.ENDPOINT and not getattr(
        tenant,
        "mode",
        None,
    ):
        logger.warning(
            "VPNC in ENDPOINT mode doesn't support"
            " configuration files other than DEFAULT. Ignoring.",
        )

    if not active_tenant:
        active_network_instance_ids: set[str] = set()
        active_tenant_network_instances: dict[
            str,
            vpnc.models.network_instance.NetworkInstance,
        ] = {}
    else:
        active_network_instance_ids = {
            x.id for x in active_tenant.network_instances.values()
        }
        active_tenant_network_instances = active_tenant.network_instances
    network_instance_ids = {x.id for x in tenant.network_instances.values()}  # pylint: disable=no-member

    # Calculate network instances that need to be removed and remove them.
    ni_remove = active_network_instance_ids.difference(network_instance_ids)
    for ni in ni_remove:
        delete_active_ni = active_tenant_network_instances.pop(ni, None)
        if delete_active_ni is None:
            continue

        # run the network instance remove commands
        delete_active_ni.delete()

    logger.info("Setting up tenant %s.", tenant.id)

    update_check: list[bool] = [
        network_instance.set(
            active_tenant_network_instances.get(network_instance.id),
        )
        for network_instance in tenant.network_instances.values()
    ]

    config.VPNC_CONFIG_TENANT[tenant.id] = tenant
    if (
        default_tenant.mode == enums.ServiceMode.HUB
        and tenant.name != config.DEFAULT_TENANT
    ):
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


def delete_downlink_tenant(path: pathlib.Path) -> None:
    """Remove downlink VPN connections."""
    default_tenant = vpnc.models.tenant.get_default_tenant()

    tenant_id = path.stem
    if not config.TENANT_RE.match(tenant_id):
        logger.error(
            "Invalid filename found in %s. Skipping.",
            tenant_id,
            exc_info=True,
        )
        return

    logger.info(
        "Removing all network instance configuration for tenant '%s'.",
        tenant_id,
    )
    active_network_instances = []
    if active_tenant := config.VPNC_CONFIG_TENANT.pop(tenant_id, None):
        active_network_instances = list(active_tenant.network_instances.values())

    if default_tenant.mode == enums.ServiceMode.ENDPOINT and not getattr(
        active_tenant,
        "mode",
        None,
    ):
        logger.warning(
            "VPNC in ENDPOINT mode doesn't support"
            " configuration files other than DEFAULT. Ignoring.",
        )

    for ni in active_network_instances:
        # remove VPN configs if exist
        logger.info(
            "Removing VPN configuration for network instance '%s' connection.",
            ni.id,
            # connection.id,
        )
        downlink_path = config.IPSEC_CONFIG_DIR.joinpath(f"{ni.id}.conf")
        downlink_path.unlink(missing_ok=True)
        time.sleep(0.1)
        # run the network instance remove commands
        ni.delete()

    config.VPNC_CONFIG_TENANT.pop(tenant_id, None)

    # Remove routes when the tenant is deleted.
    if default_tenant.mode == enums.ServiceMode.HUB:
        # FRR
        frr.generate_config()


def get_network_instance_nat64_scope(
    network_instance: vpnc.models.network_instance.NetworkInstance,
) -> IPv6Network | None:
    """Return the IPv6 NPTv6 scope for a network instance.

    This scope  is always a /48.
    """
    default_tenant = vpnc.models.tenant.get_default_tenant()

    if network_instance.type != enums.NetworkInstanceType.DOWNLINK:
        return None

    if default_tenant.mode != enums.ServiceMode.HUB:
        return None

    ni_info = info.parse_downlink_network_instance_name(
        network_instance.id,
    )

    tenant_ext = ni_info.tenant_ext_str  # c, d, e, f
    tenant_id = ni_info.tenant_id  # remote identifier
    network_instance_id = ni_info.network_instance_id  # connection number

    nat64_prefix = default_tenant.prefix_downlink_nat64
    nat64_network_address = int(nat64_prefix[0])
    offset = f"0:0:{tenant_ext}:{tenant_id:x}:{network_instance_id}::"
    nat64_offset = int(IPv6Address(offset))
    nat64_address = IPv6Address(nat64_network_address + nat64_offset)
    return IPv6Network(nat64_address).supernet(new_prefix=96)


def get_network_instance_nptv6_scope(
    network_instance_name: str,
) -> IPv6Network | None:
    """Return the IPv6 NPTv6 scope for a network instance. This is always a /48."""
    if network_instance_name in (
        config.CORE_NI,
        config.DEFAULT_NI,
        config.ENDPOINT_NI,
        config.EXTERNAL_NI,
    ):
        return None

    default_tenant = vpnc.models.tenant.get_default_tenant()

    if default_tenant.mode != enums.ServiceMode.HUB:
        return None

    ni_info = info.parse_downlink_network_instance_name(
        network_instance_name,
    )

    tenant_ext = ni_info.tenant_ext_str
    tenant_id = ni_info.tenant_id
    network_instance_id = ni_info.network_instance_id

    nptv6_superscope = default_tenant.prefix_downlink_nptv6
    nptv6_network_address = int(nptv6_superscope[0])
    offset = f"{tenant_ext}:{tenant_id:x}:{network_instance_id}::"
    nptv6_offset = int(IPv6Address(offset))
    nptv6_address = IPv6Address(nptv6_network_address + nptv6_offset)
    return IPv6Network(nptv6_address).supernet(new_prefix=48)


def get_network_instance_nat64_mappings_state(
    network_instance_name: str,
) -> tuple[IPv6Network, IPv4Network] | None:
    """Retrieve the live NAT64 mapping configured in Jool."""
    proc = subprocess.run(  # noqa: S602
        (
            f"/usr/sbin/ip netns exec {network_instance_name}"
            f" jool --instance {network_instance_name} global display |"
            " grep pool6 |"
            " awk '{ print $2 }'"
        ),
        capture_output=True,
        text=True,
        shell=True,
        check=False,
    )

    if not proc.stdout.strip():
        return None
    try:
        return IPv6Network(proc.stdout.strip()), IPv4Network("0.0.0.0/0")
    except AddressValueError:
        return None


def get_network_instance_nptv6_mappings_state(
    network_instance_name: str,
) -> list[tuple[IPv6Network, IPv6Network]]:
    """Retrieve the live NPTv6 mapping configured in ip6tables."""
    proc = subprocess.run(  # noqa: S602
        (
            f"/usr/sbin/ip netns exec {network_instance_name}"
            " ip6tables -t nat -L |"
            " grep NETMAP |"
            " awk '{print $5,$6}'"
        ),
        stdout=subprocess.PIPE,
        shell=True,
        check=False,
    )

    output: list[tuple[IPv6Network, IPv6Network]] = []

    if not proc.stdout:
        return output
    try:
        for mapping_str in proc.stdout.decode().strip().split("\n"):
            mapping: list[str] = mapping_str.split()
            local = IPv6Network(mapping[0])
            remote = IPv6Network(mapping[1].split("to:", maxsplit=1)[1])

            output.append((local, remote))
    except AddressValueError:
        return output
    return output
