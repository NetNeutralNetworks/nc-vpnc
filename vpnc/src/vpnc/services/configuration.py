"""Code to manage DOWNLINK network instances."""

from __future__ import annotations

import logging
import os
import pathlib
import re
import threading
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
from vpnc import config, files
from vpnc.models import enums, info
from vpnc.models.secret import REVEAL
from vpnc.network import namespace, nftables
from vpnc.services import vpncmangle

if TYPE_CHECKING:
    from collections.abc import Callable

    from watchdog.observers.api import BaseObserver

logger = logging.getLogger("vpnc")

# An NPTv6 rule in vpnc's table: NPTv6 prefix and the network it maps to.
NPTV6_RULE_RE = re.compile(r"ip6 daddr (\S+) dnat (?:ip6 )?prefix to (\S+)")


TENANT_FILE_RE = re.compile(rf"{config.DOWNLINK_TEN_FILE_RE}|.+\/DEFAULT\.yaml$")


def observe_configuration() -> BaseObserver:
    """Create the observer for DOWNLINK network instances configuration."""

    # A failing handler would end the observer thread, so errors are only logged.
    def handle(action: Callable[[pathlib.Path], None], path: str | bytes) -> None:
        if not TENANT_FILE_RE.match(os.fsdecode(path)):
            return
        time.sleep(0.1)
        try:
            action(pathlib.Path(os.fsdecode(path)))
        except Exception:
            logger.exception("Handling the change of %s failed.", path)

    # Define what should happen when DOWNLINK files are created, modified or deleted.
    class ConfigurationHandler(RegexMatchingEventHandler):
        """Handler for the event monitoring."""

        def on_created(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            handle(manage_tenant, event.src_path)

        def on_modified(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            handle(manage_tenant, event.src_path)

        def on_deleted(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            handle(delete_downlink_tenant, event.src_path)

        def on_moved(self, event: FileSystemEvent) -> None:
            logger.info(
                "File %s: %s to %s",
                event.event_type,
                event.src_path,
                event.dest_path,
            )
            handle(delete_downlink_tenant, event.src_path)
            handle(manage_tenant, event.dest_path)

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories.
    # This doesn't start the handler.
    observer.schedule(
        event_handler=ConfigurationHandler(
            regexes=[TENANT_FILE_RE.pattern],
            ignore_directories=True,
        ),
        path=config.VPNC_A_CONFIG_DIR,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer


# The watcher and the reconciler (rescan) load and remove tenants.
LOCK = threading.RLock()
# Per configuration file its modification time and size when it was last read.
FILE_STATES: dict[pathlib.Path, tuple[int, int]] = {}


def _file_state(path: pathlib.Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return stat.st_mtime_ns, stat.st_size


def rescan() -> None:
    """Load configuration files that changed and drop removed ones (missed events)."""
    paths = {
        path
        for path in config.VPNC_A_CONFIG_DIR.glob("*.yaml")
        if TENANT_FILE_RE.match(str(path))
    }
    for path in sorted(paths):
        if FILE_STATES.get(path) != _file_state(path):
            logger.info("Configuration file %s changed unnoticed.", path)
            manage_tenant(path)
    for path in set(FILE_STATES) - paths:
        logger.warning("Configuration file %s was removed unnoticed.", path)
        delete_downlink_tenant(path)


# Configuration file per tenant, to write updates (e.g. NPTv6 prefixes) back.
TENANT_PATHS: dict[str, pathlib.Path] = {}


def manage_tenant(path: pathlib.Path) -> None:
    """Configure tenants."""
    with LOCK:
        _manage_tenant(path)


def _manage_tenant(path: pathlib.Path) -> None:
    default_tenant = vpnc.models.tenant.get_default_tenant()
    # Before reading: a later change is seen as one.
    if (file_state := _file_state(path)) is not None:
        FILE_STATES[path] = file_state
    tenant, active_tenant = vpnc.models.tenant.load_tenant_config(path)
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

    previous_ids: set[str] = set()
    if active_tenant:
        previous_ids = {ni.id for ni in active_tenant.network_instances.values()}
    network_instance_ids = {ni.id for ni in tenant.network_instances.values()}

    logger.info("Applying tenant %s.", tenant.id)
    config.VPNC_CONFIG_TENANT[tenant.id] = tenant
    TENANT_PATHS[tenant.id] = path

    if (
        default_tenant.mode == enums.ServiceMode.HUB
        and tenant.name != config.DEFAULT_TENANT
    ):
        # DNS mangling
        vpncmangle.generate_config()

    # The reconciler applies the configuration; removed network instances too.
    from vpnc.services import reconcile  # noqa: PLC0415  (import cycle)

    reconcile.RECONCILER.trigger(
        "network_instances",
        *(network_instance_ids | previous_ids),
    )


def write_tenant(tenant_id: str) -> None:
    """Write a tenant's configuration back to its files (e.g. new NPTv6 prefixes)."""
    tenant = config.VPNC_CONFIG_TENANT.get(tenant_id)
    path = TENANT_PATHS.get(tenant_id)
    if tenant is None or path is None:
        return
    output = yaml.safe_dump(
        tenant.model_dump(mode="json", context=REVEAL),
        explicit_start=True,
        explicit_end=True,
    )
    if files.ensure_file(path, output):
        logger.info("Updated configuration file %s.", path)
    _add_nptv6_prefixes_to_candidate(tenant, path.parent.parent / "candidate" / path.name)


def _add_nptv6_prefixes_to_candidate(
    tenant: vpnc.models.tenant.Tenant,
    path: pathlib.Path,
) -> None:
    """Add assigned NPTv6 prefixes to staged routes that have none.

    Other staged changes are kept, and the prefixes stay the same after a commit.
    """
    assigned = {
        (ni.id, str(connection.id), str(route.to)): str(route.nptv6_prefix)
        for ni in tenant.network_instances.values()
        for connection in ni.connections.values()
        for route in connection.routes.ipv6
        if route.nptv6_prefix
    }
    try:
        candidate = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    if not assigned or not isinstance(candidate, dict):
        return
    changed = False
    for ni_id, ni in (candidate.get("network_instances") or {}).items():
        for connection_id, connection in (ni.get("connections") or {}).items():
            for route in (connection.get("routes") or {}).get("ipv6") or []:
                try:
                    to = str(IPv6Network(route["to"]))
                except (KeyError, TypeError, ValueError):
                    continue
                prefix = assigned.get((ni_id, str(connection_id), to))
                if prefix and not route.get("nptv6_prefix"):
                    route["nptv6_prefix"] = prefix
                    changed = True
    if changed:
        files.ensure_file(
            path,
            yaml.safe_dump(candidate, explicit_start=True, explicit_end=True),
        )
        logger.info("Added NPTv6 prefixes to the candidate %s.", path)


def delete_downlink_tenant(path: pathlib.Path) -> None:
    """Remove downlink VPN connections."""
    with LOCK:
        _delete_downlink_tenant(path)


def _delete_downlink_tenant(path: pathlib.Path) -> None:
    default_tenant = vpnc.models.tenant.get_default_tenant()
    FILE_STATES.pop(path, None)

    tenant_id = path.stem
    if not config.TENANT_RE.match(tenant_id):
        logger.error("Invalid filename found in %s. Skipping.", tenant_id)
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

    TENANT_PATHS.pop(tenant_id, None)
    # The reconciler removes the network instances.
    from vpnc.services import reconcile  # noqa: PLC0415  (import cycle)

    reconcile.RECONCILER.trigger(
        "network_instances",
        *(ni.id for ni in active_network_instances),
    )


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
    output = namespace.run(
        network_instance_name,
        ["/usr/bin/jool", "--instance", network_instance_name, "global", "display"],
    ).stdout
    pool6 = [
        fields[1]
        for fields in map(str.split, output.splitlines())
        if len(fields) > 1 and "pool6" in fields[0]
    ]
    if len(pool6) != 1:
        return None
    try:
        return IPv6Network(pool6[0]), IPv4Network("0.0.0.0/0")
    except (AddressValueError, ValueError):
        return None


def get_network_instance_nptv6_mappings_state(
    network_instance_name: str,
) -> list[tuple[IPv6Network, IPv6Network]]:
    """Retrieve the live NPTv6 mappings from vpnc's nftables table."""
    try:
        rules = nftables.run(
            network_instance_name,
            f"list chain {nftables.TABLE} prerouting",
        )
    except nftables.NftablesError:
        return []
    mappings: list[tuple[IPv6Network, IPv6Network]] = []
    for match in NPTV6_RULE_RE.finditer(rules):
        try:
            mappings.append((IPv6Network(match[1]), IPv6Network(match[2])))
        except (AddressValueError, ValueError):
            continue
    return mappings
