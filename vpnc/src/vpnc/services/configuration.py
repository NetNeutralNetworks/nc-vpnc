"""Code to manage DOWNLINK network instances."""

from __future__ import annotations

import logging
import os
import pathlib
import re
import threading
import time
from ipaddress import AddressValueError, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING, Any

import yaml
from watchdog.events import (
    FileSystemEvent,
    RegexMatchingEventHandler,
)
from watchdog.observers import Observer

import vpnc.models.network_instance
import vpnc.models.tenant
from vpnc import config, files, migration
from vpnc.models import enums
from vpnc.models.secret import REVEAL
from vpnc.network import nftables
from vpnc.services import jool, vpncmangle

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

        def on_modified(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            handle(manage_tenant, event.src_path)

        on_created = on_modified

        def on_deleted(self, event: FileSystemEvent) -> None:
            logger.info("File %s: %s", event.event_type, event.src_path)
            handle(removed, event.src_path)

        def on_moved(self, event: FileSystemEvent) -> None:
            logger.info(
                "File %s: %s to %s",
                event.event_type,
                event.src_path,
                event.dest_path,
            )
            handle(removed, event.src_path)
            handle(manage_tenant, event.dest_path)

    # A save that replaces the file (e.g. after renaming it to a backup) mustn't
    # remove the tenant: the new file has its own event.
    def removed(path: pathlib.Path) -> None:
        if not path.exists():
            delete_downlink_tenant(path)

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


def loaded(path: pathlib.Path) -> bool:
    """Return whether a configuration file is loaded as it is now."""
    return FILE_STATES.get(path) == _file_state(path)


def rescan() -> None:
    """Load configuration files that changed and drop removed ones (missed events)."""
    paths = {
        path
        for path in config.VPNC_A_CONFIG_DIR.glob("*.yaml")
        if TENANT_FILE_RE.match(str(path))
    }
    for path in sorted(paths):
        if not loaded(path):
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


def _unsupported(tenant: Any, *, hub: bool) -> bool:  # noqa: ANN401
    """Return whether it isn't the service in ENDPOINT mode, which has no tenants."""
    if hub or getattr(tenant, "mode", None):
        return False
    logger.warning(
        "VPNC in ENDPOINT mode doesn't support"
        " configuration files other than DEFAULT. Ignoring.",
    )
    return True


def _manage_tenant(path: pathlib.Path) -> None:
    hub = vpnc.models.tenant.is_hub()
    migration.migrate_file(path)
    # Before reading: a later change is seen as one.
    if (file_state := _file_state(path)) is not None:
        FILE_STATES[path] = file_state
    tenant, active_tenant = vpnc.models.tenant.load_tenant_config(path)
    if not tenant:
        return

    if _unsupported(tenant, hub=hub):
        return

    previous_ids: set[str] = set()
    if active_tenant:
        previous_ids = {ni.id for ni in active_tenant.network_instances.values()}
    network_instance_ids = {ni.id for ni in tenant.network_instances.values()}

    logger.info("Applying tenant %s.", tenant.id)
    config.VPNC_CONFIG_TENANT[tenant.id] = tenant
    TENANT_PATHS[tenant.id] = path

    if hub and tenant.name != config.DEFAULT_TENANT:
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
    output = files.to_yaml(tenant.model_dump(mode="json", context=REVEAL))
    with files.CONFIG_LOCK:
        if not loaded(path):
            # A newer file (e.g. a commit): written back once that's applied.
            logger.info("Not updating %s: it changed meanwhile.", path)
            return
        if files.ensure_file(path, output, secret=True):
            logger.info("Updated configuration file %s.", path)
        _add_nptv6_prefixes_to_candidate(
            tenant,
            path.parent.parent / "candidate" / path.name,
        )


def _add_nptv6_prefixes_to_candidate(
    tenant: vpnc.models.tenant.Tenant,
    path: pathlib.Path,
) -> None:
    """Add assigned NPTv6 prefixes to staged routes that have none.

    Other staged changes are kept, and the prefixes stay the same after a commit.
    """
    assigned = {
        (key, str(connection.id), str(route.to)): str(route.nptv6_prefix)
        for key, ni in tenant.network_instances.items()
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
    for key, ni in (candidate.get("network_instances") or {}).items():
        ni_key = vpnc.models.tenant.network_instance_key(key)
        for connection_id, connection in (ni.get("connections") or {}).items():
            for route in (connection.get("routes") or {}).get("ipv6") or []:
                try:
                    to = str(IPv6Network(route["to"]))
                except (KeyError, TypeError, ValueError):
                    continue
                prefix = assigned.get((ni_key, str(connection_id), to))
                if prefix and not route.get("nptv6_prefix"):
                    route["nptv6_prefix"] = prefix
                    changed = True
    if changed:
        files.ensure_file(path, files.to_yaml(candidate), secret=True)
        logger.info("Added NPTv6 prefixes to the candidate %s.", path)


def delete_downlink_tenant(path: pathlib.Path) -> None:
    """Remove downlink VPN connections."""
    with LOCK:
        _delete_downlink_tenant(path)


def _delete_downlink_tenant(path: pathlib.Path) -> None:
    hub = vpnc.models.tenant.is_hub()
    FILE_STATES.pop(path, None)

    tenant_id = path.stem
    if not config.TENANT_RE.match(tenant_id):
        logger.error("Invalid filename found in %s. Skipping.", tenant_id)
        return
    if tenant_id == config.DEFAULT_TENANT:
        # Without it vpnc can't run: CORE and EXTERNAL would be removed.
        logger.error(
            "%s was removed. Keeping the loaded service configuration.",
            path,
        )
        return

    logger.info(
        "Removing all network instance configuration for tenant '%s'.",
        tenant_id,
    )
    active_network_instances = []
    if active_tenant := config.VPNC_CONFIG_TENANT.pop(tenant_id, None):
        active_network_instances = list(active_tenant.network_instances.values())

    if _unsupported(active_tenant, hub=hub):
        return

    TENANT_PATHS.pop(tenant_id, None)
    if hub:
        # Without the tenant's DNS translations.
        vpncmangle.generate_config()
    # The reconciler removes the network instances.
    from vpnc.services import reconcile  # noqa: PLC0415  (import cycle)

    reconcile.RECONCILER.trigger(
        "network_instances",
        *(ni.id for ni in active_network_instances),
    )


def _downlink_offset(
    network_instance: vpnc.models.network_instance.NetworkInstance,
) -> str:
    """Return a hub's DOWNLINK as the groups of its scopes, e.g. c:1:0 for C0001-00."""
    tenant_id = network_instance.tenant_id
    return f"{tenant_id[0]}:{int(tenant_id[1:], 16):x}:{network_instance.number}"


def get_network_instance_nat64_scope(
    network_instance: vpnc.models.network_instance.NetworkInstance,
) -> IPv6Network | None:
    """Return the IPv6 NAT64 scope for a network instance. This is always a /96."""
    default_tenant = vpnc.models.tenant.get_default_tenant()

    if network_instance.type != enums.NetworkInstanceType.DOWNLINK:
        return None

    if default_tenant.mode != enums.ServiceMode.HUB:
        return None

    nat64_prefix = default_tenant.prefix_downlink_nat64
    nat64_network_address = int(nat64_prefix[0])
    offset = f"0:0:{_downlink_offset(network_instance)}::"
    nat64_offset = int(IPv6Address(offset))
    nat64_address = IPv6Address(nat64_network_address + nat64_offset)
    return IPv6Network(nat64_address).supernet(new_prefix=96)


def get_network_instance_nptv6_scope(
    network_instance: vpnc.models.network_instance.NetworkInstance,
) -> IPv6Network | None:
    """Return the IPv6 NPTv6 scope for a network instance. This is always a /48."""
    default_tenant = vpnc.models.tenant.get_default_tenant()

    if network_instance.type != enums.NetworkInstanceType.DOWNLINK:
        return None

    if default_tenant.mode != enums.ServiceMode.HUB:
        return None

    nptv6_superscope = default_tenant.prefix_downlink_nptv6
    nptv6_network_address = int(nptv6_superscope[0])
    offset = f"{_downlink_offset(network_instance)}::"
    nptv6_offset = int(IPv6Address(offset))
    nptv6_address = IPv6Address(nptv6_network_address + nptv6_offset)
    return IPv6Network(nptv6_address).supernet(new_prefix=48)


def get_network_instance_nat64_mappings_state(
    network_instance_name: str,
) -> tuple[IPv6Network, IPv4Network] | None:
    """Retrieve the live NAT64 mapping configured in Jool."""
    if (pool6 := jool.pool6(network_instance_name)) is None:
        return None
    try:
        return IPv6Network(pool6), IPv4Network("0.0.0.0/0")
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
