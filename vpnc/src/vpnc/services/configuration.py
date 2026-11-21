"""Code to manage DOWNLINK network instances."""

from __future__ import annotations

import logging
import os
import pathlib
import re
import time
from ipaddress import AddressValueError, IPv4Network, IPv6Network
from typing import TYPE_CHECKING, Any

import yaml
from watchdog.events import (
    FileSystemEvent,
    RegexMatchingEventHandler,
)
from watchdog.observers import Observer

import vpnc.models.tenant
from vpnc import config, eventlog, files, helpers, migration
from vpnc.models import enums
from vpnc.models.secret import REVEAL
from vpnc.network import nftables
from vpnc.services import jool, vpncmangle
from vpnc.services.reconciler import RECONCILER

if TYPE_CHECKING:
    from collections.abc import Callable

    from watchdog.observers.api import BaseObserver

logger = logging.getLogger("vpnc")

# An NPTv6 rule in vpnc's table: NPTv6 prefix and the network it maps to.
NPTV6_RULE_RE = re.compile(
    r"ip6 daddr (\S+) (?:counter packets \d+ bytes \d+ )?dnat (?:ip6 )?prefix to (\S+)",
)


TENANT_FILE_RE = re.compile(rf"{config.DOWNLINK_TEN_FILE_RE}|.+\/DEFAULT\.yaml$")


def observe() -> BaseObserver:
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
            delete_tenant(path)

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


# The watcher, the reconciler (rescan) and commits load and remove tenants. The
# configuration files' lock: a commit holds it while applying.
LOCK = files.CONFIG_LOCK
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
        delete_tenant(path)


# Configuration file per tenant, to write updates (e.g. NPTv6 prefixes) back.
TENANT_PATHS: dict[str, pathlib.Path] = {}


# Per tenant why its active file isn't running; it runs what it ran before.
NOT_LOADED: dict[str, str] = {}


def manage_tenant(path: pathlib.Path, *, check: bool = True) -> None:
    """Run a changed active file, if it can be loaded and passes a commit's checks.

    At startup (check False) the files are what was committed: not checked again.
    """
    with LOCK:
        _manage_tenant(path, check=check)


def _unsupported(tenant: Any, *, hub: bool) -> bool:  # noqa: ANN401
    """Return whether it isn't the service in ENDPOINT mode, which has no tenants."""
    if hub or getattr(tenant, "mode", None):
        return False
    logger.warning(
        "VPNC in ENDPOINT mode doesn't support"
        " configuration files other than DEFAULT. Ignoring.",
    )
    return True


def _warn_weak(tenant: Any) -> None:  # noqa: ANN401
    """Log the weak cryptography of a tenant's IPsec connections."""
    for network_instance in tenant.network_instances.values():
        for connection in network_instance.connections.values():
            if connection.config.type != enums.ConnectionType.IPSEC:
                continue
            for what, _ in connection.config.weaknesses().values():
                logger.warning(
                    "%s has weak cryptography: %s.",
                    connection.name(network_instance),
                    what,
                )


def _manage_tenant(path: pathlib.Path, *, check: bool) -> None:
    if not path.exists():
        # Removed since the event: its own event removes the tenant.
        return
    hub = helpers.is_hub()
    migration.migrate_file(path)
    # Before reading: a later change is seen as one.
    if (file_state := _file_state(path)) is not None:
        FILE_STATES[path] = file_state
    tenant_id = path.stem
    tenant, error = vpnc.models.tenant.load(path)
    if tenant is None:
        if path.exists():
            _not_loaded(tenant_id, error or "")
        return

    if _unsupported(tenant, hub=hub):
        return

    running = config.VPNC_CONFIG_TENANT.get(tenant_id)
    if (
        running is not None
        and TENANT_PATHS.get(tenant_id) == path
        and _same(tenant, running)
    ):
        # E.g. written by a commit, which applied it already.
        _loaded(tenant_id)
        return
    if check and (error := _refused(tenant_id, tenant)):
        _not_loaded(tenant_id, error)
        return
    run(tenant, path)


def _same(first: Any, second: Any) -> bool:  # noqa: ANN401
    """Return whether two configurations are the same, secrets included."""
    dumps = [model.model_dump(mode="json", context=REVEAL) for model in (first, second)]
    return dumps[0] == dumps[1]


def _refused(tenant_id: str, tenant: Any) -> str | None:  # noqa: ANN401
    """Return why a commit would refuse the configuration (weak cryptography aside)."""
    # The API's module imports this one.
    from vpnc.api import config_files  # noqa: PLC0415

    try:
        config_files.check_conflicts({tenant_id: tenant})
    except config_files.ConfigError as err:
        return str(err.detail)
    return None


def _not_loaded(tenant_id: str, error: str) -> None:
    """Note that an active file isn't loaded; the tenant runs what it ran."""
    if NOT_LOADED.get(tenant_id) == error:
        return
    NOT_LOADED[tenant_id] = error
    running = tenant_id in config.VPNC_CONFIG_TENANT
    eventlog.record(
        "CONFIG_NOT_LOADED",
        f"active file not loaded: {error}; "
        + ("running the configuration before it" if running else "not running"),
        tenant=tenant_id,
        level=logging.WARNING,
    )


def _loaded(tenant_id: str) -> None:
    if NOT_LOADED.pop(tenant_id, None) is not None:
        eventlog.record("CONFIG_LOADED", "active file loaded", tenant=tenant_id)


def run(tenant: Any, path: pathlib.Path) -> None:  # noqa: ANN401
    """Run a tenant's configuration: the reconciler applies it.

    The active file at path holds it (e.g. written by a commit).
    """
    with LOCK:
        if (file_state := _file_state(path)) is not None:
            FILE_STATES[path] = file_state
        if _unsupported(tenant, hub=helpers.is_hub()):
            return
        _loaded(tenant.id)
        _run(tenant, path)


def _run(tenant: Any, path: pathlib.Path) -> None:  # noqa: ANN401
    hub = helpers.is_hub()
    active_tenant = config.VPNC_CONFIG_TENANT.get(tenant.id)
    previous_ids: set[str] = set()
    if active_tenant:
        previous_ids = {ni.id for ni in active_tenant.network_instances.values()}
    network_instance_ids = {ni.id for ni in tenant.network_instances.values()}

    logger.info("Applying tenant %s.", tenant.id)
    _warn_weak(tenant)
    config.VPNC_CONFIG_TENANT[tenant.id] = tenant
    TENANT_PATHS[tenant.id] = path

    if hub:
        # DNS mangling: the tenants' translations and the service's limits.
        vpncmangle.generate_config()

    # The reconciler applies the configuration; removed network instances too.
    RECONCILER.trigger(
        "network_instances",
        *(network_instance_ids | previous_ids),
    )


def write_tenant(tenant_id: str) -> None:
    """Write a tenant's configuration back to its files (e.g. new NPTv6 prefixes)."""
    tenant = config.VPNC_CONFIG_TENANT.get(tenant_id)
    path = TENANT_PATHS.get(tenant_id)
    if tenant is None or path is None:
        return
    if helpers.is_hub():
        # The DNS translations of new NPTv6 prefixes: the watcher doesn't apply
        # the file again, it's what runs.
        vpncmangle.generate_config()
    output = files.to_yaml(tenant.model_dump(mode="json", context=REVEAL))
    with files.CONFIG_LOCK:
        if not loaded(path):
            # A newer file (e.g. a commit): written back once that's applied.
            logger.info("Not updating %s: it changed meanwhile.", path)
            return
        if files.ensure_file(path, output, secret=True):
            logger.info("Updated configuration file %s.", path)
        candidate = path.parent.parent / "candidate" / path.name
        _add_nptv6_prefixes_to_candidate(tenant, candidate)
        _add_host_keys_to_candidate(tenant, candidate)


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


def _add_host_keys_to_candidate(
    tenant: vpnc.models.tenant.Tenant,
    path: pathlib.Path,
) -> None:
    """Add accepted SSH host keys to the staged connections of the same server.

    So a commit of other staged changes doesn't remove them.
    """
    accepted = {
        (key, str(connection.id)): connection.config
        for key, ni in tenant.network_instances.items()
        for connection in ni.connections.values()
        if connection.config.type == enums.ConnectionType.SSH
        and connection.config.host_key
    }
    try:
        candidate = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    if not accepted or not isinstance(candidate, dict):
        return
    changed = False
    for key, ni in (candidate.get("network_instances") or {}).items():
        ni_key = vpnc.models.tenant.network_instance_key(key)
        for connection_id, connection in (ni.get("connections") or {}).items():
            staged = connection.get("config") or {}
            active = accepted.get((ni_key, str(connection_id)))
            if (
                active is None
                or str(staged.get("type", "")).upper() != "SSH"
                or staged.get("host_key")
                or staged.get("remote_addrs") != [str(a) for a in active.remote_addrs]
            ):
                continue
            staged["host_key"] = active.host_key
            changed = True
    if changed:
        files.ensure_file(path, files.to_yaml(candidate), secret=True)
        logger.info("Added SSH host keys to the candidate %s.", path)


def delete_tenant(path: pathlib.Path) -> None:
    """Remove downlink VPN connections."""
    with LOCK:
        _delete_tenant(path)


def _delete_tenant(path: pathlib.Path) -> None:
    hub = helpers.is_hub()
    FILE_STATES.pop(path, None)
    NOT_LOADED.pop(path.stem, None)

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

    TENANT_PATHS.pop(tenant_id, None)
    # E.g. removed by a commit already, or its file was never loaded.
    if (active_tenant := config.VPNC_CONFIG_TENANT.pop(tenant_id, None)) is None:
        return
    logger.info(
        "Removing all network instance configuration for tenant '%s'.",
        tenant_id,
    )
    active_network_instances = list(active_tenant.network_instances.values())
    if hub:
        # Without the tenant's DNS translations.
        vpncmangle.generate_config()
    # The reconciler removes the network instances.
    RECONCILER.trigger(
        "network_instances",
        *(ni.id for ni in active_network_instances),
    )


def nat64_mapping(
    network_instance_name: str,
) -> tuple[IPv6Network, IPv4Network] | None:
    """Retrieve the live NAT64 mapping configured in Jool."""
    if (pool6 := jool.pool6(network_instance_name)) is None:
        return None
    try:
        return IPv6Network(pool6), IPv4Network("0.0.0.0/0")
    except (AddressValueError, ValueError):
        return None


def nptv6_mappings(
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
