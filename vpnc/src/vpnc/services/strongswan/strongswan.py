"""Load IPsec connections into charon over vici, and write them for operators."""

from __future__ import annotations

import atexit
import json
import logging
import os
import sys
import time
from typing import TYPE_CHECKING, Any

import vici
import vici.exception

from vpnc import config, files
from vpnc.models import enums, tenant
from vpnc.network import namespace

if TYPE_CHECKING:
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# A connection as vici messages: the connection and its pre-shared key.
Connection = tuple[dict[str, Any], dict[str, Any]]

# Per connection, what vpnc last loaded into charon.
LOADED: dict[str, str] = {}


def connections(network_instance: NetworkInstance) -> dict[str, Connection]:
    """Return the IPsec connections of a network instance by name."""
    default_tenant = tenant.get_default_tenant()
    vpn_id = 0x10000000
    if network_instance.type == enums.NetworkInstanceType.DOWNLINK:
        vpn_id = int(f"0x{network_instance.id.replace('-', '')}0", 16)

    result: dict[str, Connection] = {}
    for connection in network_instance.connections.values():
        cfg = connection.config
        if cfg.type != enums.ConnectionType.IPSEC:
            continue
        name = f"{network_instance.id}-{connection.id}"
        remote_id = cfg.remote_id or str(cfg.remote_addrs[0])
        xfrm_id = hex(vpn_id + connection.id)
        initiator = cfg.initiation.value == "start"
        local_ts = [str(x) for x in cfg.traffic_selectors.local]
        remote_ts = [str(x) for x in cfg.traffic_selectors.remote]
        if not (local_ts and remote_ts):
            local_ts = remote_ts = ["0.0.0.0/0", "::/0"]
        child = {
            "local_ts": local_ts,
            "remote_ts": remote_ts,
            "life_time": f"{int(cfg.ipsec_lifetime * 1.1 + 0.5)}s",
            "rekey_time": f"{cfg.ipsec_lifetime}s",
            "rekey_bytes": "1024000000",
            "esp_proposals": [cfg.ipsec_proposal.replace("ipsec-", "")],
            "hw_offload": "auto",
            # A responder waits for the peer to (re)establish the connection.
            "start_action": "start" if initiator else "none",
            "dpd_action": "restart" if initiator else "clear",
            "close_action": "start" if initiator else "none",
        }
        conn = {
            "version": str(cfg.ike_version),
            "local_addrs": ["%any"],
            "remote_addrs": [str(x) for x in cfg.remote_addrs],
            "aggressive": "no",
            "dpd_delay": "30s",
            # Keep trying instead of giving up.
            "keyingtries": "0",
            "unique": "replace",
            "if_id_in": xfrm_id,
            "if_id_out": xfrm_id,
            "local": {"id": cfg.local_id or default_tenant.local_id, "auth": "psk"},
            "remote": {"id": remote_id, "auth": "psk"},
            "proposals": [cfg.ike_proposal.replace("ike-", "")],
            "rekey_time": f"{cfg.ike_lifetime}s",
            "children": {name: child},
        }
        shared = {
            "id": f"ike-{name}",
            "type": "IKE",
            "data": cfg.psk.get_secret_value(),
            "owners": [remote_id],
        }
        result[name] = (conn, shared)
    return result


def _section(name: str, value: dict[str, Any], depth: int) -> list[str]:
    pad = "    " * depth
    lines = [f"{pad}{name} {{"]
    for key, item in value.items():
        if isinstance(item, dict):
            lines += _section(key, item, depth + 1)
        else:
            text = ",".join(item) if isinstance(item, list) else item
            lines.append(f"{pad}    {key} = {text}")
    lines.append(f"{pad}}}")
    return lines


def render(conns: dict[str, Connection]) -> str:
    """Return connections in swanctl.conf format."""
    lines = ["connections {"]
    for name, (conn, _) in conns.items():
        lines += _section(name, conn, 1)
    lines += ["}", "", "secrets {"]
    for name, (_, shared) in conns.items():
        lines += _section(
            shared["id"],
            {f"id-{name}": shared["owners"][0], "secret": shared["data"]},
            1,
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _write(ni_id: str, conns: dict[str, Connection]) -> None:
    """Write the connections for operators; charon gets them over vici."""
    path = config.IPSEC_CONFIG_DIR.joinpath(f"{ni_id}.conf")
    if not conns:
        path.unlink(missing_ok=True)
        return
    if files.ensure_file(path, render(conns)):
        os.chown(path, config.IPSEC_USER, config.IPSEC_GROUP)


def _load(
    vcs: vici.Session,
    conns: dict[str, Connection],
    loaded: set[str] | None = None,
) -> None:
    """Load connections that changed, or that charon lacks (loaded: its names)."""
    for name, (conn, shared) in conns.items():
        fingerprint = json.dumps([conn, shared], sort_keys=True)
        if LOADED.get(name) == fingerprint and (loaded is None or name in loaded):
            continue
        vcs.load_conn({name: conn})
        vcs.load_shared(shared)
        LOADED[name] = fingerprint
        logger.info("Loaded IPsec connection %s.", name)


def _unload(vcs: vici.Session, names: set[str]) -> None:
    for name in sorted(names):
        for unload, arg in (
            (vcs.unload_conn, {"name": name}),
            (vcs.unload_shared, {"id": f"ike-{name}"}),
        ):
            try:
                unload(arg)
            except vici.exception.CommandException:
                logger.debug("%s of %s wasn't loaded.", arg, name)
        LOADED.pop(name, None)
        logger.info("Unloaded IPsec connection %s.", name)


def _own(ni_id: str, names: set[str]) -> set[str]:
    return {name for name in names if name.rsplit("-", 1)[0] == ni_id}


def apply(network_instance: NetworkInstance) -> None:
    """Make charon's connections of a network instance as configured.

    Only connections that changed are loaded; others, and their SAs, aren't
    touched. Failures are retried by the full check (sync).
    """
    conns = connections(network_instance)
    _write(network_instance.id, conns)
    try:
        vcs = vici.Session()
        _load(vcs, conns)
        _unload(vcs, _own(network_instance.id, set(LOADED)) - conns.keys())
    except (OSError, vici.exception.CommandException):
        logger.exception(
            "Loading the IPsec connections of %s failed.",
            network_instance.id,
        )


def remove(ni_id: str) -> None:
    """Unload the connections of a removed network instance and delete its file."""
    config.IPSEC_CONFIG_DIR.joinpath(f"{ni_id}.conf").unlink(missing_ok=True)
    try:
        vcs = vici.Session()
        loaded = {name.decode() for name in vcs.get_conns()["conns"]}
        _unload(vcs, _own(ni_id, loaded | set(LOADED)))
    except (OSError, vici.exception.CommandException):
        logger.exception("Unloading the IPsec connections of %s failed.", ni_id)


def sync(vcs: vici.Session) -> None:
    """Make charon's connections and keys exactly the configured ones.

    Loads what's missing (e.g. after a charon restart) or changed, and unloads
    what isn't configured.
    """
    conns: dict[str, Connection] = {}
    for tenant_config in list(config.VPNC_CONFIG_TENANT.values()):
        for network_instance in tenant_config.network_instances.values():
            conns |= connections(network_instance)
    loaded = {name.decode() for name in vcs.get_conns()["conns"]}
    keys = {key.decode() for key in vcs.get_shared()["keys"]}
    # A connection whose key is missing is loaded again.
    _load(vcs, conns, {name for name in loaded if f"ike-{name}" in keys})
    if unknown := loaded - conns.keys():
        logger.warning("Unloading unknown IPsec connections: %s.", sorted(unknown))
        _unload(vcs, unknown)
    for key in keys - {f"ike-{name}" for name in conns}:
        logger.warning("Unloading unknown IPsec key %s.", key)
        vcs.unload_shared({"id": key})


def stop() -> None:
    """Shut down IPsec when terminating the program."""
    logger.info("Stopping Strongswan in network instance %s.", config.EXTERNAL_NI)
    namespace.run(config.EXTERNAL_NI, ["/usr/sbin/ipsec", "stop"])


def start() -> None:
    """Start the IPSec service in the EXTERNAL network instance."""
    # Remove old strongswan/swanctl config files
    logger.info("Starting Strongswan process.")
    for file in config.IPSEC_CONFIG_DIR.iterdir():
        logger.debug("Unlinking swanctl config file %s at startup", file)
        file.unlink(missing_ok=True)

    logger.info("Starting Strongswan in network instance %s.", config.EXTERNAL_NI)
    result = namespace.run(config.EXTERNAL_NI, ["/usr/sbin/ipsec", "start"])
    if result.returncode != 0:
        logger.critical("Could not start Strongswan\n%s", result.stderr)
        sys.exit(1)

    atexit.register(stop)

    tries = 50
    delay = 0.1
    for i in range(tries):
        try:
            vici.Session()
            break
        except (ConnectionRefusedError, FileNotFoundError):
            if i >= tries - 1:
                logger.critical(
                    "VICI socket not available after %s tries. Exiting.",
                    tries,
                )
                sys.exit(1)
            logger.info("VICI socket is not yet available. Retrying.")
            time.sleep(delay)
