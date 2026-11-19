"""Load IPsec connections into charon over vici, and write them for operators."""

from __future__ import annotations

import atexit
import json
import logging
import sys
import time
from typing import TYPE_CHECKING, Any

import vici
import vici.exception

from vpnc import config, eventlog, files, helpers
from vpnc.models import enums
from vpnc.models.ipsec import Initiation
from vpnc.models.post_quantum import STRONGSWAN_KE, ppk_bytes
from vpnc.network import namespace
from vpnc.services import charon

if TYPE_CHECKING:
    import pathlib

    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# A connection as vici messages: the connection and its keys (PSK, PPK).
Connection = tuple[dict[str, Any], list[dict[str, Any]]]

# A failed vici request: no answer in time, a broken session or a refusal.
VICI_ERRORS = (
    OSError,
    vici.exception.SessionException,
    vici.exception.CommandException,
)

# Per connection, what vpnc last loaded into charon.
LOADED: dict[str, str] = {}
# Seconds to wait for the peer to confirm a terminated IKE SA.
TERMINATE_TIMEOUT = 5
# The key exchange methods charon supports; read once it's running.
KEY_EXCHANGES: frozenset[str] | None = None
# Connections refused for a missing ML-KEM, logged once.
REFUSED: set[str] = set()


def _key_id(name: str) -> str:
    """Return the id of a connection's pre-shared key in charon."""
    return f"ike-{name}"


def _ppk_id(name: str) -> str:
    """Return the id of a connection's postquantum preshared key in charon."""
    return f"ppk-{name}"


def supported_key_exchanges() -> frozenset[str] | None:
    """Return the key exchange methods charon supports, None if unknown."""
    global KEY_EXCHANGES  # noqa: PLW0603
    if KEY_EXCHANGES is None:
        try:
            with charon.session() as vcs:
                KEY_EXCHANGES = charon.key_exchanges(vcs)
        except VICI_ERRORS:
            logger.warning("Reading charon's key exchanges failed.", exc_info=True)
    return KEY_EXCHANGES


def _path(ni_id: str) -> pathlib.Path:
    """Return the file with a network instance's connections."""
    return config.IPSEC_CONFIG_DIR.joinpath(f"{ni_id}.conf")


def connections(network_instance: NetworkInstance) -> dict[str, Connection]:
    """Return the IPsec connections of a network instance by name."""
    default_tenant = helpers.get_default_tenant()
    result: dict[str, Connection] = {}
    for connection in network_instance.connections.values():
        cfg = connection.config
        if cfg.type != enums.ConnectionType.IPSEC:
            continue
        name = connection.name(network_instance)
        if not connection.enabled:
            continue
        pq = cfg.post_quantum
        # Never without ML-KEM; a later sync retries when charon was unreachable.
        if pq.enabled and pq.ml_kem.value not in (
            supported := supported_key_exchanges() or ()
        ):
            if supported and name not in REFUSED:
                logger.error(
                    "Not loading IPsec connection %s: charon lacks %s"
                    " (strongSwan 6, Ubuntu 26.04, is required).",
                    name,
                    pq.ml_kem.value,
                )
                REFUSED.add(name)
            continue
        REFUSED.discard(name)
        # Hybrid: ML-KEM as additional key exchange after the classical one.
        ke = f"-ke1_{STRONGSWAN_KE[pq.ml_kem]}" if pq.enabled else ""
        remote_id = cfg.remote_id or str(cfg.remote_addrs[0])
        xfrm_id = hex(cfg.if_id(network_instance, connection))
        initiator = cfg.initiation == Initiation.INITIATOR
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
            "esp_proposals": [cfg.ipsec_proposal.replace("ipsec-", "") + ke],
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
            "proposals": [cfg.ike_proposal.replace("ike-", "") + ke],
            "rekey_time": f"{cfg.ike_lifetime}s",
            "children": {name: child},
        }
        keys = [
            {
                "id": _key_id(name),
                "type": "IKE",
                "data": cfg.psk.get_secret_value(),
                "owners": [remote_id],
            },
        ]
        if ppk_id := cfg.ppk_id(network_instance, connection):
            conn["ppk_id"] = ppk_id
            # A PPK that's optional could be left out by an attacker.
            conn["ppk_required"] = "yes"
            keys.append(
                {
                    "id": _ppk_id(name),
                    "type": "PPK",
                    "data": pq.ppk.key.get_secret_value(),
                    "owners": [ppk_id],
                },
            )
        result[name] = (conn, keys)
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
    for name, (_, keys) in conns.items():
        for key in keys:
            lines += _section(
                key["id"],
                {f"id-{name}": key["owners"][0], "secret": key["data"]},
                1,
            )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _write(ni_id: str, conns: dict[str, Connection]) -> None:
    """Write the connections for operators; charon gets them over vici."""
    path = _path(ni_id)
    if not conns:
        path.unlink(missing_ok=True)
        return
    files.ensure_file(path, render(conns), secret=True)


def _pending(
    conns: dict[str, Connection],
    loaded: set[str] | None = None,
) -> dict[str, str]:
    """Return the fingerprints of the connections to load.

    Those that changed, or that charon lacks (loaded: its names).
    """
    pending: dict[str, str] = {}
    for name, (conn, keys) in conns.items():
        fingerprint = json.dumps([conn, keys], sort_keys=True)
        if LOADED.get(name) != fingerprint or (
            loaded is not None and name not in loaded
        ):
            pending[name] = fingerprint
    return pending


def _kept(old: str | None, new: Connection) -> list[str]:
    """Return what changed that a connection's SAs keep the old of.

    The key they were authenticated with, and the traffic selectors: charon
    only negotiates those anew as an initiator.
    """
    if old is None:
        return []
    (was, was_keys), (conn, keys) = json.loads(old), new

    def data(keys: list[dict[str, Any]], kind: str) -> list[str]:
        return [key["data"] for key in keys if key["type"] == kind]

    changed = [
        field
        for field, kind in (("psk", "IKE"), ("ppk", "PPK"))
        if data(was_keys, kind) != data(keys, kind)
    ]
    (was_child,), (child,) = was["children"].values(), conn["children"].values()
    if any(was_child[ts] != child[ts] for ts in ("local_ts", "remote_ts")):
        changed.append("traffic_selectors")
    return changed


def _load(
    vcs: vici.Session,
    conns: dict[str, Connection],
    loaded: set[str] | None = None,
) -> dict[str, list[str]]:
    """Load connections that changed, or that charon lacks (loaded: its names).

    Returns the ones to reset, with what changed that their SAs keep the old of.
    """
    stale: dict[str, list[str]] = {}
    for name, fingerprint in _pending(conns, loaded).items():
        conn, keys = conns[name]
        if kept := _kept(LOADED.get(name), conns[name]):
            stale[name] = kept
        vcs.load_conn({name: conn})
        for key in keys:
            # A PPK is decoded like swanctl does; its decoded length was validated.
            vcs.load_shared(
                {**key, "data": ppk_bytes(key["data"])}
                if key["type"] == "PPK"
                else key,
            )
        if len(keys) == 1 and _ppk_id(name) in LOADED.get(name, ""):
            _unload_key(vcs, _ppk_id(name))
        LOADED[name] = fingerprint
        logger.info("Loaded IPsec connection %s.", name)
    return stale


def terminate(name: str, *, force: bool = False) -> None:
    """Terminate a connection's IKE SAs; with force without telling the peer."""
    with charon.session(charon.VICI_TIMEOUT + TERMINATE_TIMEOUT) as vcs:
        # Fails when there's no SA, or the peer doesn't confirm in time.
        charon.terminate(
            vcs,
            ike=name,
            wait=TERMINATE_TIMEOUT,
            force=force,
            warn=False,
        )


def initiate(name: str) -> None:
    """Set an initiator's connection up, without waiting for it."""
    with charon.session() as vcs:
        charon.initiate(vcs, name, warn=False)


def _renew(conns: dict[str, Connection], stale: dict[str, list[str]]) -> None:
    """Reset connections whose SAs have what was configured before."""
    for name, changed in stale.items():
        eventlog.record(
            "CONFIG_RESET",
            f"reset: its {', '.join(changed)} changed",
            connection=name,
            changed=changed,
        )
        try:
            terminate(name)
            # A responder's peer sets it up again.
            if conns[name][0]["children"][name]["start_action"] == "start":
                initiate(name)
        except VICI_ERRORS:
            logger.exception("Resetting IPsec connection %s failed.", name)


def _unload_key(vcs: vici.Session, key_id: str) -> None:
    try:
        vcs.unload_shared({"id": key_id})
    except vici.exception.CommandException:
        logger.debug("Key %s wasn't loaded.", key_id)


def _unload(vcs: vici.Session, names: set[str]) -> None:
    for name in sorted(names):
        try:
            vcs.unload_conn({"name": name})
        except vici.exception.CommandException:
            logger.debug("Connection %s wasn't loaded.", name)
        _unload_key(vcs, _key_id(name))
        _unload_key(vcs, _ppk_id(name))
        LOADED.pop(name, None)
        logger.info("Unloaded IPsec connection %s.", name)


def _own(ni_id: str, names: set[str]) -> set[str]:
    return {name for name in names if helpers.split_connection_name(name)[0] == ni_id}


def apply(network_instance: NetworkInstance) -> None:
    """Make charon's connections of a network instance as configured.

    Only connections that changed are loaded; others, and their SAs, aren't
    touched. A changed PSK, PPK or traffic selectors resets the connection: its
    SAs would keep the old. Failures are retried by the full check (sync).
    """
    conns = connections(network_instance)
    _write(network_instance.id, conns)
    gone = _own(network_instance.id, set(LOADED)) - conns.keys()
    if not gone and not _pending(conns):
        return
    try:
        with charon.session() as vcs:
            stale = _load(vcs, conns)
            _unload(vcs, gone)
    except VICI_ERRORS:
        logger.exception(
            "Loading the IPsec connections of %s failed.",
            network_instance.id,
        )
        return
    _renew(conns, stale)


def remove(ni_id: str) -> None:
    """Unload the connections of a removed network instance and delete its file."""
    _path(ni_id).unlink(missing_ok=True)
    try:
        with charon.session() as vcs:
            loaded = charon.loaded_connections(vcs)
            _unload(vcs, _own(ni_id, loaded | set(LOADED)))
    except VICI_ERRORS:
        logger.exception("Unloading the IPsec connections of %s failed.", ni_id)


def sync(vcs: vici.Session) -> None:
    """Make charon's connections and keys exactly the configured ones.

    Loads what's missing (e.g. after a charon restart) or changed, and unloads
    what isn't configured.
    """
    conns: dict[str, Connection] = {}
    for network_instance in helpers.network_instances().values():
        conns |= connections(network_instance)
    loaded = charon.loaded_connections(vcs)
    keys = {key.decode() for key in vcs.get_shared()["keys"]}
    # A connection with a missing key is loaded again.
    complete = {
        name
        for name in loaded
        if name in conns and all(key["id"] in keys for key in conns[name][1])
    }
    stale = _load(vcs, conns, complete)
    if unknown := loaded - conns.keys():
        logger.warning("Unloading unknown IPsec connections: %s.", sorted(unknown))
        _unload(vcs, unknown)
    for key in keys - {key["id"] for _, own in conns.values() for key in own}:
        logger.warning("Unloading unknown IPsec key %s.", key)
        vcs.unload_shared({"id": key})
    _renew(conns, stale)


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
            with charon.session():
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
