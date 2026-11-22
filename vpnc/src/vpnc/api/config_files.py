"""The active and candidate (staged) configurations of tenants and the service.

A tenant (or the service, DEFAULT) has an active configuration, which vpnc runs
and keeps in its active file, and may have a candidate file with staged
changes; a commit checks them, writes the active file and runs it. Without a
candidate file nothing is staged; an empty one stages removing the tenant. An
active file changed otherwise runs if a commit would accept it; if not, the
tenant runs what it ran (see configuration.NOT_LOADED).

A commit keeps the active configuration it replaces in the history (empty: the
tenant didn't exist). A confirmed commit is rolled back unless confirmed in
time; the rollback is stored, so it also happens after vpnc restarts.
"""

from __future__ import annotations

import datetime as dt
import difflib
import functools
import json
import logging
import threading
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    ValidationError,
)

from vpnc import config, eventlog, files, helpers, keys, migration
from vpnc.models import enums, tenant
from vpnc.models.ipsec import ppk_id_users
from vpnc.models.post_quantum import PostQuantumPresharedKey
from vpnc.models.secret import REVEAL
from vpnc.models.wireguard import wireguard_port_users
from vpnc.services import configuration, ssh
from vpnc.services.strongswan import proposals, strongswan

if TYPE_CHECKING:
    import pathlib

Revision = Literal["active", "candidate"]
DIRS: dict[Revision, pathlib.Path] = {
    "active": config.VPNC_A_CONFIG_DIR,
    "candidate": config.VPNC_C_CONFIG_DIR,
}
# The configuration version of new tenants.
VERSION = migration.CURRENT
HISTORY_DIR = config.VPNC_HISTORY_DIR
# Revisions kept per tenant; 1 is the most recent.
HISTORY = 5

logger = logging.getLogger("vpnc")
# Commits, confirms and rollbacks (also from timers).
LOCK = files.CONFIG_LOCK
TIMERS: dict[str, threading.Timer] = {}


class ConfigError(Exception):
    """A configuration request can't be fulfilled."""

    def __init__(self, status: int, title: str, detail: str | Any) -> None:  # noqa: ANN401
        """Store the HTTP status, title and detail for the response."""
        super().__init__(title)
        self.status = status
        self.title = title
        self.detail = detail


class ConfigSummary(BaseModel):
    """A tenant's configuration and its staged changes."""

    id: str
    name: str | None
    status: Literal["UNCHANGED", "MODIFIED", "ADDED", "DELETED"]
    # A commit to confirm before then, or it's rolled back.
    confirm_by: str | None = None
    # Why the active file isn't running, or the candidate file can't be read.
    error: str | None = None


class NewTenant(BaseModel):
    """A tenant to add: its id and name; the rest is set after."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=config.TENANT_ID_PATTERN)
    name: str = Field(min_length=1)


class CommitResult(BaseModel):
    """The result of a commit, confirm, discard, delete or restore."""

    id: str
    changed: bool
    confirm_by: str | None = None
    # Service settings that only apply after vpnc restarts.
    restart_needed: list[str] = []
    # Weak cryptography the commit added, per connection (allow_weak).
    warnings: list[str] = []
    # Secrets the commit generated, e.g. C0001-00-0 psk.
    generated: list[str] = []


# Service settings read at startup only. The downlink prefixes are partly
# applied live, but readdressing every downlink is only clean at startup.
RESTART_FIELDS = (
    "mode",
    "prefix_downlink_interface_v4",
    "prefix_downlink_interface_v6",
    "prefix_downlink_nat64",
    "prefix_downlink_nptv6",
)
# The service settings vpnc started with.
STARTUP: dict[str, Any] = {}


def remember_startup() -> None:
    """Remember the service settings that need a restart to change."""
    service = _dump(_load(config.DEFAULT_TENANT, "active"), reveal=False) or {}
    STARTUP.update({field: service.get(field) for field in RESTART_FIELDS})


def restart_needed() -> list[str]:
    """Return the service settings that changed since vpnc started."""
    service = _dump(_load(config.DEFAULT_TENANT, "active"), reveal=False) or {}
    return [f for f in RESTART_FIELDS if STARTUP and service.get(f) != STARTUP[f]]


class HistoryEntry(BaseModel):
    """An earlier active configuration."""

    revision: int
    # When a commit replaced it.
    replaced: str
    # Whether the tenant existed.
    exists: bool


Model = tenant.Tenant | tenant.ServiceHub | tenant.ServiceEndpoint


def check_id(tenant_id: str) -> None:
    """Raise a 404 for ids that can't be tenants."""
    if not config.TENANT_RE.match(tenant_id):
        raise ConfigError(404, "Not found", f"'{tenant_id}' isn't a valid tenant id.")


def _path(tenant_id: str, revision: Revision) -> pathlib.Path:
    return DIRS[revision].joinpath(f"{tenant_id}.yaml")


def _text(tenant_id: str, revision: Revision) -> str | None:
    try:
        return _path(tenant_id, revision).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def validate(tenant_id: str, data: Any) -> Model:  # noqa: ANN401
    """Return the validated configuration (ValidationError if invalid)."""
    if not isinstance(data, dict):
        raise ConfigError(422, "Invalid configuration", "Expected a mapping.")
    try:
        # JSON allows lone surrogates (e.g. "\ud800"); the files are UTF-8.
        json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
    except UnicodeEncodeError:
        detail = "Text should be valid Unicode (no lone surrogates)."
        raise ConfigError(422, "Invalid configuration", detail) from None
    data = migration.upgrade(data)
    model = (
        tenant.Service(config=data).config
        if tenant_id == config.DEFAULT_TENANT
        else tenant.Tenant(**data)
    )
    if model.id != tenant_id:
        raise ConfigError(
            422,
            "Invalid configuration",
            f"The id '{model.id}' doesn't match '{tenant_id}'.",
        )
    _check_algorithms(model)
    return model


def _check_algorithms(model: Model) -> None:
    """Refuse IPsec proposals charon refuses, or with algorithms it doesn't have.

    Without asking charon to load them; what it has only if it can be asked.
    """
    available = strongswan.supported_algorithms()
    for ni in model.network_instances.values():
        for connection in ni.connections.values():
            cfg = connection.config
            if cfg.type != enums.ConnectionType.IPSEC:
                continue
            for field, esp in (("ike_proposal", False), ("ipsec_proposal", True)):
                value = getattr(cfg, field)
                reason = proposals.problem(value, esp=esp)
                if reason is None and available:
                    missing = proposals.unavailable(value, available, esp=esp)
                    if missing:
                        reason = f"charon doesn't have {', '.join(missing)}"
                if reason:
                    detail = f"{connection.name(ni)}: {field} {value}: {reason}."
                    raise ConfigError(422, "Invalid configuration", detail)


def _running(tenant_id: str) -> Model | None:
    """Return a copy of the configuration vpnc runs."""
    model = config.VPNC_CONFIG_TENANT.get(tenant_id)
    return model.model_copy(deep=True) if model is not None else None


def _exists(tenant_id: str) -> bool:
    """Return whether a tenant runs or has an active file (e.g. one not loaded)."""
    return tenant_id in config.VPNC_CONFIG_TENANT or _path(tenant_id, "active").exists()


def _load(tenant_id: str, revision: Revision) -> Model | None:
    """Return a revision; the candidate is the active one unless changes are staged.

    The active one is what runs. None if there's none, or removing the tenant is
    staged.
    """
    if revision == "active":
        return _running(tenant_id)
    text = _text(tenant_id, revision)
    if text is None:
        return _running(tenant_id)
    if not text.strip():
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        detail = f"The candidate file of {tenant_id} isn't valid YAML."
        raise ConfigError(422, "Invalid configuration", detail) from None
    return validate(tenant_id, data)


def _dump(model: Model | None, *, reveal: bool) -> dict[str, Any] | None:
    if model is None:
        return None
    return model.model_dump(mode="json", context=REVEAL if reveal else None)


def _yaml(data: dict[str, Any] | None) -> str:
    return "" if data is None else files.to_yaml(data)


def _same(first: Model | None, second: Model | None) -> bool:
    """Return whether two configurations are the same, secrets included."""
    return _dump(first, reveal=True) == _dump(second, reveal=True)


def _changed(tenant_id: str) -> bool:
    """Return whether the candidate differs from the active configuration."""
    return not _same(_load(tenant_id, "candidate"), _load(tenant_id, "active"))


def staged(tenant_id: str) -> bool:
    """Return whether a tenant has staged changes (or a candidate that's invalid)."""
    with LOCK:
        try:
            return _changed(tenant_id)
        except (ConfigError, ValidationError):
            return True


def _keep_service(tenant_id: str) -> None:
    """Refuse removing the service."""
    if tenant_id == config.DEFAULT_TENANT:
        raise ConfigError(409, "Conflict", "The service can't be removed.")


def tenant_ids() -> list[str]:
    """Return the tenants that run or have a configuration file (not the service)."""
    files = {
        p.stem
        for directory in DIRS.values()
        for p in directory.glob("*.yaml")
        if config.TENANT_RE.match(p.stem)
    }
    return sorted((files | set(config.VPNC_CONFIG_TENANT)) - {config.DEFAULT_TENANT})


def summaries() -> list[ConfigSummary]:
    """Return the tenants with configuration (not the service)."""
    output: list[ConfigSummary] = []
    for tenant_id in tenant_ids():
        error = configuration.NOT_LOADED.get(tenant_id)
        if error:
            error = f"active file not loaded: {error}"
        active = _load(tenant_id, "active")
        try:
            candidate = _load(tenant_id, "candidate")
        except (ConfigError, ValidationError):
            candidate, error = active, "the candidate file isn't valid"
            status = "MODIFIED"
        else:
            status = _status(active, candidate)
        if active is None and candidate is None and not error:
            continue
        output.append(
            ConfigSummary(
                id=tenant_id,
                name=(candidate or active).name if candidate or active else None,
                status=status,
                confirm_by=(_pending(tenant_id) or {}).get("confirm_by"),
                error=error,
            ),
        )
    return output


def _status(
    active: Model | None,
    candidate: Model | None,
) -> Literal["UNCHANGED", "MODIFIED", "ADDED", "DELETED"]:
    if active is None:
        return "ADDED" if candidate is not None else "UNCHANGED"
    if candidate is None:
        return "DELETED"
    return "UNCHANGED" if _same(active, candidate) else "MODIFIED"


def read(tenant_id: str, revision: Revision, *, reveal: bool) -> dict[str, Any]:
    """Return a configuration revision."""
    check_id(tenant_id)
    if (model := _load(tenant_id, revision)) is None:
        detail = f"No {revision} configuration of {tenant_id}."
        if revision == "candidate" and _exists(tenant_id):
            detail = f"Removing {tenant_id} is staged."
        elif error := configuration.NOT_LOADED.get(tenant_id):
            detail = f"{tenant_id} doesn't run: its active file isn't loaded: {error}."
        raise ConfigError(404, "Not found", detail)
    return _dump(model, reveal=reveal)  # type: ignore[return-value]


@functools.cache
def _schema(*, service: bool) -> dict[str, Any]:
    if service:
        # Of both modes: its mode says which applies.
        return TypeAdapter(tenant.ServiceHub | tenant.ServiceEndpoint).json_schema()
    return tenant.Tenant.model_json_schema()


def schema(tenant_id: str) -> dict[str, Any]:
    """Return the JSON Schema of a tenant's or the service's configuration."""
    check_id(tenant_id)
    return _schema(service=tenant_id == config.DEFAULT_TENANT)


def write_candidate(tenant_id: str, data: Any) -> dict[str, Any]:  # noqa: ANN401
    """Validate and stage a configuration; return it as stored."""
    check_id(tenant_id)
    model = validate(tenant_id, data)
    with LOCK:
        files.ensure_file(
            _path(tenant_id, "candidate"),
            _yaml(_dump(model, reveal=True)),
            secret=True,
        )
    return _dump(model, reveal=False)  # type: ignore[return-value]


def merge_patch(target: Any, patch: Any) -> Any:  # noqa: ANN401
    """Apply an RFC 7386 JSON merge patch: null removes, objects merge."""
    if not isinstance(patch, dict):
        return patch
    result = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        # Connections have integer keys; isdigit() alone is true for e.g. "²".
        existing = key
        if (
            key not in result
            and isinstance(key, str)
            and key.isascii()
            and key.isdigit()
        ):
            existing = int(key) if int(key) in result else key
        if value is None:
            result.pop(existing, None)
        else:
            result[existing] = merge_patch(result.get(existing), value)
    return result


def add_candidate(new: NewTenant) -> dict[str, Any]:
    """Stage a new tenant with only its name; return it as stored."""
    with LOCK:
        if _exists(new.id) or _text(new.id, "candidate") is not None:
            detail = f"{new.id} has configuration already (active or staged)."
            raise ConfigError(409, "Conflict", detail)
        data = {"version": VERSION, "id": new.id, "name": new.name}
        return write_candidate(new.id, data)


def patch_candidate(tenant_id: str, patch: Any) -> dict[str, Any]:  # noqa: ANN401
    """Stage changes (a merge patch) on top of the staged configuration.

    A tenant without one is added first, or staged whole (PUT).
    """
    check_id(tenant_id)
    with LOCK:
        base = _dump(_load(tenant_id, "candidate"), reveal=True)
        if base is None:
            if _text(tenant_id, "candidate") is not None:
                detail = f"Removing {tenant_id} is staged: discard that first."
                raise ConfigError(409, "Conflict", detail)
            if _exists(tenant_id):
                detail = f"{tenant_id}'s active file isn't loaded: stage it whole."
                raise ConfigError(409, "Conflict", detail)
            detail = f"No configuration of {tenant_id}: add the tenant first."
            raise ConfigError(404, "Not found", detail)
        return write_candidate(tenant_id, merge_patch(base, patch))


def delete_candidate(tenant_id: str) -> CommitResult:
    """Stage removing a tenant."""
    check_id(tenant_id)
    _keep_service(tenant_id)
    with LOCK:
        if _load(tenant_id, "candidate") is None:
            if _text(tenant_id, "candidate") is not None:
                # Staged already.
                return CommitResult(id=tenant_id, changed=False)
            if not _exists(tenant_id):
                detail = f"No configuration of {tenant_id}."
                raise ConfigError(404, "Not found", detail)
        if not _exists(tenant_id):
            # Only staged: nothing to remove on commit.
            _path(tenant_id, "candidate").unlink()
        else:
            files.ensure_file(_path(tenant_id, "candidate"), "", secret=True)
    return CommitResult(id=tenant_id, changed=True)


def diff(tenant_id: str) -> str:
    """Return a unified diff of the staged changes.

    Secrets are hidden; a changed secret doesn't show.
    """
    check_id(tenant_id)
    texts = [
        _yaml(_dump(_load(tenant_id, revision), reveal=False))
        for revision in ("active", "candidate")
    ]
    return "".join(
        difflib.unified_diff(
            texts[0].splitlines(keepends=True),
            texts[1].splitlines(keepends=True),
            fromfile=f"active/{tenant_id}.yaml",
            tofile=f"candidate/{tenant_id}.yaml",
        ),
    )


def _now() -> dt.datetime:
    return dt.datetime.now().astimezone()


def _history_path(tenant_id: str, revision: int) -> pathlib.Path:
    return HISTORY_DIR / tenant_id / f"{revision}.yaml"


def _save_history(tenant_id: str, text: str | None) -> None:
    """Keep a replaced active configuration as revision 1."""
    first = _history_path(tenant_id, 1)
    first.parent.mkdir(mode=files.SECRET_DIR_MODE, parents=True, exist_ok=True)
    content = text or ""
    if first.exists() and first.read_text(encoding="utf-8") == content:
        return
    _history_path(tenant_id, HISTORY).unlink(missing_ok=True)
    for revision in range(HISTORY - 1, 0, -1):
        if (path := _history_path(tenant_id, revision)).exists():
            path.rename(_history_path(tenant_id, revision + 1))
    files.ensure_file(first, content, secret=True)


def _activate(tenant_id: str, model: Model | None) -> None:
    """Write (or with None remove) the active file, and run it."""
    path = _path(tenant_id, "active")
    if model is None:
        path.unlink(missing_ok=True)
        configuration.delete_tenant(path)
        return
    files.ensure_file(path, _yaml(_dump(model, reveal=True)), secret=True)
    configuration.run(model, path)


def _pending_path(tenant_id: str) -> pathlib.Path:
    return HISTORY_DIR / tenant_id / "pending.json"


def _pending_ids() -> list[str]:
    """Return the tenants (and service) with a commit to confirm."""
    return sorted(p.parent.name for p in HISTORY_DIR.glob("*/pending.json"))


def _pending(tenant_id: str) -> dict[str, Any] | None:
    try:
        return json.loads(_pending_path(tenant_id).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def _clear_pending(tenant_id: str) -> bool:
    if timer := TIMERS.pop(tenant_id, None):
        timer.cancel()
    path = _pending_path(tenant_id)
    existed = path.exists()
    path.unlink(missing_ok=True)
    return existed


def _committed(tenant_id: str, confirm: int | None) -> None:
    what = "configuration committed" if _exists(tenant_id) else "removed"
    if confirm:
        what += f", rolled back unless confirmed in {eventlog.duration(confirm)}"
    eventlog.record("CONFIG_COMMITTED", what, tenant=tenant_id)


def _confirmed(tenant_id: str) -> None:
    eventlog.record("CONFIG_CONFIRMED", "commit confirmed", tenant=tenant_id)


def _schedule(tenant_id: str, confirm_by: str) -> None:
    if timer := TIMERS.pop(tenant_id, None):
        timer.cancel()
    delay = dt.datetime.fromisoformat(confirm_by) - _now()
    timer = threading.Timer(
        max(delay.total_seconds(), 0),
        _roll_back_unconfirmed,
        args=(tenant_id,),
    )
    timer.daemon = True
    TIMERS[tenant_id] = timer
    timer.start()


def _roll_back_unconfirmed(tenant_id: str) -> None:
    """Restore the configuration from before an unconfirmed commit.

    The unconfirmed changes stay staged.
    """
    with LOCK:
        if (pending := _pending(tenant_id)) is None:
            return
        rollback = pending["rollback"]
        _activate(
            tenant_id,
            validate(tenant_id, yaml.safe_load(rollback)) if rollback else None,
        )
        _clear_pending(tenant_id)
        eventlog.record(
            "CONFIG_ROLLED_BACK",
            "configuration rolled back: the commit wasn't confirmed",
            tenant=tenant_id,
            level=logging.WARNING,
        )


def resume_pending() -> None:
    """Schedule the rollbacks of unconfirmed commits (e.g. after a restart)."""
    for tenant_id in _pending_ids():
        if pending := _pending(tenant_id):
            logger.warning(
                "The commit of %s isn't confirmed; rolling back at %s.",
                tenant_id,
                pending["confirm_by"],
            )
            _schedule(tenant_id, pending["confirm_by"])


def _node_tenants(candidates: dict[str, Model | None]) -> dict[str, Model]:
    """Return the configurations running on this node, with the candidates."""
    running = {
        tenant_id: model
        for tenant_id, model in config.VPNC_CONFIG_TENANT.items()
        if tenant_id not in candidates
    }
    return running | {k: v for k, v in candidates.items() if v is not None}


def check_conflicts(candidates: dict[str, Model | None]) -> None:
    """Refuse candidates that conflict with another tenant or this node.

    A WireGuard port or PPK id another connection uses, a route without NPTv6
    that overlaps another route in CORE, or post-quantum cryptography this node
    doesn't support.
    """
    tenants = _node_tenants(candidates)
    own = {
        connection.name(ni)
        for tenant_id in candidates
        if tenant_id in tenants
        for ni in tenants[tenant_id].network_instances.values()
        for connection in ni.connections.values()
    }
    for what, users in (
        ("WireGuard port", wireguard_port_users(tenants.values())),
        ("PPK id", ppk_id_users(tenants.values())),
    ):
        for value, names in users.items():
            if len(names) > 1 and own & set(names):
                raise ConfigError(
                    422,
                    "Invalid configuration",
                    f"{what} {value} is used by {', '.join(names)}.",
                )
    if config.DEFAULT_TENANT in candidates:
        # The service's prefixes.
        own |= set(tenant.MAX_PREFIX_LENGTHS)
    for route, of, other, other_of in tenant.core_route_overlaps(tenants.values()):
        if of not in own:
            # The candidate's route first.
            route, of, other, other_of = other, other_of, route, of  # noqa: PLW2901
        if of in own:
            raise ConfigError(
                422,
                "Invalid configuration",
                f"Route {route} of {of} overlaps {other} of {other_of}.",
            )
    for model in candidates.values():
        if model is not None:
            _check_post_quantum(model)
            _check_proposals(model)


def _check_proposals(model: Model) -> None:
    """Refuse IPsec proposals charon doesn't accept."""
    _check_algorithms(model)
    for ni in model.network_instances.values():
        for connection in ni.connections.values():
            if connection.config.type != enums.ConnectionType.IPSEC:
                continue
            name = connection.name(ni)
            try:
                refused = strongswan.refused_proposals(connection.config)
            except strongswan.VICI_ERRORS:
                raise ConfigError(
                    503,
                    "charon unavailable",
                    f"Can't check the proposals of {name} with charon.",
                ) from None
            if refused:
                value = getattr(connection.config, refused)
                raise ConfigError(
                    422,
                    "Invalid configuration",
                    f"{name}: charon doesn't accept {refused} {value}.",
                )


def _added_weaknesses(tenant_id: str, candidate: Model | None) -> list[str]:
    """Return the weak cryptography a candidate adds to its IPsec connections.

    What the active configuration has already, with the same setting, stays
    without asking: e.g. the short PSK of a connection that's in use.
    """
    if candidate is None:
        return []
    active = _load(tenant_id, "active")
    before = {
        connection.name(ni): connection.config.weaknesses()
        for ni in (active.network_instances.values() if active else [])
        for connection in ni.connections.values()
        if connection.config.type == enums.ConnectionType.IPSEC
    }
    return [
        f"{connection.name(ni)}: {what}"
        for ni in candidate.network_instances.values()
        for connection in ni.connections.values()
        if connection.config.type == enums.ConnectionType.IPSEC
        for kind, (what, setting) in connection.config.weaknesses().items()
        if before.get(connection.name(ni), {}).get(kind, (None, None))[1] != setting
    ]


def _check_weak(candidates: dict[str, Model | None], *, allow: bool) -> list[str]:
    """Refuse candidates that add weak cryptography, unless allowed; return it."""
    added = [
        weakness
        for tenant_id, candidate in candidates.items()
        for weakness in _added_weaknesses(tenant_id, candidate)
    ]
    if added and not allow:
        raise ConfigError(
            422,
            "Weak cryptography",
            "; ".join(added) + ". Commit with --allow-weak to accept it.",
        )
    for weakness in added:
        logger.warning("Committed with weak cryptography: %s.", weakness)
    return added


def _check_post_quantum(model: Model) -> None:
    """Refuse post-quantum cryptography that charon or OpenSSH lacks."""
    for ni in model.network_instances.values():
        for connection in ni.connections.values():
            cfg = connection.config
            if not getattr(cfg, "post_quantum", None) or not cfg.post_quantum.enabled:
                continue
            name = connection.name(ni)
            missing = None
            if cfg.type == enums.ConnectionType.IPSEC:
                supported = strongswan.supported_key_exchanges()
                if supported is None:
                    raise ConfigError(
                        503,
                        "charon unavailable",
                        f"Can't check the ML-KEM support of charon for {name}.",
                    )
                if cfg.post_quantum.ml_kem.value not in supported:
                    missing = f"charon lacks {cfg.post_quantum.ml_kem.value}"
            elif cfg.type == enums.ConnectionType.SSH and (
                kex := ssh.unsupported_kex(cfg)
            ):
                missing = f"OpenSSH lacks {kex}"
            if missing:
                raise ConfigError(
                    422,
                    "Invalid configuration",
                    f"{name}: {missing}; Ubuntu 26.04 is required.",
                )


# How a commit makes a secret that isn't set, by its path in a connection's config.
SECRET_MAKERS = {
    "psk": lambda: keys.random_secret("text"),
    "post_quantum.ppk.key": lambda: keys.random_secret("text"),
    "private_key": keys.wireguard_private_key,
    "post_quantum.ppk": lambda: keys.random_secret("base64"),
}


def _fill_secrets(model: Model) -> list[str]:
    """Generate the secrets a configuration lacks; return which."""
    generated = []
    for ni in model.network_instances.values():
        for connection in ni.connections.values():
            cfg = connection.config
            for path in cfg.unset_secrets():
                *parents, field = path.split(".")
                target = cfg
                for parent in parents:
                    target = getattr(target, parent)
                setattr(target, field, SecretStr(SECRET_MAKERS[path]()))
                generated.append(f"{connection.name(ni)} {path}")
    return generated


def _fill_ppk_ids(model: Model) -> bool:
    """Write the default PPK ids into a configuration; return whether any.

    Written, they no longer follow a changed hostname.
    """
    filled = False
    for ni in model.network_instances.values():
        for connection in ni.connections.values():
            cfg = connection.config
            if cfg.type != enums.ConnectionType.IPSEC:
                continue
            ppk = cfg.post_quantum.ppk
            if not (cfg.post_quantum.enabled and ppk) or ppk.id is not None:
                continue
            ppk_id = cfg.ppk_id(ni, connection)
            try:
                PostQuantumPresharedKey(id=ppk_id, key=ppk.key)
            except ValidationError as exc:
                raise ConfigError(
                    422,
                    "Invalid configuration",
                    f"{connection.name(ni)}: the default PPK id {ppk_id} isn't "
                    "valid; set post_quantum.ppk.id.",
                ) from exc
            ppk.id = ppk_id
            filled = True
    return filled


def commit(
    tenant_id: str,
    confirm: int | None = None,
    *,
    check_node: bool = True,
    allow_weak: bool = False,
) -> CommitResult:
    """Make the staged changes active.

    With confirm (seconds), roll back unless confirmed in time; a commit
    without it confirms. commit_all checks all at once. Weak cryptography (a
    short PSK, IKEv1, weak algorithms) is only added with allow_weak.
    """
    check_id(tenant_id)
    with LOCK:
        running = _running(tenant_id)
        previous = _yaml(_dump(running, reveal=True)) or None
        changed = False
        warnings: list[str] = []
        generated: list[str] = []
        not_loaded = tenant_id in configuration.NOT_LOADED
        # Also when nothing is staged, the active file that isn't loaded of a
        # tenant that runs is replaced by what runs.
        if _text(tenant_id, "candidate") is not None or (
            not_loaded and running is not None
        ):
            candidate = _load(tenant_id, "candidate")
            if candidate is None:
                _keep_service(tenant_id)
            if check_node:
                check_conflicts({tenant_id: candidate})
            generated = _fill_secrets(candidate) if candidate is not None else []
            warnings = _check_weak({tenant_id: candidate}, allow=allow_weak)
            ids_filled = candidate is not None and _fill_ppk_ids(candidate)
            filled = ids_filled or bool(generated)
            if not _same(candidate, running) or not_loaded:
                _activate(tenant_id, candidate)
                changed = True
                if filled:
                    # So what's filled in doesn't show as staged changes.
                    text = _yaml(_dump(candidate, reveal=True))
                    files.ensure_file(_path(tenant_id, "candidate"), text, secret=True)
            if candidate is None:
                _path(tenant_id, "candidate").unlink(missing_ok=True)
        if changed:
            _save_history(tenant_id, previous)
            _committed(tenant_id, confirm)
        restart = restart_needed() if tenant_id == config.DEFAULT_TENANT else []
        pending = _pending(tenant_id)
        if confirm is None or not (changed or pending):
            if pending and confirm is None:
                _clear_pending(tenant_id)
                _confirmed(tenant_id)
            return CommitResult(
                id=tenant_id,
                changed=changed,
                restart_needed=restart,
                warnings=warnings,
                generated=generated,
            )
        # A new confirmed commit rolls back to before the first.
        confirm_by = (_now() + dt.timedelta(seconds=confirm)).isoformat(
            timespec="seconds",
        )
        rollback = pending["rollback"] if pending else previous
        files.ensure_file(
            _pending_path(tenant_id),
            json.dumps({"confirm_by": confirm_by, "rollback": rollback}),
            secret=True,
        )
        _schedule(tenant_id, confirm_by)
        return CommitResult(
            id=tenant_id,
            changed=changed,
            confirm_by=confirm_by,
            restart_needed=restart,
            warnings=warnings,
            generated=generated,
        )


def set_enabled(tenant_id: str, connection: str, *, enabled: bool) -> None:
    """Enable or disable a connection (e.g. C0001-00-0) in its configuration.

    In the active configuration, which is loaded right away, and in staged
    changes: a commit doesn't undo it. It isn't a commit: no history is kept.
    """
    ni_id, number = helpers.split_connection_name(connection)
    path = _path(tenant_id, "active")
    with LOCK:
        staged = _text(tenant_id, "candidate") is not None
        revisions: list[Revision] = ["active", "candidate"] if staged else ["active"]
        for revision in revisions:
            model = _load(tenant_id, revision)
            found = [
                ni.connections[int(number)]
                for ni in (model.network_instances.values() if model else [])
                if ni.id == ni_id and int(number) in ni.connections
            ]
            if not found or found[0].enabled == enabled:
                continue
            found[0].enabled = enabled
            text = _yaml(_dump(model, reveal=True))
            files.ensure_file(_path(tenant_id, revision), text, secret=True)
        configuration.manage_tenant(path)


def confirm(tenant_id: str) -> CommitResult:
    """Confirm a commit, so it isn't rolled back."""
    check_id(tenant_id)
    with LOCK:
        if not _clear_pending(tenant_id):
            raise ConfigError(409, "Conflict", f"{tenant_id} has no commit to confirm.")
    _confirmed(tenant_id)
    return CommitResult(id=tenant_id, changed=True)


def history(tenant_id: str) -> list[HistoryEntry]:
    """Return the earlier active configurations, most recent first."""
    check_id(tenant_id)
    output: list[HistoryEntry] = []
    for revision in range(1, HISTORY + 1):
        path = _history_path(tenant_id, revision)
        try:
            stat = path.stat()
        except FileNotFoundError:
            break
        replaced = dt.datetime.fromtimestamp(stat.st_mtime).astimezone()
        output.append(
            HistoryEntry(
                revision=revision,
                replaced=replaced.isoformat(timespec="seconds"),
                exists=stat.st_size > 0,
            ),
        )
    return output


def _history_text(tenant_id: str, revision: int) -> str:
    check_id(tenant_id)
    try:
        return _history_path(tenant_id, revision).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(
            404,
            "Not found",
            f"{tenant_id} has no revision {revision}.",
        ) from None


def read_history(tenant_id: str, revision: int, *, reveal: bool) -> dict[str, Any]:
    """Return an earlier active configuration."""
    if not (text := _history_text(tenant_id, revision).strip()):
        detail = f"{tenant_id} didn't exist at revision {revision}."
        raise ConfigError(404, "Not found", detail)
    return _dump(validate(tenant_id, yaml.safe_load(text)), reveal=reveal)  # type: ignore[return-value]


def restore(tenant_id: str, revision: int) -> CommitResult:
    """Stage an earlier active configuration (commit to apply it)."""
    text = _history_text(tenant_id, revision)
    with LOCK:
        if text.strip():
            write_candidate(tenant_id, yaml.safe_load(text))
        elif not _exists(tenant_id):
            _path(tenant_id, "candidate").unlink(missing_ok=True)
        else:
            delete_candidate(tenant_id)
    return CommitResult(id=tenant_id, changed=_changed(tenant_id))


def discard(tenant_id: str) -> CommitResult:
    """Drop the staged changes."""
    check_id(tenant_id)
    with LOCK:
        changed = staged(tenant_id)
        _path(tenant_id, "candidate").unlink(missing_ok=True)
    return CommitResult(id=tenant_id, changed=changed)


def _staged_ids() -> list[str]:
    """Return the tenants (and service) with a candidate file or pending commit."""
    ids = {
        p.stem
        for p in DIRS["candidate"].glob("*.yaml")
        if config.TENANT_RE.match(p.stem)
    }
    return sorted(ids | set(_pending_ids()))


def commit_all(
    confirm: int | None = None,
    *,
    allow_weak: bool = False,
) -> list[CommitResult]:
    """Commit the staged changes of all tenants and the service.

    All are validated first, so an invalid one stops the commit of all.
    """
    with LOCK:
        staged = _staged_ids()
        candidates = {tenant_id: _load(tenant_id, "candidate") for tenant_id in staged}
        check_conflicts(candidates)
        _check_weak(candidates, allow=allow_weak)
        results = [
            commit(tenant_id, confirm, check_node=False, allow_weak=True)
            for tenant_id in staged
        ]
    return [r for r in results if r.changed or r.confirm_by or r.restart_needed]


def confirm_all() -> list[CommitResult]:
    """Confirm all commits."""
    return [confirm(tenant_id) for tenant_id in _pending_ids()]


def discard_all() -> list[CommitResult]:
    """Drop the staged changes of all tenants and the service."""
    results = [discard(tenant_id) for tenant_id in _staged_ids()]
    return [r for r in results if r.changed]
