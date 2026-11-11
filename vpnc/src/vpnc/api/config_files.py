"""The active and candidate (staged) configuration files of tenants and the service.

A tenant (or the service, DEFAULT) has an active file, which vpnc applies, and
may have a candidate file with staged changes; a commit makes them active.
Without a candidate file nothing is staged; an empty one stages removing the
tenant.

A commit keeps the active configuration it replaces in the history (empty: the
tenant didn't exist). A confirmed commit is rolled back unless confirmed in
time; the rollback is stored, so it also happens after vpnc restarts.
"""

from __future__ import annotations

import datetime
import difflib
import json
import logging
import threading
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel

from vpnc import config, files
from vpnc.models import tenant
from vpnc.models.secret import REVEAL

if TYPE_CHECKING:
    import pathlib

Revision = Literal["active", "candidate"]
DIRS: dict[Revision, pathlib.Path] = {
    "active": config.VPNC_A_CONFIG_DIR,
    "candidate": config.VPNC_C_CONFIG_DIR,
}
# The configuration version of new tenants.
VERSION = "0.1.3"
HISTORY_DIR = config.VPNC_A_CONFIG_DIR.parent / "history"
# Revisions kept per tenant; 1 is the most recent.
HISTORY = 5

logger = logging.getLogger("vpnc")
# Commits, confirms and rollbacks (also from timers).
LOCK = threading.RLock()
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
    status: Literal["unchanged", "modified", "added", "deleted"]
    # A commit to confirm before then, or it's rolled back.
    confirm_by: str | None = None


class CommitResult(BaseModel):
    """The result of a commit, confirm, discard, delete or restore."""

    id: str
    changed: bool
    confirm_by: str | None = None
    # Service settings that only apply after vpnc restarts.
    restart_needed: list[str] = []


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
    return model


def _load(tenant_id: str, revision: Revision) -> Model | None:
    """Return a revision; the candidate is the active one unless changes are staged.

    None if there's none, or removing the tenant is staged.
    """
    text = _text(tenant_id, revision)
    if text is None and revision == "candidate":
        return _load(tenant_id, "active")
    if text is None or not text.strip():
        return None
    return validate(tenant_id, yaml.safe_load(text))


def _dump(model: Model | None, *, reveal: bool) -> dict[str, Any] | None:
    if model is None:
        return None
    return model.model_dump(mode="json", context=REVEAL if reveal else None)


def _yaml(data: dict[str, Any] | None) -> str:
    if data is None:
        return ""
    return yaml.safe_dump(data, explicit_start=True, explicit_end=True)


def summaries() -> list[ConfigSummary]:
    """Return the tenants with configuration (not the service)."""
    ids = {
        p.stem
        for directory in DIRS.values()
        for p in directory.glob("*.yaml")
        if config.TENANT_RE.match(p.stem) and p.stem != config.DEFAULT_TENANT
    }
    output: list[ConfigSummary] = []
    for tenant_id in sorted(ids):
        active, candidate = _load(tenant_id, "active"), _load(tenant_id, "candidate")
        if active is None and candidate is None:
            continue
        if active is None:
            status = "added"
        elif candidate is None:
            status = "deleted"
        elif _dump(active, reveal=True) != _dump(candidate, reveal=True):
            status = "modified"
        else:
            status = "unchanged"
        output.append(
            ConfigSummary(
                id=tenant_id,
                name=(candidate or active).name,  # type: ignore[union-attr]
                status=status,
                confirm_by=(_pending(tenant_id) or {}).get("confirm_by"),
            ),
        )
    return output


def read(tenant_id: str, revision: Revision, *, reveal: bool) -> dict[str, Any]:
    """Return a configuration revision."""
    check_id(tenant_id)
    if (model := _load(tenant_id, revision)) is None:
        detail = f"No {revision} configuration of {tenant_id}."
        if revision == "candidate" and _text(tenant_id, "active") is not None:
            detail = f"Removing {tenant_id} is staged."
        raise ConfigError(404, "Not found", detail)
    return _dump(model, reveal=reveal)  # type: ignore[return-value]


def write_candidate(tenant_id: str, data: Any) -> dict[str, Any]:  # noqa: ANN401
    """Validate and stage a configuration; return it as stored."""
    check_id(tenant_id)
    model = validate(tenant_id, data)
    files.ensure_file(_path(tenant_id, "candidate"), _yaml(_dump(model, reveal=True)))
    return _dump(model, reveal=False)  # type: ignore[return-value]


def merge_patch(target: Any, patch: Any) -> Any:  # noqa: ANN401
    """Apply an RFC 7386 JSON merge patch: null removes, objects merge."""
    if not isinstance(patch, dict):
        return patch
    result = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        # Connections have integer keys.
        existing = key
        if key not in result and isinstance(key, str) and key.isdigit():
            existing = int(key) if int(key) in result else key
        if value is None:
            result.pop(existing, None)
        else:
            result[existing] = merge_patch(result.get(existing), value)
    return result


def patch_candidate(tenant_id: str, patch: Any) -> dict[str, Any]:  # noqa: ANN401
    """Stage changes (a merge patch) on top of the staged configuration.

    A tenant without configuration starts empty.
    """
    check_id(tenant_id)
    base = _dump(_load(tenant_id, "candidate"), reveal=True)
    if base is None:
        base = {"version": VERSION, "id": tenant_id}
    return write_candidate(tenant_id, merge_patch(base, patch))


def delete_candidate(tenant_id: str) -> CommitResult:
    """Stage removing a tenant."""
    check_id(tenant_id)
    if tenant_id == config.DEFAULT_TENANT:
        raise ConfigError(409, "Conflict", "The service can't be removed.")
    if _load(tenant_id, "candidate") is None:
        if _text(tenant_id, "active") is None:
            raise ConfigError(404, "Not found", f"No configuration of {tenant_id}.")
        return CommitResult(id=tenant_id, changed=False)
    if _text(tenant_id, "active") is None:
        # Only staged: nothing to remove on commit.
        _path(tenant_id, "candidate").unlink()
    else:
        files.ensure_file(_path(tenant_id, "candidate"), "")
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


def _now() -> datetime.datetime:
    return datetime.datetime.now().astimezone()


def _history_path(tenant_id: str, revision: int) -> pathlib.Path:
    return HISTORY_DIR / tenant_id / f"{revision}.yaml"


def _save_history(tenant_id: str, text: str | None) -> None:
    """Keep a replaced active configuration as revision 1."""
    first = _history_path(tenant_id, 1)
    first.parent.mkdir(parents=True, exist_ok=True)
    content = text or ""
    if first.exists() and first.read_text(encoding="utf-8") == content:
        return
    _history_path(tenant_id, HISTORY).unlink(missing_ok=True)
    for revision in range(HISTORY - 1, 0, -1):
        if (path := _history_path(tenant_id, revision)).exists():
            path.rename(_history_path(tenant_id, revision + 1))
    first.write_text(content, encoding="utf-8")


def _set_active(tenant_id: str, text: str | None) -> bool:
    """Write (or with None remove) the active file; return whether it changed."""
    path = _path(tenant_id, "active")
    if text is None or not text.strip():
        changed = path.exists()
        path.unlink(missing_ok=True)
        return changed
    # Written in place: the configuration watcher applies modified files.
    return files.ensure_file(path, text)


def _pending_path(tenant_id: str) -> pathlib.Path:
    return HISTORY_DIR / tenant_id / "pending.json"


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


def _schedule(tenant_id: str, confirm_by: str) -> None:
    if timer := TIMERS.pop(tenant_id, None):
        timer.cancel()
    delay = datetime.datetime.fromisoformat(confirm_by) - _now()
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
        _set_active(tenant_id, pending["rollback"])
        _clear_pending(tenant_id)
        logger.warning("Rolled back %s: the commit wasn't confirmed.", tenant_id)


def resume_pending() -> None:
    """Schedule the rollbacks of unconfirmed commits (e.g. after a restart)."""
    for path in HISTORY_DIR.glob("*/pending.json"):
        tenant_id = path.parent.name
        if pending := _pending(tenant_id):
            logger.warning(
                "The commit of %s isn't confirmed; rolling back at %s.",
                tenant_id,
                pending["confirm_by"],
            )
            _schedule(tenant_id, pending["confirm_by"])


def commit(tenant_id: str, confirm: int | None = None) -> CommitResult:
    """Make the staged changes active.

    With confirm (seconds), roll back unless confirmed in time; a commit
    without it confirms.
    """
    check_id(tenant_id)
    with LOCK:
        previous = _text(tenant_id, "active")
        changed = False
        if _text(tenant_id, "candidate") is not None:
            candidate = _dump(_load(tenant_id, "candidate"), reveal=True)
            # Only changed configurations: the files may differ in formatting.
            if candidate != _dump(_load(tenant_id, "active"), reveal=True):
                changed = _set_active(tenant_id, _yaml(candidate) or None)
            if candidate is None:
                _path(tenant_id, "candidate").unlink()
        if changed:
            _save_history(tenant_id, previous)
        restart = restart_needed() if tenant_id == config.DEFAULT_TENANT else []
        pending = _pending(tenant_id)
        if confirm is None or not (changed or pending):
            if pending and confirm is None:
                _clear_pending(tenant_id)
                logger.info("Confirmed the commit of %s.", tenant_id)
            return CommitResult(id=tenant_id, changed=changed, restart_needed=restart)
        # A new confirmed commit rolls back to before the first.
        confirm_by = (_now() + datetime.timedelta(seconds=confirm)).isoformat(
            timespec="seconds",
        )
        rollback = pending["rollback"] if pending else previous
        _pending_path(tenant_id).write_text(
            json.dumps({"confirm_by": confirm_by, "rollback": rollback}),
            encoding="utf-8",
        )
        _schedule(tenant_id, confirm_by)
        return CommitResult(
            id=tenant_id,
            changed=changed,
            confirm_by=confirm_by,
            restart_needed=restart,
        )


def confirm(tenant_id: str) -> CommitResult:
    """Confirm a commit, so it isn't rolled back."""
    check_id(tenant_id)
    with LOCK:
        if not _clear_pending(tenant_id):
            raise ConfigError(409, "Conflict", f"{tenant_id} has no commit to confirm.")
    logger.info("Confirmed the commit of %s.", tenant_id)
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
        replaced = datetime.datetime.fromtimestamp(stat.st_mtime).astimezone()
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
        elif _text(tenant_id, "active") is None:
            _path(tenant_id, "candidate").unlink(missing_ok=True)
        else:
            delete_candidate(tenant_id)
    changed = _dump(_load(tenant_id, "candidate"), reveal=True) != _dump(
        _load(tenant_id, "active"),
        reveal=True,
    )
    return CommitResult(id=tenant_id, changed=changed)


def discard(tenant_id: str) -> CommitResult:
    """Drop the staged changes."""
    check_id(tenant_id)
    changed = _dump(_load(tenant_id, "candidate"), reveal=True) != _dump(
        _load(tenant_id, "active"),
        reveal=True,
    )
    _path(tenant_id, "candidate").unlink(missing_ok=True)
    return CommitResult(id=tenant_id, changed=changed)


def _staged_ids() -> list[str]:
    """Return the tenants (and service) with a candidate file or pending commit."""
    ids = {
        p.stem
        for p in DIRS["candidate"].glob("*.yaml")
        if config.TENANT_RE.match(p.stem)
    } | {p.parent.name for p in HISTORY_DIR.glob("*/pending.json")}
    return sorted(ids)


def commit_all(confirm: int | None = None) -> list[CommitResult]:
    """Commit the staged changes of all tenants and the service."""
    results = [commit(tenant_id, confirm) for tenant_id in _staged_ids()]
    return [r for r in results if r.changed or r.confirm_by or r.restart_needed]


def confirm_all() -> list[CommitResult]:
    """Confirm all commits."""
    return [
        confirm(p.parent.name) for p in sorted(HISTORY_DIR.glob("*/pending.json"))
    ]


def discard_all() -> list[CommitResult]:
    """Drop the staged changes of all tenants and the service."""
    results = [discard(tenant_id) for tenant_id in _staged_ids()]
    return [r for r in results if r.changed]
