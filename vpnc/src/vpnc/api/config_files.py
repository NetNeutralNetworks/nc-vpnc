"""The active and candidate (staged) configuration files of tenants and the service.

A tenant (or the service, DEFAULT) has an active file, which vpnc applies, and
may have a candidate file with staged changes; a commit makes them active.
Without a candidate file nothing is staged; an empty one stages removing the
tenant.
"""

from __future__ import annotations

import difflib
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


class CommitResult(BaseModel):
    """The result of a commit, discard or delete."""

    id: str
    changed: bool


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


def commit(tenant_id: str) -> CommitResult:
    """Make the staged changes active."""
    check_id(tenant_id)
    active_path = _path(tenant_id, "active")
    text = _text(tenant_id, "candidate")
    if text is None:
        return CommitResult(id=tenant_id, changed=False)
    candidate = _load(tenant_id, "candidate")
    if candidate is None:
        changed = active_path.exists()
        active_path.unlink(missing_ok=True)
        _path(tenant_id, "candidate").unlink()
        return CommitResult(id=tenant_id, changed=changed)
    # Written in place: the configuration watcher applies modified files.
    changed = files.ensure_file(active_path, _yaml(_dump(candidate, reveal=True)))
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
