"""The candidate and active configuration files of tenants and the service.

A tenant (or the service, DEFAULT) has one file per revision. Committing copies
the candidate to the active file, which vpnc applies; a missing candidate removes
the tenant on commit.
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


class ConfigError(Exception):
    """A configuration request can't be fulfilled."""

    def __init__(self, status: int, title: str, detail: str | Any) -> None:  # noqa: ANN401
        """Store the HTTP status, title and detail for the response."""
        super().__init__(title)
        self.status = status
        self.title = title
        self.detail = detail


class ConfigSummary(BaseModel):
    """A configuration file per revision."""

    id: str
    name: str | None
    active: bool
    candidate: bool
    # The candidate differs from the active configuration.
    changed: bool


class CommitResult(BaseModel):
    """The result of a commit or discard."""

    id: str
    changed: bool


Model = tenant.Tenant | tenant.ServiceHub | tenant.ServiceEndpoint


def check_id(tenant_id: str) -> None:
    """Raise a 404 for ids that can't be tenants."""
    if not config.TENANT_RE.match(tenant_id):
        raise ConfigError(404, "Not found", f"'{tenant_id}' isn't a valid tenant id.")


def _path(tenant_id: str, revision: Revision) -> pathlib.Path:
    return DIRS[revision].joinpath(f"{tenant_id}.yaml")


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
    try:
        text = _path(tenant_id, revision).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return validate(tenant_id, yaml.safe_load(text))


def _dump(model: Model, *, reveal: bool) -> dict[str, Any]:
    return model.model_dump(mode="json", context=REVEAL if reveal else None)


def _yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, explicit_start=True, explicit_end=True)


def summaries() -> list[ConfigSummary]:
    """Return the tenants with configuration files (not the service)."""
    ids = {
        p.stem
        for directory in DIRS.values()
        for p in directory.glob("*.yaml")
        if config.TENANT_RE.match(p.stem) and p.stem != config.DEFAULT_TENANT
    }
    output: list[ConfigSummary] = []
    for tenant_id in sorted(ids):
        active, candidate = _load(tenant_id, "active"), _load(tenant_id, "candidate")
        name = (candidate or active).name if (candidate or active) else None
        changed = (
            active is None
            or candidate is None
            or _dump(active, reveal=True) != _dump(candidate, reveal=True)
        )
        output.append(
            ConfigSummary(
                id=tenant_id,
                name=name,
                active=active is not None,
                candidate=candidate is not None,
                changed=changed,
            ),
        )
    return output


def read(tenant_id: str, revision: Revision, *, reveal: bool) -> dict[str, Any]:
    """Return a configuration revision."""
    check_id(tenant_id)
    if (model := _load(tenant_id, revision)) is None:
        raise ConfigError(404, "Not found", f"No {revision} configuration.")
    return _dump(model, reveal=reveal)


def write_candidate(tenant_id: str, data: Any) -> dict[str, Any]:  # noqa: ANN401
    """Validate and store a candidate configuration; return it as stored."""
    check_id(tenant_id)
    model = validate(tenant_id, data)
    files.ensure_file(_path(tenant_id, "candidate"), _yaml(_dump(model, reveal=True)))
    return _dump(model, reveal=False)


def diff(tenant_id: str) -> str:
    """Return a unified diff from the active to the candidate configuration.

    Secrets are hidden; a changed secret doesn't show.
    """
    check_id(tenant_id)
    texts = []
    for revision in ("active", "candidate"):
        model = _load(tenant_id, revision)
        texts.append(_yaml(_dump(model, reveal=False)) if model else "")
    return "".join(
        difflib.unified_diff(
            texts[0].splitlines(keepends=True),
            texts[1].splitlines(keepends=True),
            fromfile=f"active/{tenant_id}.yaml",
            tofile=f"candidate/{tenant_id}.yaml",
        ),
    )


def commit(tenant_id: str) -> CommitResult:
    """Make the candidate configuration active; without a candidate, remove it."""
    check_id(tenant_id)
    active_path = _path(tenant_id, "active")
    candidate = _load(tenant_id, "candidate")
    if candidate is None:
        if tenant_id == config.DEFAULT_TENANT:
            raise ConfigError(409, "Conflict", "The service can't be removed.")
        changed = active_path.exists()
        active_path.unlink(missing_ok=True)
        return CommitResult(id=tenant_id, changed=changed)
    # Written in place: the configuration watcher applies modified files.
    changed = files.ensure_file(active_path, _yaml(_dump(candidate, reveal=True)))
    return CommitResult(id=tenant_id, changed=changed)


def discard(tenant_id: str) -> CommitResult:
    """Make the candidate configuration the active one again."""
    check_id(tenant_id)
    candidate_path = _path(tenant_id, "candidate")
    active = _load(tenant_id, "active")
    if active is None:
        changed = candidate_path.exists()
        candidate_path.unlink(missing_ok=True)
        return CommitResult(id=tenant_id, changed=changed)
    changed = files.ensure_file(candidate_path, _yaml(_dump(active, reveal=True)))
    return CommitResult(id=tenant_id, changed=changed)
