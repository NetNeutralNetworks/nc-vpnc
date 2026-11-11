"""The local REST API: live state (flat, global ids) and configuration (per file).

Errors are RFC 9457 problem details (application/problem+json).
"""

from __future__ import annotations

from typing import Annotated, Any, NoReturn

from fastapi import Body, FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError

from vpnc import config
from vpnc.api import config_files, status
from vpnc.api.config_files import CommitResult, ConfigError, ConfigSummary, Revision
from vpnc.models import enums, tenant

app = FastAPI(
    title="vpnc",
    description="Local API of vpnc. Served on a Unix socket.",
    version="1",
    docs_url=None,
    redoc_url=None,
)

PROBLEM = "application/problem+json"


def problem(status_code: int, title: str, detail: Any) -> JSONResponse:  # noqa: ANN401
    """Return an RFC 9457 problem response."""
    return JSONResponse(
        {
            "type": "about:blank",
            "title": title,
            "status": status_code,
            "detail": detail,
        },
        status_code=status_code,
        media_type=PROBLEM,
    )


def _errors(err: ValidationError | RequestValidationError) -> list[dict[str, Any]]:
    return [
        {"loc": ".".join(str(p) for p in e["loc"]), "msg": e["msg"]}
        for e in err.errors()
    ]


@app.exception_handler(ConfigError)
async def _config_error(_: Request, err: ConfigError) -> JSONResponse:
    return problem(err.status, err.title, err.detail)


@app.exception_handler(ValidationError)
async def _validation_error(_: Request, err: ValidationError) -> JSONResponse:
    return problem(422, "Invalid configuration", _errors(err))


@app.exception_handler(RequestValidationError)
async def _request_error(_: Request, err: RequestValidationError) -> JSONResponse:
    return problem(422, "Invalid request", _errors(err))


def _not_found(kind: str, item_id: str) -> NoReturn:
    raise ConfigError(404, "Not found", f"No {kind} '{item_id}'.")


# Live state. FastAPI runs these (sync) functions in its thread pool.


@app.get("/v1/status")
def get_status() -> status.Status:
    """Return an overview of the service."""
    return status.status()


@app.get("/v1/tenants")
def list_tenants() -> list[status.TenantState]:
    """Return the tenants."""
    return status.tenant_states()


@app.get("/v1/tenants/{tenant_id}")
def get_tenant(tenant_id: str) -> status.TenantState:
    """Return a tenant."""
    if not (states := status.tenant_states([tenant_id])):
        _not_found("tenant", tenant_id)
    return states[0]


def _select(prefix: str | None, tenant_id: str | None) -> list[Any]:
    """Return network instances by tenant and/or id prefix (e.g. C0001-0)."""
    return [
        ni
        for ni_id, ni in sorted(status.network_instances().items())
        if (tenant_id is None or status.tenant_of(ni_id) == tenant_id)
        and (prefix is None or ni_id.startswith(prefix))
    ]


@app.get("/v1/network-instances")
def list_network_instances(
    tenant_id: Annotated[str | None, Query(alias="tenant")] = None,
) -> list[status.NetworkInstanceState]:
    """Return the network instances, optionally of one tenant."""
    return status.network_instance_states(_select(None, tenant_id))


@app.get("/v1/network-instances/{ni_id}")
def get_network_instance(ni_id: str) -> status.NetworkInstanceState:
    """Return a network instance with its NAT64 and NPTv6 translations."""
    if (ni := status.network_instances().get(ni_id)) is None:
        _not_found("network instance", ni_id)
    return status.network_instance_states([ni], translations=True)[0]


@app.get("/v1/connections")
def list_connections(
    tenant_id: Annotated[str | None, Query(alias="tenant")] = None,
    ni_id: Annotated[str | None, Query(alias="network_instance")] = None,
    state: Annotated[status.State | None, Query()] = None,
) -> list[status.ConnectionState]:
    """Return the connections, optionally filtered."""
    selected = [
        ni for ni in _select(None, tenant_id) if ni_id is None or ni.id == ni_id
    ]
    return [
        s
        for s in status.connection_states(selected)
        if state is None or s.state == state
    ]


@app.get("/v1/connections/{connection_id}")
def get_connection(connection_id: str) -> status.ConnectionState:
    """Return a connection (e.g. C0001-00-0 or CORE-0)."""
    ni_id, _, conn = connection_id.rpartition("-")
    ni = status.network_instances().get(ni_id)
    if ni is None or not conn.isdigit() or int(conn) not in ni.connections:
        _not_found("connection", connection_id)
    states = status.connection_states([ni])
    return next(s for s in states if s.id == connection_id)


@app.get("/v1/bgp/neighbors")
def list_bgp_neighbors() -> list[status.BgpNeighbor]:
    """Return the BGP sessions in CORE (hub mode only)."""
    if tenant.get_default_tenant().mode != enums.ServiceMode.HUB:
        detail = "BGP only runs in hub mode."
        raise ConfigError(409, "Conflict", detail)
    return status.bgp_neighbors()


# Configuration, per file: a tenant, or the service (the DEFAULT file).

TenantId = Annotated[str, Path(pattern=r"^[2-9A-F]\d{4}$")]


@app.get("/v1/config/tenants")
def list_configs() -> list[ConfigSummary]:
    """Return the tenants with configuration, and whether they have changes."""
    return config_files.summaries()


@app.get("/v1/config/tenants/{tenant_id}")
def get_tenant_config(
    tenant_id: TenantId,
    revision: Revision = "active",
    reveal_secrets: bool = False,  # noqa: FBT001, FBT002
) -> dict[str, Any]:
    """Return a tenant's configuration."""
    return config_files.read(tenant_id, revision, reveal=reveal_secrets)


@app.put("/v1/config/tenants/{tenant_id}/candidate")
def put_tenant_candidate(
    tenant_id: TenantId,
    body: Annotated[dict[str, Any], Body()],
) -> dict[str, Any]:
    """Validate and store a tenant's candidate configuration."""
    return config_files.write_candidate(tenant_id, body)


@app.delete("/v1/config/tenants/{tenant_id}/candidate")
def discard_tenant(tenant_id: TenantId) -> CommitResult:
    """Make a tenant's candidate configuration the active one again."""
    return config_files.discard(tenant_id)


@app.get("/v1/config/tenants/{tenant_id}/diff", response_class=PlainTextResponse)
def diff_tenant(tenant_id: TenantId) -> str:
    """Return the changes from the active to the candidate configuration."""
    return config_files.diff(tenant_id)


@app.post("/v1/config/tenants/{tenant_id}/commit")
def commit_tenant(tenant_id: TenantId) -> CommitResult:
    """Apply a tenant's candidate configuration (no candidate: remove it)."""
    return config_files.commit(tenant_id)


SERVICE = config.DEFAULT_TENANT


@app.get("/v1/config/service")
def get_service_config(
    revision: Revision = "active",
    reveal_secrets: bool = False,  # noqa: FBT001, FBT002
) -> dict[str, Any]:
    """Return the service configuration."""
    return config_files.read(SERVICE, revision, reveal=reveal_secrets)


@app.put("/v1/config/service/candidate")
def put_service_candidate(body: Annotated[dict[str, Any], Body()]) -> dict[str, Any]:
    """Validate and store the candidate service configuration."""
    return config_files.write_candidate(SERVICE, body)


@app.delete("/v1/config/service/candidate")
def discard_service() -> CommitResult:
    """Make the candidate service configuration the active one again."""
    return config_files.discard(SERVICE)


@app.get("/v1/config/service/diff", response_class=PlainTextResponse)
def diff_service() -> str:
    """Return the changes from the active to the candidate service configuration."""
    return config_files.diff(SERVICE)


@app.post("/v1/config/service/commit")
def commit_service() -> CommitResult:
    """Apply the candidate service configuration. Some changes need a restart."""
    return config_files.commit(SERVICE)
