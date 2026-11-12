"""The local REST API: live state (flat, global ids) and configuration (per file).

Errors are RFC 9457 problem details (application/problem+json).
"""

import pathlib
import subprocess
from collections.abc import AsyncIterator, Callable
from typing import Annotated, Any, Literal, NoReturn

from fastapi import APIRouter, Body, Depends, FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import ValidationError

from vpnc import config, helpers
from vpnc.api import config_files, diagnostics, logs, status
from vpnc.api.config_files import (
    CommitResult,
    ConfigError,
    ConfigSummary,
    HistoryEntry,
    Revision,
)
from vpnc.models import enums, tenant
from vpnc.models.connections import Connection
from vpnc.models.network_instance import NetworkInstance
from vpnc.services import control

app = FastAPI(
    title="vpnc",
    description="Local API of vpnc. Served on a Unix socket.",
    version="1",
    docs_url=None,
    redoc_url=None,
)

PROBLEM = "application/problem+json"
ConfigBody = Annotated[dict[str, Any], Body()]


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


@app.get("/v1/ids")
def get_ids() -> status.Ids:
    """Return the ids of what's configured, without its state."""
    return status.ids()


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
        for ni_id, ni in sorted(helpers.network_instances().items())
        if (tenant_id is None or ni.tenant_id == tenant_id)
        and (prefix is None or ni_id.startswith(prefix))
    ]


@app.get("/v1/network-instances")
def list_network_instances(
    tenant_id: Annotated[str | None, Query(alias="tenant")] = None,
) -> list[status.NetworkInstanceState]:
    """Return the network instances, optionally of one tenant."""
    return status.network_instance_states(_select(None, tenant_id))


def _network_instance(ni_id: str) -> NetworkInstance:
    if (ni := helpers.network_instances().get(ni_id)) is None:
        _not_found("network instance", ni_id)
    return ni


@app.get("/v1/network-instances/{ni_id}")
def get_network_instance(ni_id: str) -> status.NetworkInstanceState:
    """Return a network instance with its NAT64 and NPTv6 translations."""
    ni = _network_instance(ni_id)
    return status.network_instance_states([ni], translations=True)[0]


@app.get("/v1/connections")
def list_connections(
    tenant_id: Annotated[str | None, Query(alias="tenant")] = None,
    ni_id: Annotated[str | None, Query(alias="network_instance")] = None,
    state: Annotated[status.State | None, Query()] = None,
    connection_type: Annotated[enums.ConnectionType | None, Query(alias="type")] = None,
    counters: bool = False,  # noqa: FBT001, FBT002
) -> list[status.ConnectionState]:
    """Return the connections, optionally filtered (and with traffic counters)."""
    selected = [
        ni for ni in _select(None, tenant_id) if ni_id is None or ni.id == ni_id
    ]
    return [
        s
        for s in status.connection_states(selected, counters=counters)
        if (state is None or s.state == state)
        and (connection_type is None or s.type == connection_type.value)
    ]


def _connection(connection_id: str) -> tuple[NetworkInstance, Connection]:
    ni_id, conn = helpers.split_connection_name(connection_id)
    ni = helpers.network_instances().get(ni_id)
    if ni is None or not conn.isdigit() or int(conn) not in ni.connections:
        _not_found("connection", connection_id)
    return ni, ni.connections[int(conn)]


def _connection_state(connection_id: str) -> status.ConnectionState:
    ni, _ = _connection(connection_id)
    states = status.connection_states([ni], counters=True)
    return next(s for s in states if s.id == connection_id)


@app.get("/v1/connections/{connection_id}")
def get_connection(connection_id: str) -> status.ConnectionState:
    """Return a connection (e.g. C0001-00-0 or CORE-0)."""
    return _connection_state(connection_id)


def _control(connection_id: str, action: Any) -> status.ConnectionState:  # noqa: ANN401
    ni, connection = _connection(connection_id)
    try:
        action(ni, connection)
    except control.ControlError as err:
        raise ConfigError(409, "Conflict", str(err)) from err
    return _connection_state(connection_id)


@app.post("/v1/connections/{connection_id}/stop")
def stop_connection(connection_id: str) -> status.ConnectionState:
    """Stop a VPN connection until it's started, or vpnc restarts."""
    return _control(connection_id, control.stop)


@app.post("/v1/connections/{connection_id}/start")
def start_connection(connection_id: str) -> status.ConnectionState:
    """Start a stopped VPN connection."""
    return _control(connection_id, control.start)


@app.post("/v1/connections/{connection_id}/reset")
def reset_connection(connection_id: str) -> status.ConnectionState:
    """Set a VPN connection up again (new IKE SA, WireGuard or SSH session)."""
    return _control(connection_id, control.reset)


def _logs(
    queries: list[logs.Query],
    lines: int,
    *,
    follow: bool,
) -> Any:  # noqa: ANN401
    """Return the last log lines; with follow, as a stream that continues.

    The stream has a JSON log line per line; empty lines keep it alive.
    """
    if not follow:
        return logs.last(queries, lines)

    async def stream() -> AsyncIterator[str]:
        async for line in logs.follow(queries, lines):
            yield (line.model_dump_json() if line else "") + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


Lines = Annotated[int, Query(ge=1, le=10000)]
Follow = Annotated[bool, Query(description="Keep sending new lines (JSON lines).")]


@app.get("/v1/connections/{connection_id}/logs", response_model=list[logs.LogLine])
def get_connection_logs(
    connection_id: str,
    lines: Lines = 100,
    level: logs.Level = "info",
    follow: Follow = False,  # noqa: FBT002
) -> Any:  # noqa: ANN401
    """Return a connection's last log lines: vpnc's (incl. SSH) and charon's."""
    _, connection = _connection(connection_id)
    ipsec = connection.config.type == enums.ConnectionType.IPSEC
    queries = logs.connection_queries(connection_id, ipsec=ipsec, level=level)
    return _logs(queries, lines, follow=follow)


@app.get("/v1/network-instances/{ni_id}/logs", response_model=list[logs.LogLine])
def get_network_instance_logs(
    ni_id: str,
    lines: Lines = 100,
    level: logs.Level = "info",
    follow: Follow = False,  # noqa: FBT002
) -> Any:  # noqa: ANN401
    """Return the last log lines of a network instance and its connections."""
    queries = logs.network_instance_queries(_network_instance(ni_id).id, level=level)
    return _logs(queries, lines, follow=follow)


def _hub_only() -> None:
    if not tenant.is_hub():
        raise ConfigError(409, "Conflict", "BGP only runs in hub mode.")


@app.get("/v1/bgp/neighbors")
def list_bgp_neighbors() -> list[status.BgpNeighbor]:
    """Return the BGP sessions in CORE (hub mode only)."""
    _hub_only()
    return status.bgp_neighbors()


@app.get("/v1/bgp/neighbors/{neighbor}")
def get_bgp_neighbor(neighbor: status.IPAddress) -> status.BgpNeighborDetail:
    """Return a BGP session in detail."""
    _hub_only()
    if (detail := status.bgp_neighbor(neighbor)) is None:
        _not_found("BGP neighbor", str(neighbor))
    return detail


@app.get("/v1/bgp/neighbors/{neighbor}/routes")
def list_bgp_neighbor_routes(
    neighbor: status.IPAddress,
    direction: Literal["received", "advertised"],
) -> list[status.BgpRoute]:
    """Return the routes received from (before policy) or advertised to a neighbor."""
    _hub_only()
    if status.bgp_neighbor(neighbor) is None:
        _not_found("BGP neighbor", str(neighbor))
    return status.bgp_neighbor_routes(neighbor, direction)


@app.get("/v1/bgp/routes")
def list_bgp_routes() -> list[status.BgpRoute]:
    """Return CORE's BGP table: every path to every prefix."""
    _hub_only()
    return status.bgp_routes()


# Troubleshooting inside a network instance.


@app.get("/v1/network-instances/{ni_id}/routes")
def list_routes(
    ni_id: str,
    family: Annotated[Literal["4", "6"] | None, Query()] = None,
) -> list[diagnostics.Route]:
    """Return the routes of a network instance (installed, blackhole etc.)."""
    ni = _network_instance(ni_id)
    return diagnostics.routes(ni.id, int(family) if family else None)


@app.post("/v1/network-instances/{ni_id}/ping")
def ping(ni_id: str, body: diagnostics.PingRequest) -> diagnostics.PingResult:
    """Ping from a network instance."""
    return diagnostics.ping(_network_instance(ni_id).id, body)


@app.post("/v1/network-instances/{ni_id}/traceroute")
def traceroute(
    ni_id: str,
    body: diagnostics.TracerouteRequest,
) -> diagnostics.TracerouteResult:
    """Traceroute from a network instance."""
    return diagnostics.traceroute(_network_instance(ni_id).id, body)


@app.post("/v1/network-instances/{ni_id}/tcp")
def tcp(ni_id: str, body: diagnostics.TcpRequest) -> diagnostics.TcpResult:
    """Open a TCP connection from a network instance."""
    return diagnostics.tcp(_network_instance(ni_id).id, body)


@app.get("/v1/logs", response_model=list[logs.LogLine])
def get_logs(
    source: logs.Source = "vpnc",
    level: logs.Level = "info",
    lines: Lines = 100,
    follow: Follow = False,  # noqa: FBT002
) -> Any:  # noqa: ANN401
    """Return the last lines of vpnc's, vpncmangle's or charon's log.

    The level doesn't apply to charon's log, whose lines have a subsystem.
    """
    return _logs(logs.daemon_queries(source, level), lines, follow=follow)


UNIT = "ncubed-vpnc.service"


@app.post("/v1/service/{action}", status_code=202)
def service_action(action: Literal["restart", "stop"]) -> dict[str, str]:
    """Restart or stop vpnc (systemd); it happens after the response."""
    if not pathlib.Path("/run/systemd/system").is_dir():
        raise ConfigError(409, "Conflict", "vpnc doesn't run under systemd here.")
    subprocess.run(  # noqa: S603
        ["/usr/bin/systemctl", "--no-block", action, UNIT],
        check=True,
        timeout=10,
    )
    return {"action": action}


@app.get("/v1/version")
def get_version() -> status.Version:
    """Return the versions of vpnc and the software it runs."""
    return status.version()


# Configuration, per file: a tenant, or the service (the DEFAULT file). Writes
# are staged in the candidate; a commit makes them active.

SERVICE = config.DEFAULT_TENANT


@app.post("/v1/config/commit")
def commit_all(
    confirm: Annotated[int | None, Query(ge=10, le=86400)] = None,
) -> list[CommitResult]:
    """Commit the staged changes of all tenants and the service.

    With confirm (seconds), each is rolled back unless confirmed in time.
    """
    return config_files.commit_all(confirm)


@app.post("/v1/config/confirm")
def confirm_all() -> list[CommitResult]:
    """Confirm all commits."""
    return config_files.confirm_all()


@app.post("/v1/config/discard")
def discard_all() -> list[CommitResult]:
    """Drop the staged changes of all tenants and the service."""
    return config_files.discard_all()


@app.get("/v1/config/tenants")
def list_configs() -> list[ConfigSummary]:
    """Return the tenants with configuration and their staged changes."""
    return config_files.summaries()


def tenant_id_path(
    tenant_id: Annotated[str, Path(pattern=config.TENANT_ID_PATTERN)],
) -> str:
    """Return the tenant id from the path."""
    return tenant_id


def service_id() -> str:
    """Return the service's (DEFAULT's) id."""
    return SERVICE


def config_routes(prefix: str, target: Callable[..., str], what: str) -> APIRouter:
    """Return the routes of a configuration file (a tenant's or the service's)."""
    router = APIRouter(prefix=prefix)
    Target = Annotated[str, Depends(target)]  # noqa: N806
    Reveal = Annotated[bool, Query(alias="reveal_secrets")]  # noqa: N806

    @router.get("", summary=f"Return the {what} configuration")
    def get_config(
        target_id: Target,
        revision: Revision = "active",
        reveal: Reveal = False,  # noqa: FBT002
    ) -> dict[str, Any]:
        """The candidate revision includes the staged changes."""
        return config_files.read(target_id, revision, reveal=reveal)

    @router.put("", summary=f"Stage the {what} configuration")
    def put_config(target_id: Target, body: ConfigBody) -> dict[str, Any]:
        """A new tenant is created on commit."""
        return config_files.write_candidate(target_id, body)

    @router.patch("", summary=f"Stage changes to the {what} configuration")
    def patch_config(target_id: Target, body: ConfigBody) -> dict[str, Any]:
        """An RFC 7386 merge patch: null removes."""
        return config_files.patch_candidate(target_id, body)

    @router.get("/diff", response_class=PlainTextResponse, summary="Staged changes")
    def diff(target_id: Target) -> str:
        """A unified diff; secrets are hidden."""
        return config_files.diff(target_id)

    @router.post("/commit", summary="Apply the staged changes")
    def commit(
        target_id: Target,
        confirm: Annotated[int | None, Query(ge=10, le=86400)] = None,
    ) -> CommitResult:
        """With confirm (seconds), it's rolled back unless confirmed in time.

        A commit without confirm confirms an earlier one.
        """
        return config_files.commit(target_id, confirm)

    @router.post("/confirm", summary="Confirm a commit")
    def confirm(target_id: Target) -> CommitResult:
        """The commit isn't rolled back."""
        return config_files.confirm(target_id)

    @router.post("/discard", summary="Drop the staged changes")
    def discard(target_id: Target) -> CommitResult:
        """The candidate is the active configuration again."""
        return config_files.discard(target_id)

    @router.get("/history", summary="Earlier active configurations")
    def history(target_id: Target) -> list[HistoryEntry]:
        """Most recent first; a commit adds one."""
        return config_files.history(target_id)

    @router.get("/history/{revision}", summary="An earlier active configuration")
    def get_history(
        target_id: Target,
        revision: Annotated[int, Path(ge=1)],
        reveal: Reveal = False,  # noqa: FBT002
    ) -> dict[str, Any]:
        """404 if the tenant didn't exist then."""
        return config_files.read_history(target_id, revision, reveal=reveal)

    @router.post("/history/{revision}/restore", summary="Stage an earlier revision")
    def restore(
        target_id: Target,
        revision: Annotated[int, Path(ge=1)],
    ) -> CommitResult:
        """Commit to apply it."""
        return config_files.restore(target_id, revision)

    return router


tenant_routes = config_routes("/v1/config/tenants/{tenant_id}", tenant_id_path, "tenant")


@tenant_routes.delete("", summary="Stage removing the tenant")
def delete_tenant_config(
    tenant_id: Annotated[str, Depends(tenant_id_path)],
) -> CommitResult:
    """The tenant is removed on commit."""
    return config_files.delete_candidate(tenant_id)


app.include_router(tenant_routes)
app.include_router(config_routes("/v1/config/service", service_id, "service"))
