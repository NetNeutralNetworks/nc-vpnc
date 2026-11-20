"""The local REST API: live state (flat, global ids) and configuration (per file).

Errors are RFC 9457 problem details (application/problem+json).
"""

import logging
import pathlib
import subprocess
from collections.abc import AsyncIterator, Callable, Sequence
from http import HTTPStatus
from typing import Annotated, Any, Literal, NoReturn

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    FastAPI,
    Path,
    Query,
    Request,
)
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, BeforeValidator, TypeAdapter, ValidationError
from starlette.exceptions import HTTPException
from starlette.routing import Match

from vpnc import config, eventlog, helpers
from vpnc.api import config_files, diagnosis, diagnostics, events, logs, status
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
from vpnc.models.ssh import INTERFACE_PATTERN, USERNAME_PATTERN
from vpnc.services import control, ssh

logger = logging.getLogger("vpnc")

PROBLEM = "application/problem+json"


class Problem(BaseModel):
    """An RFC 9457 problem: what went wrong."""

    type: str = "about:blank"
    title: str
    status: int
    # A message, or per invalid value where (loc) and what (msg).
    detail: str | list[dict[str, str]] | None = None


# What any route may answer besides its result.
ERRORS = {
    400: "Bad request: the body can't be read",
    404: "Not found: no such tenant, network instance, connection, ...",
    409: "Conflict: e.g. nothing to confirm, or a resource in use",
    422: "Invalid request or configuration",
    503: "A service vpnc needs (e.g. charon) didn't answer",
}

app = FastAPI(
    title="vpnc",
    description="Local API of vpnc. Served on a Unix socket.",
    version="1",
    docs_url=None,
    redoc_url=None,
    responses={
        status: {
            "description": description,
            "content": {PROBLEM: {"schema": Problem.model_json_schema()}},
        }
        for status, description in ERRORS.items()
    },
)

# Values are upper case; lower case is accepted.
Upper = BeforeValidator(lambda v: v.upper() if isinstance(v, str) else v)
ConfigBody = Annotated[dict[str, Any], Body()]


def problem(
    status_code: int,
    title: str,
    detail: Any,  # noqa: ANN401
    headers: dict[str, str] | None = None,
) -> JSONResponse:
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
        headers=headers,
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


@app.exception_handler(HTTPException)
async def _http_error(request: Request, err: HTTPException) -> JSONResponse:
    """Answer e.g. an unknown path or method as a problem too."""
    headers = dict(err.headers or {})
    if err.status_code == 405:  # noqa: PLR2004
        # Each method is a route of its own: Starlette names only the first's.
        methods = {
            method
            for route in app.routes
            if isinstance(route, APIRoute)
            and route.matches(request.scope)[0] != Match.NONE
            for method in route.methods
        }
        headers["Allow"] = ", ".join(sorted(methods))
    title = HTTPStatus(err.status_code).phrase
    return problem(err.status_code, title, err.detail, headers)


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
    return status.network_instance_states([ni], detail=True)[0]


@app.get("/v1/connections")
def list_connections(
    tenant_id: Annotated[str | None, Query(alias="tenant")] = None,
    ni_id: Annotated[str | None, Query(alias="network_instance")] = None,
    admin_status: Annotated[status.AdminStatus | None, Upper] = None,
    oper_status: Annotated[status.OperStatus | None, Upper] = None,
    connection_type: Annotated[
        enums.ConnectionType | None,
        Upper,
        Query(alias="type"),
    ] = None,
) -> list[status.ConnectionState]:
    """Return the connections, optionally filtered."""
    selected = [
        ni for ni in _select(None, tenant_id) if ni_id is None or ni.id == ni_id
    ]
    return [
        s
        for s in status.connection_states(selected)
        if (admin_status is None or s.admin_status == admin_status)
        and (oper_status is None or s.oper_status == oper_status)
        and (connection_type is None or s.type == connection_type)
    ]


def _connection(connection_id: str) -> tuple[NetworkInstance, Connection]:
    ni_id, conn = helpers.split_connection_name(connection_id)
    ni = helpers.network_instances().get(ni_id)
    if (
        ni is None
        or not (conn.isascii() and conn.isdigit())
        or int(conn) not in ni.connections
    ):
        _not_found("connection", connection_id)
    return ni, ni.connections[int(conn)]


def _connection_state(connection_id: str) -> status.ConnectionState:
    ni, _ = _connection(connection_id)
    states = status.connection_states([ni])
    return next(s for s in states if s.id == connection_id)


@app.get("/v1/connections/{connection_id}")
def get_connection(connection_id: str) -> status.ConnectionState:
    """Return a connection (e.g. C0001-00-0 or CORE-0)."""
    return _connection_state(connection_id)


@app.get("/v1/connections/{connection_id}/diagnosis")
def get_connection_diagnosis(connection_id: str) -> diagnosis.Diagnosis:
    """Return what's wrong with a connection: the problem, details and checks."""
    return diagnosis.diagnose(*_connection(connection_id))


@app.get("/v1/connections/{connection_id}/probes")
def get_connection_probes(connection_id: str) -> list[status.ProbeDetail]:
    """Return a connection's probes with their last tests (3 minutes)."""
    return status.probe_details(*_connection(connection_id))


@app.get(
    "/v1/connections/{connection_id}/ssh-setup",
    response_class=PlainTextResponse,
)
def get_connection_ssh_setup(
    connection_id: str,
    username: Annotated[str | None, Query(pattern=USERNAME_PATTERN)] = None,
    interface: Annotated[str | None, Query(pattern=INTERFACE_PATTERN)] = None,
) -> PlainTextResponse:
    """Return a script that sets up an SSH connection's remote side for an account.

    Root runs it there once: the account can then only open the tunnel. By
    default for the connection's username and remote_config_interface.
    """
    try:
        script = ssh.remote_setup(*_connection(connection_id), username, interface)
    except ssh.SetupError as err:
        raise ConfigError(409, "Conflict", str(err)) from err
    return PlainTextResponse(script)


def _set_enabled(connection_id: str, *, enabled: bool) -> status.ConnectionState:
    ni, _ = _connection(connection_id)
    config_files.set_enabled(ni.tenant_id, connection_id, enabled=enabled)
    # As loaded now.
    control.apply(*_connection(connection_id))
    return _connection_state(connection_id)


@app.post("/v1/connections/{connection_id}/stop")
def stop_connection(connection_id: str) -> status.ConnectionState:
    """Disable a connection: enabled is set to false in its configuration."""
    return _set_enabled(connection_id, enabled=False)


@app.post("/v1/connections/{connection_id}/start")
def start_connection(connection_id: str) -> status.ConnectionState:
    """Enable a connection: enabled is set to true in its configuration."""
    return _set_enabled(connection_id, enabled=True)


@app.post("/v1/connections/{connection_id}/reset")
def reset_connection(connection_id: str) -> status.ConnectionState:
    """Set a VPN connection up again (new IKE SA, WireGuard or SSH session)."""
    try:
        control.reset(*_connection(connection_id))
    except control.ControlError as err:
        raise ConfigError(409, "Conflict", str(err)) from err
    eventlog.record("RESET", "reset by an administrator", connection=connection_id)
    return _connection_state(connection_id)


def _logs(
    queries: Sequence[logs.Selection],
    lines: int,
    *,
    follow: bool,
) -> Any:  # noqa: ANN401
    """Return the last log lines or events; with follow, as a stream that continues.

    The stream has a JSON log line or event per line; empty lines keep it alive.
    """
    if not follow:
        return logs.last(queries, lines)

    async def stream() -> AsyncIterator[str]:
        async for line in logs.follow(queries, lines):
            yield (line.model_dump_json() if line else "") + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


Lines = Annotated[int, Query(ge=1, le=10000)]
Level = Annotated[logs.Level, Upper]
Follow = Annotated[bool, Query(description="Keep sending new lines (JSON lines).")]


@app.get("/v1/connections/{connection_id}/logs", response_model=list[logs.LogLine])
def get_connection_logs(
    connection_id: str,
    lines: Lines = 100,
    level: Level = "INFO",
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
    level: Level = "INFO",
    follow: Follow = False,  # noqa: FBT002
) -> Any:  # noqa: ANN401
    """Return the last log lines of a network instance and its connections."""
    queries = logs.network_instance_queries(_network_instance(ni_id).id, level=level)
    return _logs(queries, lines, follow=follow)


# A tenant, network instance or connection; also one that's removed.
Subject = Query(pattern=r"^[A-Za-z0-9-]+$")


@app.get("/v1/events", response_model=list[events.Event])
def get_events(  # noqa: PLR0913, PLR0917 (a parameter per filter)
    tenant_id: Annotated[str | None, Subject, Query(alias="tenant")] = None,
    ni_id: Annotated[str | None, Subject, Query(alias="network_instance")] = None,
    connection_id: Annotated[str | None, Subject, Query(alias="connection")] = None,
    event: Annotated[str | None, Upper, Query(pattern=r"^[A-Za-z_]+$")] = None,
    since: Annotated[int | None, Query(ge=1, description="Seconds back.")] = None,
    limit: Lines = 100,
    follow: Follow = False,  # noqa: FBT002
) -> Any:  # noqa: ANN401
    """Return the last events: all, or of a tenant, network instance or connection.

    A tenant's include its network instances', theirs their connections'.
    """
    query = events.Query(tenant_id, ni_id, connection_id, event, since)
    return _logs([query], limit, follow=follow)


def _hub_only(what: str = "BGP only runs") -> None:
    if not helpers.is_hub():
        raise ConfigError(409, "Conflict", f"{what} in hub mode.")


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


@app.get("/v1/network-instances/{ni_id}/sessions")
def list_sessions(
    ni_id: str,
    address: Annotated[diagnostics.IPAddress | None, Query()] = None,
    protocol: Annotated[
        Literal["TCP", "UDP", "ICMP", "ICMPV6"] | None,
        Query(),
        Upper,
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100000)] = 1000,
) -> diagnostics.Sessions:
    """Return the sessions through a network instance: NAT64, NPTv6 and routed."""
    ni = _network_instance(ni_id)
    return diagnostics.sessions(ni, address, protocol, limit)


@app.get("/v1/network-instances/{ni_id}/firewall")
def list_firewall(ni_id: str) -> list[diagnostics.FirewallRule]:
    """Return the rules of a network instance's firewall with their counters."""
    return diagnostics.firewall(_network_instance(ni_id).id)


@app.get("/v1/translate")
def translate(
    address: Annotated[diagnostics.IPAddress, Query()],
    network_instance: Annotated[
        str | None,
        Query(description="Required for an IPv4 address: it's a tenant's."),
    ] = None,
) -> list[diagnostics.AddressTranslation]:
    """Return an address as admins reach it and in the tenant, from either side.

    An IPv4 address is a tenant's: it needs the network instance.
    """
    _hub_only("Addresses are only translated")
    if network_instance is not None:
        selected = [_network_instance(network_instance)]
    elif address.version == 4:  # noqa: PLR2004
        detail = "An IPv4 address needs a network instance."
        raise ConfigError(422, "Invalid request", detail)
    else:
        selected = list(helpers.network_instances().values())
    return diagnostics.translate(address, selected)


@app.get("/v1/logs", response_model=list[logs.LogLine])
def get_logs(
    source: logs.Source = "vpnc",
    level: Level = "INFO",
    lines: Lines = 100,
    follow: Follow = False,  # noqa: FBT002
) -> Any:  # noqa: ANN401
    """Return the last lines of vpnc's, vpncmangle's or charon's log.

    The level doesn't apply to charon's log, whose lines have a subsystem.
    """
    return _logs(logs.daemon_queries(source, level), lines, follow=follow)


UNIT = "ncubed-vpnc.service"


def _systemctl(action: str) -> None:
    """Have systemd restart or stop vpnc.

    systemctl is in vpnc's cgroup: stopping vpnc can kill it before it exits,
    after the job was queued.
    """
    try:
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/systemctl", "--no-block", action, UNIT],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.exception("Running systemctl %s failed.", action)
        return
    if result.returncode > 0:
        logger.error("systemctl %s failed: %s", action, result.stderr.strip())


@app.post("/v1/service/{action}", status_code=202)
def service_action(
    action: Literal["restart", "stop"],
    background: BackgroundTasks,
) -> dict[str, str]:
    """Restart or stop vpnc (systemd); it happens after the response."""
    if not pathlib.Path("/run/systemd/system").is_dir():
        raise ConfigError(409, "Conflict", "vpnc doesn't run under systemd here.")
    loaded = subprocess.run(  # noqa: S603
        ["/usr/bin/systemctl", "show", "--property=LoadState", "--value", UNIT],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    ).stdout.strip()
    if loaded != "loaded":
        detail = f"{UNIT} isn't loaded ({loaded or 'unknown'})."
        raise ConfigError(409, "Conflict", detail)
    background.add_task(_systemctl, action)
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
    allow_weak: bool = False,  # noqa: FBT001, FBT002
) -> list[CommitResult]:
    """Commit the staged changes of all tenants and the service.

    With confirm (seconds), each is rolled back unless confirmed in time. Weak
    cryptography (a short PSK, IKEv1, weak algorithms) is only added with
    allow_weak.
    """
    return config_files.commit_all(confirm, allow_weak=allow_weak)


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


@app.post("/v1/config/tenants", status_code=201)
def add_config(body: config_files.NewTenant) -> dict[str, Any]:
    """Stage a new tenant with only its name; set the rest, then commit."""
    return config_files.add_candidate(body)


def tenant_id_path(
    tenant_id: Annotated[
        str,
        Path(pattern=config.TENANT_ID_PATTERN, min_length=5, max_length=5),
    ],
) -> str:
    """Return the tenant id from the path."""
    return tenant_id


def service_id() -> str:
    """Return the service's (DEFAULT's) id."""
    return SERVICE


def config_routes(  # noqa: C901 (a nested function per route)
    prefix: str,
    target: Callable[..., str],
    what: str,
) -> APIRouter:
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
        """Return it; the candidate revision includes the staged changes."""
        return config_files.read(target_id, revision, reveal=reveal)

    @router.put("", summary=f"Stage the {what} configuration")
    def put_config(target_id: Target, body: ConfigBody) -> dict[str, Any]:
        """Replace the candidate; a new tenant is created on commit."""
        return config_files.write_candidate(target_id, body)

    @router.patch("", summary=f"Stage changes to the {what} configuration")
    def patch_config(target_id: Target, body: ConfigBody) -> dict[str, Any]:
        """Merge an RFC 7386 patch into the candidate: null removes.

        A tenant without configuration is added first (POST /v1/config/tenants).
        """
        return config_files.patch_candidate(target_id, body)

    @router.get("/diff", response_class=PlainTextResponse, summary="Staged changes")
    def diff(target_id: Target) -> str:
        """Return a unified diff; secrets are hidden."""
        return config_files.diff(target_id)

    @router.get("/schema", summary=f"JSON Schema of the {what} configuration")
    def schema(target_id: Target) -> dict[str, Any]:
        """Return the keys it can have, with their types and defaults."""
        return config_files.schema(target_id)

    @router.post("/commit", summary="Apply the staged changes")
    def commit(
        target_id: Target,
        confirm: Annotated[int | None, Query(ge=10, le=86400)] = None,
        allow_weak: bool = False,  # noqa: FBT001, FBT002
    ) -> CommitResult:
        """With confirm (seconds), it's rolled back unless confirmed in time.

        A commit without confirm confirms an earlier one. Weak cryptography (a
        short PSK, IKEv1, weak algorithms) is only added with allow_weak.
        """
        return config_files.commit(target_id, confirm, allow_weak=allow_weak)

    @router.post("/confirm", summary="Confirm a commit")
    def confirm(target_id: Target) -> CommitResult:
        """Keep the commit: it isn't rolled back."""
        return config_files.confirm(target_id)

    @router.post("/discard", summary="Drop the staged changes")
    def discard(target_id: Target) -> CommitResult:
        """Make the candidate the active configuration again."""
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


tenant_routes = config_routes(
    "/v1/config/tenants/{tenant_id}", tenant_id_path, "tenant"
)


@tenant_routes.delete("", summary="Stage removing the tenant")
def delete_tenant_config(
    tenant_id: Annotated[str, Depends(tenant_id_path)],
) -> CommitResult:
    """Stage it; the tenant is removed on commit."""
    return config_files.delete_candidate(tenant_id)


app.include_router(tenant_routes)
app.include_router(config_routes("/v1/config/service", service_id, "service"))

# The models of the configurations PUT accepts. The body is read as any
# object: older versions are converted before the model checks them.
CONFIG_MODELS = {
    "/v1/config/tenants/{tenant_id}": TypeAdapter(tenant.Tenant),
    "/v1/config/service": TypeAdapter(tenant.ServiceHub | tenant.ServiceEndpoint),
}


def openapi() -> dict[str, Any]:
    """Return the OpenAPI schema, with the configuration models PUT accepts."""
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    components = schema.setdefault("components", {}).setdefault("schemas", {})
    for path, adapter in CONFIG_MODELS.items():
        body = adapter.json_schema(ref_template="#/components/schemas/{model}")
        components.update(body.pop("$defs", {}))
        content = schema["paths"][path]["put"]["requestBody"]["content"]
        content["application/json"]["schema"] = body
    app.openapi_schema = schema
    return schema


app.openapi = openapi  # type: ignore[method-assign]
