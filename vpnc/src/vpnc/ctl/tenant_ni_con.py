"""Manage tenant network instance connections."""

from __future__ import annotations

from typing import Any, Generator, Optional

import tabulate
import typer
import yaml
from rich import print
from typing_extensions import Annotated

from . import helpers

app = typer.Typer()


def complete_connection(ctx: typer.Context) -> Generator[tuple[str, str], Any, None]:
    """Autocomplete connection identifiers."""
    # tenant.main
    assert ctx.parent is not None, "Context parent should not be None"
    assert ctx.parent.parent is not None, "Context parent should not be None"

    active: bool = ctx.parent.params.get("active", False)
    tenant_id: str = ctx.parent.parent.params["tenant_id"]
    instance_id: str = ctx.parent.params["instance_id"]

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    for connection in tenant.network_instances[instance_id].connections.values():
        yield (str(connection.id), connection.metadata.get("description", ""))


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    connection_id: Annotated[
        Optional[int],  # noqa: UP007
        typer.Argument(autocompletion=complete_connection),
    ] = None,
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Entrypoint for tenant network-instance connection commands."""
    _ = active

    if (
        ctx.invoked_subcommand is None and connection_id is not None
        # and connection_id != "list"
    ):
        ctx.fail("Missing command.")
    if ctx.invoked_subcommand:
        return
    list_(ctx)


def list_(ctx: typer.Context) -> None:
    """List all connections."""
    assert ctx.parent is not None
    assert ctx.parent.parent is not None

    active: bool = ctx.params.get("active", False)
    tenant_id: str = ctx.parent.parent.params["tenant_id"]
    instance_id: str = ctx.parent.params["instance_id"]

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    output: list[dict[str, Any]] = [
        {
            "connection": connection.id,
            "type": connection.config.type.name,
            "description": connection.metadata.get("description", ""),
        }
        for connection in tenant.network_instances[instance_id].connections.values()
    ]

    print(tabulate.tabulate(output, headers="keys"))


@app.command()
def show(
    ctx: typer.Context,
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Show a connection configuration."""
    assert ctx.parent is not None
    assert ctx.parent.parent is not None
    assert ctx.parent.parent.parent is not None

    tenant_id: str = ctx.parent.parent.parent.params["tenant_id"]
    instance_id: str = ctx.parent.parent.params["instance_id"]
    connection_id: int = ctx.parent.params["connection_id"]

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    network_instance = tenant.network_instances.get(instance_id)
    if not network_instance:
        return

    connection = network_instance.connections[connection_id]
    if not connection:
        return

    print(
        yaml.safe_dump(
            connection.model_dump(mode="json"),
            explicit_start=True,
            explicit_end=True,
            sort_keys=False,
        ),
    )


@app.command()
def summary(
    ctx: typer.Context,
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Show a connection's connectivity status."""
    assert ctx.parent is not None
    assert ctx.parent.parent is not None
    assert ctx.parent.parent.parent is not None

    _ = active

    tenant_id: str = ctx.parent.parent.parent.params["tenant_id"]
    instance_id: str = ctx.parent.parent.params["instance_id"]
    connection_id: int = ctx.parent.params["connection_id"]

    path = helpers.get_config_path(ctx, active=True)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    network_instance = tenant.network_instances.get(instance_id)
    if not network_instance:
        return

    connection = network_instance.connections[connection_id]
    if not connection:
        return
    connection_status_summary = connection.status_summary(network_instance)

    print(tabulate.tabulate([connection_status_summary], headers="keys"))
