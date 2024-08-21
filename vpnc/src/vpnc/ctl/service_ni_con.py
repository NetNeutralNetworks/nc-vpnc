#!/usr/bin/env python3

from typing import Any, Generator, Optional

import tabulate
import typer
import yaml
from typing_extensions import Annotated

from . import helpers

app = typer.Typer()


def complete_connection(ctx: typer.Context) -> Generator[tuple[str, str], Any, None]:
    """
    Autocompletes connection identifiers
    """
    # tenant.main
    assert ctx.parent is not None
    assert ctx.parent.parent is not None

    active: bool = ctx.parent.params.get("active", False)
    instance_id = ctx.parent.params.get("instance_id")

    path = helpers.get_service_config_path(ctx, active)

    service = helpers.get_service_config(ctx, path)

    for idx, connection in enumerate(
        service.network_instances.get(instance_id).connections
    ):
        yield (str(idx), connection.metadata.get("description", ""))


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    connection_id: Annotated[
        Optional[int],
        typer.Argument(autocompletion=complete_connection),
    ] = None,
):
    """
    Entrypoint for service  network-instance connection commands
    """

    if (
        ctx.invoked_subcommand is None
        and connection_id is not None
        and connection_id != "list"
    ):
        ctx.fail("Missing command.")
    list_(ctx)


def list_(ctx: typer.Context):
    """
    List all connections
    """
    # tenant.main
    assert ctx.parent is not None
    assert ctx.parent.parent is not None

    active: bool = ctx.params.get("active", False)
    instance_id = ctx.parent.params.get("instance_id")

    path = helpers.get_service_config_path(ctx, active)

    service = helpers.get_service_config(ctx, path)

    output: list[dict[str, Any]] = []
    for idx, connection in enumerate(
        service.network_instances.get(instance_id).connections
    ):
        output.append(
            {
                "connection": idx,
                "type": connection.config.type.name,
                "description": connection.metadata.get("description", ""),
            }
        )

    print(tabulate.tabulate(output, headers="keys"))


@app.command()
def show(
    ctx: typer.Context,
    # full: Annotated[bool, typer.Option("--full")] = False,
    active: Annotated[bool, typer.Option("--active")] = False,
):
    """
    Show a connection configuration
    """
    assert ctx.parent is not None
    assert ctx.parent.parent is not None

    instance_id: str = ctx.parent.parent.params["instance_id"]
    connection_id: str = ctx.parent.params["connection_id"]

    path = helpers.get_service_config_path(ctx, active)

    service = helpers.get_service_config(ctx, path)

    network_instance = service.network_instances.get(instance_id)
    if not network_instance:
        return

    connection = network_instance.connections[connection_id]
    if not connection:
        return

    print(
        yaml.safe_dump(
            connection.model_dump(mode="json"), explicit_start=True, explicit_end=True
        )
    )


@app.command()
def summary(
    ctx: typer.Context,
):
    """
    Show a connection's connectivity status
    """
    assert ctx.parent is not None
    assert ctx.parent.parent is not None

    # tenant_id: str = ctx.parent.parent.parent.params["tenant_id"]
    instance_id: str = ctx.parent.parent.params["instance_id"]
    connection_id: str = ctx.parent.params["connection_id"]

    path = helpers.get_service_config_path(ctx, True)

    service = helpers.get_service_config(ctx, path)

    network_instance = service.network_instances.get(instance_id)
    if not network_instance:
        return

    connection = network_instance.connections[connection_id]
    if not connection:
        return

    connection_status_summary = connection.config.status_summary(
        network_instance, connection_id
    )

    print(tabulate.tabulate([connection_status_summary], headers="keys"))
