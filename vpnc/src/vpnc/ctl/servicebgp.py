"""Manage service configuration."""

from __future__ import annotations

from typing import Any

import tabulate
import typer
import yaml
from rich import print
from typing_extensions import Annotated

from vpnc import models
from vpnc.ctl import helpers

app = typer.Typer()


@app.command()
def show(
    ctx: typer.Context,
    active: Annotated[bool, typer.Option("--active/--candidate")] = False,  # noqa: FBT002
) -> None:
    """Show the service BGP configuration."""
    path = helpers.get_service_config_path(ctx, active=active)

    service = helpers.get_service_config(ctx, path)

    if service.mode is not models.ServiceMode.HUB:
        print("BGP is inactive. Running in 'endpoint' mode.")
        return

    with path.open(encoding="utf-8") as f:
        bgp = service.bgp

    output = bgp.model_dump(mode="json")
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def summary(
    ctx: typer.Context,
) -> None:
    """Show a network-instance's connectivity status."""
    assert ctx.parent is not None

    instance_id: str = ctx.parent.params["instance_id"]

    path = helpers.get_service_config_path(ctx, active=True)

    service = helpers.get_service_config(ctx, path)

    output: list[dict[str, Any]] = [
        connection.status_summary(service.network_instances[instance_id])
        for connection in service.network_instances[instance_id].connections.values()
    ]

    print(tabulate.tabulate(output, headers="keys"))


# @app.command(name="set")
# def set_(
#     # pylint: disable=unused-argument
#     asn: Annotated[Optional[int], typer.Option()] = None,
#     router_id: Annotated[
#         Optional[IPv4Address],
#         typer.Option(parser=IPv4Address),
#     ] = None,
# ) -> None:
#     """Set service BGP properties."""
#     all_args = {k: v for k, v in locals().items() if v is not None}

#     path = config.VPNC_C_SERVICE_CONFIG_PATH

#     if not path.exists():
#         return

#     with config.VPNC_A_SERVICE_CONFIG_PATH.open(encoding="utf-8") as f:
#         service = models.ServiceHub(**yaml.safe_load(f))

#     if service.mode is not models.ServiceMode.HUB:
#         print("BGP is inactive. Running in 'endpoint' mode.")
#         return

#     updated_bgp = service.bgp.model_copy(update=all_args)
#     service.bgp = updated_bgp

#     # performs the class post_init construction.
#     output = yaml.safe_dump(
#         service.model_dump(mode="json"),
#         explicit_start=True,
#         explicit_end=True,
#     )
#     with path.open("w+", encoding="utf-8") as f:
#         f.write(output)
#     show(active=False)


if __name__ == "__main__":
    app()
