"""Manage tenant network instances."""

from __future__ import annotations

from enum import Enum
from typing import Any, Generator, Optional

import tabulate
import typer
import yaml
from rich import print
from typing_extensions import Annotated

from . import helpers, tenant_ni_con

app = typer.Typer()
app.add_typer(tenant_ni_con.app, name="connections")

IPAddress = Any
IPInterface = Any
IPNetwork = Any


def complete_network_instance(
    ctx: typer.Context,
) -> Generator[tuple[str, str], Any, None]:
    """Autocompletes network-instance identifiers."""
    # tenants.main
    assert ctx.parent is not None

    active: bool = ctx.parent.params.get("active", False)
    tenant_id: str = ctx.parent.params["tenant_id"]

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    for network_instance in tenant.network_instances.values():
        yield (network_instance.id, network_instance.metadata.get("description", ""))


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    instance_id: Annotated[
        Optional[str],  # noqa: UP007
        typer.Argument(autocompletion=complete_network_instance),
    ] = None,
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Entrypoint for tenant network-instance commands."""
    _ = active

    if (
        ctx.invoked_subcommand is None
        and instance_id is not None
        and instance_id != "list"
    ):
        ctx.fail("Missing command.")
    if ctx.invoked_subcommand:
        return
    list_(ctx)


def list_(ctx: typer.Context) -> None:
    """List all network-instances."""
    # tenant.main
    assert ctx.parent is not None

    active: bool = ctx.params.get("active", False)
    tenant_id: str = ctx.parent.params["tenant_id"]

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    output: list[dict[str, Any]] = [
        {
            "network-instance": network_instance.id,
            "description": network_instance.metadata.get("description", ""),
        }
        for network_instance in tenant.network_instances.values()
    ]

    print(tabulate.tabulate(output, headers="keys"))


@app.command()
def show(
    ctx: typer.Context,
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Show a network-instance configuration."""
    # tenant_network_instance.main
    assert ctx.parent is not None
    # tenant.main
    assert ctx.parent.parent is not None

    tenant_id: str = ctx.parent.parent.params["tenant_id"]
    instance_id: str = ctx.parent.params["instance_id"]

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    network_instance = tenant.network_instances.get(instance_id)
    if not network_instance:
        return
    output = {instance_id: network_instance.model_dump(mode="json")}
    print(
        yaml.safe_dump(output, explicit_start=True, explicit_end=True, sort_keys=False),
    )


@app.command()
def summary(
    ctx: typer.Context,
) -> None:
    """Show a network-instance's connectivity status."""
    # tenant_network_instance.main
    assert ctx.parent is not None
    # tenant.main
    assert ctx.parent.parent is not None

    tenant_id: str = ctx.parent.parent.params["tenant_id"]
    instance_id: str = ctx.parent.params["instance_id"]

    path = helpers.get_config_path(ctx, active=True)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    output: list[dict[str, Any]] = [
        connection.status_summary(tenant.network_instances[instance_id])
        for connection in tenant.network_instances[instance_id].connections.values()
    ]

    print(tabulate.tabulate(output, headers="keys"))


class IkeVersion(str, Enum):
    """IKE versions."""

    ONE = 1
    TWO = 2


# @app.command()
# def add(
#     ctx: typer.Context,
#     # pylint: disable=unused-argument
#     description: Annotated[str, typer.Option()],
#     remote_peer_ip: Annotated[IPAddress, typer.Option(parser=ip_address)],
#     psk: Annotated[str, typer.Option("--pre-shared-key")],
#     metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
#     remote_id: Annotated[Optional[str], typer.Option()] = None,
#     ike_version: Annotated[Optional[IkeVersion], typer.Option()] = None,
#     ike_proposal: Annotated[str, typer.Option()] = None,
#     ike_lifetime: Annotated[Optional[int], typer.Option()] = None,
#     ipsec_proposal: Annotated[str, typer.Option()] = None,
#     ipsec_lifetime: Annotated[Optional[int], typer.Option()] = None,
#     initiation: Annotated[Optional[ipsec.Initiation], typer.Option()] = None,
#     tunnel_ip: Annotated[
#         Optional[IPInterface], typer.Option(parser=ip_interface)
#     ] = None,
#     routes: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
#     # traffic_selectors_local: list[str] = typer.Option(
#     #     None, callback=validate_ip_networks
#     # ),
#     # traffic_selectors_remote: list[str] = typer.Option(
#     #     None, callback=validate_ip_networks
#     # ),
# ):
#     """
#     Add a tunnel to a remote
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     id_: str = ctx.obj["id_"]
#     path = config.VPNC_C_TENANT_CONFIG_DIR.joinpath(f"{id_}.yaml")

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         remote = models.Tenant(**yaml.safe_load(f))

#     if id_ != remote.id:
#         print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
#         return

#     tunnel_id: int = ctx.obj["instance_id"]
#     if remote.connections.get(tunnel_id):
#         print(f"Connection '{tunnel_id}' already exists'.")
#         return

#     tunnel = models.NetworkInstance(**all_args)
#     # if data.get("traffic_selectors_local") or data.get("traffic_selectors_remote"):
#     #     data["traffic_selectors"] = {}
#     #     data["traffic_selectors"]["local"] = set(data.pop("traffic_selectors_local"))
#     #     data["traffic_selectors"]["remote"] = set(data.pop("traffic_selectors_remote"))
#     # else:
#     #     data.pop("traffic_selectors_local")
#     #     data.pop("traffic_selectors_remote")
#     # tunnel = models.Tunnel(**data)
#     remote.connections[tunnel_id] = tunnel

#     output = yaml.safe_dump(
#         remote.model_dump(mode="json"), explicit_start=True, explicit_end=True, sort_keys=False,
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)

#     show(ctx)


# @app.command(name="set")
# def set_(
#     ctx: typer.Context,
#     # pylint: disable=unused-argument
#     description: Annotated[Optional[str], typer.Option()] = None,
#     metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
#     remote_peer_ip: Annotated[
#         Optional[IPAddress], typer.Option(parser=ip_address)
#     ] = None,
#     remote_id: Annotated[Optional[str], typer.Option()] = None,
#     ike_version: Annotated[Optional[IkeVersion], typer.Option()] = None,
#     ike_proposal: Annotated[Optional[str], typer.Option()] = None,
#     ike_lifetime: Annotated[Optional[int], typer.Option()] = None,
#     ipsec_proposal: Annotated[Optional[str], typer.Option()] = None,
#     ipsec_lifetime: Annotated[Optional[int], typer.Option()] = None,
#     initiation: Annotated[Optional[ipsec.Initiation], typer.Option()] = None,
#     tunnel_ip: Annotated[
#         Optional[IPInterface], typer.Option(parser=IPv4Interface)
#     ] = None,
#     psk: Annotated[Optional[str], typer.Option("--pre-shared-key")] = None,
#     routes: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
#     traffic_selectors_local: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
#     traffic_selectors_remote: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
# ):
#     """
#     Set tunnel properties for a remote
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     all_metadata = all_args.pop("metadata", {})
#     all_routes = all_args.pop("routes", set())
#     all_ts_local = all_args.pop("traffic_selectors_local", set())
#     all_ts_remote = all_args.pop("traffic_selectors_remote", set())
#     id_: str = ctx.obj["id_"]
#     path = config.VPNC_C_TENANT_CONFIG_DIR.joinpath(f"{id_}.yaml")

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         remote = models.Tenant(**yaml.safe_load(f))

#     if id_ != remote.id:
#         print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
#         return

#     tunnel_id: int = ctx.obj["instance_id"]
#     if not remote.connections.get(tunnel_id):
#         print(f"Connection '{tunnel_id}' doesn't exists'.")
#         return

#     tunnel = remote.connections[tunnel_id]
#     updated_tunnel = tunnel.model_copy(update=all_args)
#     updated_tunnel.metadata.update(all_metadata)
#     updated_tunnel.routes.update(all_routes)
#     updated_tunnel.traffic_selectors.local.update(all_ts_local)
#     updated_tunnel.traffic_selectors.remote.update(all_ts_remote)

#     remote.connections[tunnel_id] = updated_tunnel

#     output = yaml.safe_dump(
#         remote.model_dump(mode="json"), explicit_start=True, explicit_end=True, sort_keys=False,
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)

#     show(ctx)


# @app.command()
# def unset(
#     ctx: typer.Context,
#     # pylint: disable=unused-argument
#     metadata: Annotated[Optional[list[str]], typer.Option()] = None,
#     remote_id: Annotated[bool, typer.Option()] = False,
#     ike_version: Annotated[bool, typer.Option()] = False,
#     ike_proposal: Annotated[bool, typer.Option()] = False,
#     ike_lifetime: Annotated[bool, typer.Option()] = False,
#     ipsec_proposal: Annotated[bool, typer.Option()] = False,
#     ipsec_lifetime: Annotated[bool, typer.Option()] = False,
#     initiation: Annotated[bool, typer.Option()] = False,
#     tunnel_ip: Annotated[bool, typer.Option()] = False,
#     routes: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
#     traffic_selectors_local: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
#     traffic_selectors_remote: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
# ):
#     """
#     Unset tunnel properties for a remote
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     all_metadata = all_args.pop("metadata", {})
#     all_routes = all_args.pop("routes", [])
#     all_ts_local = all_args.pop("traffic_selectors_local", [])
#     all_ts_remote = all_args.pop("traffic_selectors_remote", [])

#     id_: str = ctx.obj["id_"]
#     path = config.VPNC_C_TENANT_CONFIG_DIR.joinpath(f"{id_}.yaml")

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         remote = models.Tenant(**yaml.safe_load(f))

#     if id_ != remote.id:
#         print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
#         return

#     tunnel_id: int = ctx.obj["instance_id"]
#     if not remote.connections.get(tunnel_id):
#         print(f"Connection '{tunnel_id}' doesn't exists'.")
#         return

#     tunnel = remote.connections[int(tunnel_id)]
#     tunnel_dict = tunnel.model_dump(mode="json")

#     for k in all_args:
#         tunnel_dict.pop(k, None)

#     for k in all_metadata:
#         tunnel_dict.get("metadata", {}).pop(k, None)

#     set(tunnel_dict.get("routes", set())).symmetric_difference(all_routes)
#     set(
#         tunnel_dict.get("traffic_selectors", {}).get("local", set())
#     ).symmetric_difference(set(all_ts_local))
#     set(
#         tunnel_dict.get("traffic_selectors", {}).get("remote", set())
#     ).symmetric_difference(set(all_ts_remote))

#     updated_tunnel = models.NetworkInstance(**tunnel_dict)
#     remote.connections[tunnel_id] = updated_tunnel

#     output = yaml.safe_dump(
#         remote.model_dump(mode="json"), explicit_start=True, explicit_end=True, sort_keys=False,
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)

#     show(ctx)


# @app.command()
# def delete(
#     ctx: typer.Context,
#     dry_run: bool = typer.Option(False, "--dry-run"),
#     force: bool = typer.Option(False, "--force"),
# ):
#     """
#     Delete a specific tunnel from a remote
#     """
#     id_: str = ctx.obj["id_"]
#     tunnel_id: int = ctx.obj["instance_id"]
#     path = config.VPNC_C_TENANT_CONFIG_DIR.joinpath(f"{id_}.yaml")

#     if not path.exists():
#         return
#     with open(path, "r", encoding="utf-8") as f:
#         remote = models.Tenant(**yaml.safe_load(f))
#     if id_ != remote.id:
#         print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
#         return

#     tunnel = remote.connections.get(tunnel_id)
#     if not tunnel:
#         print(f"Tunnel with id '{tunnel_id}' doesn't exist.")
#         return
#     remote.connections.pop(tunnel_id)

#     output = yaml.safe_dump(
#         remote.model_dump(mode="json"), explicit_start=True, explicit_end=True, sort_keys=False,
#     )
#     print(yaml.safe_dump({tunnel_id: tunnel.model_dump(mode="json")}))
#     if dry_run:
#         print(f"(Simulated) Deleted tunnel '{tunnel_id}'")
#     elif force:
#         with open(path, "w", encoding="utf-8") as f:
#             f.write(output)
#         print(f"Deleted tunnel '{tunnel_id}'")
#     elif typer.confirm(
#         f"Are you sure you want to delete remote '{id_}' connection '{tunnel_id}'?",
#         abort=True,
#     ):
#         with open(path, "w", encoding="utf-8") as f:
#             f.write(output)
#         print(f"Deleted tunnel '{tunnel_id}'")


if __name__ == "__main__":
    app()
