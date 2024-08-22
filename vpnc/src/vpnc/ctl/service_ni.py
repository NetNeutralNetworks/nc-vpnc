#!/usr/bin/env python3

from enum import Enum
from typing import Any, Optional

import tabulate
import typer
import yaml
from typing_extensions import Annotated

from . import helpers, service_ni_con

app = typer.Typer()
app.add_typer(service_ni_con.app, name="connections")

IPAddress = Any
IPInterface = Any
IPNetwork = Any


def complete_network_instance(ctx: typer.Context) -> list[str]:
    """
    Autocompletes network-instance identifiers
    """
    # service.main
    assert ctx.parent is not None

    active: bool = ctx.parent.params.get("active", False)

    path = helpers.get_service_config_path(ctx, active)

    service = helpers.get_service_config(ctx, path)

    return list(service.network_instances.keys())


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    instance_id: Annotated[
        Optional[str], typer.Argument(autocompletion=complete_network_instance)
    ] = None,
    active: Annotated[bool, typer.Option("--active")] = False,
):
    """
    Entrypoint for service network-instance commands
    """

    _ = active

    if ctx.invoked_subcommand is None and instance_id is not None:
        ctx.fail("Missing command.")
    if ctx.invoked_subcommand is None:
        list_(ctx)


def list_(ctx: typer.Context):
    """
    List all network-instances
    """
    assert ctx.parent is not None

    active: bool = ctx.params.get("active", False)

    path = helpers.get_service_config_path(ctx, active)

    service = helpers.get_service_config(ctx, path)

    output: list[dict[str, Any]] = []
    for _, network_instance in service.network_instances.items():
        output.append(
            {
                "network-instance": network_instance.name,
                "description": network_instance.metadata.get("description", ""),
            }
        )

    print(tabulate.tabulate(output, headers="keys"))


@app.command()
def show(
    ctx: typer.Context,
    active: Annotated[bool, typer.Option("--active")] = False,
):
    """
    Show a network-instance configuration
    """
    # service_network_instance.main
    assert ctx.parent is not None
    instance_id: str = ctx.parent.params["instance_id"]

    path = helpers.get_service_config_path(ctx, active)

    service = helpers.get_service_config(ctx, path)

    # if service.mode.name != "HUB":
    #     print("Service is not running in hub mode")
    #     return

    network_instance = service.network_instances.get(instance_id)
    if not network_instance:
        return
    output = {instance_id: network_instance.model_dump(mode="json")}
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def summary(
    ctx: typer.Context,
):
    """
    Show a network-instance's connectivity status
    """

    assert ctx.parent is not None

    instance_id: str = ctx.parent.params["instance_id"]

    path = helpers.get_service_config_path(ctx, True)

    service = helpers.get_service_config(ctx, path)

    output: list[dict[str, Any]] = []
    for idx, connection in enumerate(
        service.network_instances[instance_id].connections
    ):
        output.append(
            connection.config.status_summary(
                service.network_instances[instance_id], idx
            )
        )

    print(tabulate.tabulate(output, headers="keys"))


class IkeVersion(str, Enum):
    "IKE versions"
    ONE = 1
    TWO = 2


# @app.command()
# def add(
#     ctx: typer.Context,
#     # pylint: disable=unused-argument
#     description: Annotated[str, typer.Option()],
#     remote_peer_ip: Annotated[IPAddress, typer.Option(parser=ip_address)],
#     psk: Annotated[str, typer.Option("--pre-shared-key")],
#     asn: Annotated[int, typer.Option()],
#     metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
#     remote_id: Annotated[Optional[str], typer.Option()] = None,
#     ike_version: Annotated[Optional[IkeVersion], typer.Option()] = None,
#     ike_proposal: Annotated[Optional[str], typer.Option()] = None,
#     ike_lifetime: Annotated[Optional[int], typer.Option()] = None,
#     ipsec_proposal: Annotated[Optional[str], typer.Option()] = None,
#     ipsec_lifetime: Annotated[Optional[int], typer.Option()] = None,
#     initiation: Annotated[Optional[ipsec.Initiation], typer.Option()] = None,
#     tunnel_ip: Annotated[
#         Optional[IPInterface], typer.Option(parser=ip_interface)
#     ] = None,
#     routes: Annotated[
#         Optional[list[IPNetwork]],
#         typer.Option(parser=ip_network),
#     ] = None,
#     priority: Annotated[Optional[int], typer.Option()] = None,
#     # traffic_selectors_local: list[str] = typer.Option(
#     #     None, callback=validate_ip_networks
#     # ),
#     # traffic_selectors_remote: list[str] = typer.Option(
#     #     None, callback=validate_ip_networks
#     # ),
# ):
#     """
#     Add a new uplink
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     path = config.VPNC_C_SERVICE_CONFIG_PATH

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         service = models.ServiceEndpoint(**yaml.safe_load(f))

#     if service.mode.name != "HUB":
#         print("Service is not running in hub mode")
#         return

#     tunnel_id = ctx.obj["tunnel_id"]
#     if service.connections.get(tunnel_id):
#         print(f"Connection '{tunnel_id}' already exists'.")
#         return

#     tunnel = models.ConnectionConfigIPsec(**all_args)
#     # if data.get("traffic_selectors_local") or data.get("traffic_selectors_remote"):
#     #     data["traffic_selectors"] = {}
#     #     data["traffic_selectors"]["local"] = set(data.pop("traffic_selectors_local"))
#     #     data["traffic_selectors"]["remote"] = set(data.pop("traffic_selectors_remote"))
#     # else:
#     #     data.pop("traffic_selectors_local")
#     #     data.pop("traffic_selectors_remote")
#     # tunnel = models.Tunnel(**data)
#     service.connections[tunnel_id] = tunnel

#     output = yaml.safe_dump(
#         service.model_dump(mode="json"), explicit_start=True, explicit_end=True
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
#         Optional[IPInterface], typer.Option(parser=ip_interface)
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
#     asn: Annotated[Optional[int], typer.Option()] = None,
#     priority: Annotated[Optional[int], typer.Option()] = None,
# ):
#     """
#     Set properties for an uplink
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     all_metadata: list[str] = all_args.pop("metadata", {})
#     all_routes = all_args.pop("routes", set())
#     all_ts_local = all_args.pop("traffic_selectors_local", set())
#     all_ts_remote = all_args.pop("traffic_selectors_remote", set())
#     path = config.VPNC_C_SERVICE_CONFIG_PATH

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         service = models.ServiceEndpoint(**yaml.safe_load(f))

#     if service.mode.name != "HUB":
#         print("Service is not running in hub mode")
#         return

#     tunnel_id: int = ctx.obj["tunnel_id"]
#     if not service.connections.get(tunnel_id):
#         print(f"Connection '{tunnel_id}' doesn't exists'.")
#         return

#     tunnel = service.connections[tunnel_id]
#     updated_tunnel = tunnel.model_copy(update=all_args)
#     updated_tunnel.metadata.update(all_metadata)
#     updated_tunnel.routes.update(all_routes)
#     updated_tunnel.traffic_selectors.local.update(all_ts_local)
#     updated_tunnel.traffic_selectors.remote.update(all_ts_remote)

#     service.connections[tunnel_id] = updated_tunnel

#     output = yaml.safe_dump(
#         service.model_dump(mode="json"), explicit_start=True, explicit_end=True
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)

#     show(ctx)


# @app.command()
# def unset(
#     ctx: typer.Context,
#     # pylint: disable=unused-argument
#     metadata: Annotated[Optional[list[str]], typer.Option()] = None,
#     remote_id: Annotated[bool, typer.Option("--remote-id")] = False,
#     ike_version: Annotated[bool, typer.Option()] = False,
#     ike_proposal: Annotated[bool, typer.Option()] = False,
#     ike_lifetime: Annotated[bool, typer.Option()] = False,
#     ipsec_proposal: Annotated[bool, typer.Option()] = False,
#     ipsec_lifetime: Annotated[bool, typer.Option()] = False,
#     initiation: Annotated[bool, typer.Option()] = False,
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
#     priority: Annotated[bool, typer.Option()] = False,
# ):
#     """
#     Unset properties for an uplink
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     all_metadata = all_args.pop("metadata", {})
#     all_routes = all_args.pop("routes", [])
#     all_ts_local = all_args.pop("traffic_selectors_local", [])
#     all_ts_remote = all_args.pop("traffic_selectors_remote", [])
#     path = config.VPNC_C_SERVICE_CONFIG_PATH

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         service = models.ServiceEndpoint(**yaml.safe_load(f))

#     tunnel_id = ctx.obj["tunnel_id"]
#     if not service.connections.get(tunnel_id):
#         print(f"Connection '{tunnel_id}' doesn't exists'.")
#         return

#     tunnel = service.connections[tunnel_id]
#     tunnel_dict = tunnel.model_dump(mode="json")

#     for k in all_args:
#         tunnel_dict.pop(k)

#     for k in all_metadata:
#         tunnel_dict.get("metadata", {}).pop(k, None)

#     set(tunnel_dict.get("routes", set())).symmetric_difference(all_routes)
#     set(
#         tunnel_dict.get("traffic_selectors", {}).get("local", set())
#     ).symmetric_difference(set(all_ts_local))
#     set(
#         tunnel_dict.get("traffic_selectors", {}).get("remote", set())
#     ).symmetric_difference(set(all_ts_remote))

#     updated_tunnel = models.ConnectionConfigIPsec(**tunnel_dict)
#     service.connections[tunnel_id] = updated_tunnel

#     output = yaml.safe_dump(
#         service.model_dump(mode="json"), explicit_start=True, explicit_end=True
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)

#     show(ctx)


# @app.command()
# def delete(
#     ctx: typer.Context,
#     dry_run: bool = typer.Option(False, "--dry-run"),
#     force: bool = typer.Option(False, "--force"),
#     # pylint: disable=unused-argument
# ):
#     """
#     Deletes an uplink.
#     """
#     path = config.VPNC_C_SERVICE_CONFIG_PATH
#     with open(path, "r", encoding="utf-8") as f:
#         service = models.ServiceEndpoint(**yaml.safe_load(f))

#     if service.mode.name != "HUB":
#         print("Service is not running in hub mode")
#         return

#     if not path.exists():
#         return

#     tunnel_id = ctx.obj["tunnel_id"]
#     if not service.connections.get(tunnel_id):
#         print(f"Connection '{tunnel_id}' doesn't exists'.")
#         return

#     tunnel = service.connections.get(tunnel_id)
#     if not tunnel:
#         print(f"Tunnel with id '{tunnel_id}' doesn't exist.")
#         return
#     service.connections.pop(tunnel_id)

#     output = yaml.safe_dump(
#         service.model_dump(mode="json"), explicit_start=True, explicit_end=True
#     )
#     print(output)
#     if dry_run:
#         print(f"(Simulated) Deleted uplink '{tunnel_id}'")
#     elif force:
#         with open(path, "w", encoding="utf-8") as f:
#             f.write(output)
#         print(f"Deleted uplink '{tunnel_id}'")
#     elif typer.confirm(
#         f"Are you sure you want to delete uplink '{tunnel_id}'?",
#         abort=True,
#     ):
#         with open(path, "w", encoding="utf-8") as f:
#             f.write(output)
#         print(f"Deleted uplink '{tunnel_id}'")


if __name__ == "__main__":
    app()
