#!/usr/bin/env python3

import json
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
from typing import Any, Optional

import typer
import yaml
from typing_extensions import Annotated

from .. import config, models
from ..models import ipsec

app = typer.Typer()

IPAddress = Any
IPInterface = Any
IPNetwork = Any


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context, tunnel_id: Annotated[Optional[int], typer.Argument()] = None
):
    """
    Edit uplinks (tunnels)
    """
    _ = tunnel_id

    if not ctx.obj:
        ctx.obj = {}
    ctx.obj.update(ctx.params)
    if ctx.invoked_subcommand is None and tunnel_id is not None:
        ctx.fail("Missing command.")
    if ctx.invoked_subcommand is None:
        list_(ctx)


def list_(ctx: typer.Context):
    """
    List all uplinks for the service
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    print("tunnel description\n------ -----------")
    for k, v in service.connections.items():
        print(f"{k:<6} {v.description}")


@app.command()
def show(ctx: typer.Context):
    """
    Show a specific uplink
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name != "HUB":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return

    tunnel_id = ctx.obj["tunnel_id"]
    tunnel = service.connections.get(tunnel_id)
    if not tunnel:
        return
    output = {tunnel_id: tunnel.model_dump(mode="json")}
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


class IkeVersion(str, Enum):
    "IKE versions"
    ONE = 1
    TWO = 2


@app.command()
def add(
    ctx: typer.Context,
    # pylint: disable=unused-argument
    description: Annotated[str, typer.Option()],
    remote_peer_ip: Annotated[IPAddress, typer.Option(parser=ip_address)],
    psk: Annotated[str, typer.Option("--pre-shared-key")],
    asn: Annotated[int, typer.Option()],
    metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
    remote_id: Annotated[Optional[str], typer.Option()] = None,
    ike_version: Annotated[Optional[IkeVersion], typer.Option()] = None,
    ike_proposal: Annotated[Optional[str], typer.Option()] = None,
    ike_lifetime: Annotated[Optional[int], typer.Option()] = None,
    ipsec_proposal: Annotated[Optional[str], typer.Option()] = None,
    ipsec_lifetime: Annotated[Optional[int], typer.Option()] = None,
    initiation: Annotated[Optional[ipsec.Initiation], typer.Option()] = None,
    tunnel_ip: Annotated[
        Optional[IPInterface], typer.Option(parser=ip_interface)
    ] = None,
    routes: Annotated[
        Optional[list[IPNetwork]],
        typer.Option(parser=ip_network),
    ] = None,
    priority: Annotated[Optional[int], typer.Option()] = None,
    # traffic_selectors_local: list[str] = typer.Option(
    #     None, callback=validate_ip_networks
    # ),
    # traffic_selectors_remote: list[str] = typer.Option(
    #     None, callback=validate_ip_networks
    # ),
):
    """
    Add a new uplink
    """
    all_args = {k: v for k, v in locals().items() if v}
    all_args.pop("ctx")
    path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name != "HUB":
        print("Service is not running in hub mode")
        return

    tunnel_id = ctx.obj["tunnel_id"]
    if service.connections.get(tunnel_id):
        print(f"Connection '{tunnel_id}' already exists'.")
        return

    tunnel = models.ConnectionConfigIPsec(**all_args)
    # if data.get("traffic_selectors_local") or data.get("traffic_selectors_remote"):
    #     data["traffic_selectors"] = {}
    #     data["traffic_selectors"]["local"] = set(data.pop("traffic_selectors_local"))
    #     data["traffic_selectors"]["remote"] = set(data.pop("traffic_selectors_remote"))
    # else:
    #     data.pop("traffic_selectors_local")
    #     data.pop("traffic_selectors_remote")
    # tunnel = models.Tunnel(**data)
    service.connections[tunnel_id] = tunnel

    output = yaml.safe_dump(
        service.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)

    show(ctx)


@app.command(name="set")
def set_(
    ctx: typer.Context,
    # pylint: disable=unused-argument
    description: Annotated[Optional[str], typer.Option()] = None,
    metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
    remote_peer_ip: Annotated[
        Optional[IPAddress], typer.Option(parser=ip_address)
    ] = None,
    remote_id: Annotated[Optional[str], typer.Option()] = None,
    ike_version: Annotated[Optional[IkeVersion], typer.Option()] = None,
    ike_proposal: Annotated[Optional[str], typer.Option()] = None,
    ike_lifetime: Annotated[Optional[int], typer.Option()] = None,
    ipsec_proposal: Annotated[Optional[str], typer.Option()] = None,
    ipsec_lifetime: Annotated[Optional[int], typer.Option()] = None,
    initiation: Annotated[Optional[ipsec.Initiation], typer.Option()] = None,
    tunnel_ip: Annotated[
        Optional[IPInterface], typer.Option(parser=ip_interface)
    ] = None,
    psk: Annotated[Optional[str], typer.Option("--pre-shared-key")] = None,
    routes: Annotated[
        Optional[list[IPNetwork]],
        typer.Option(parser=ip_network),
    ] = None,
    traffic_selectors_local: Annotated[
        Optional[list[IPNetwork]],
        typer.Option(parser=ip_network),
    ] = None,
    traffic_selectors_remote: Annotated[
        Optional[list[IPNetwork]],
        typer.Option(parser=ip_network),
    ] = None,
    asn: Annotated[Optional[int], typer.Option()] = None,
    priority: Annotated[Optional[int], typer.Option()] = None,
):
    """
    Set properties for an uplink
    """
    all_args = {k: v for k, v in locals().items() if v}
    all_args.pop("ctx")
    all_metadata: list[str] = all_args.pop("metadata", {})
    all_routes = all_args.pop("routes", set())
    all_ts_local = all_args.pop("traffic_selectors_local", set())
    all_ts_remote = all_args.pop("traffic_selectors_remote", set())
    path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name != "HUB":
        print("Service is not running in hub mode")
        return

    tunnel_id: int = ctx.obj["tunnel_id"]
    if not service.connections.get(tunnel_id):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = service.connections[tunnel_id]
    updated_tunnel = tunnel.model_copy(update=all_args)
    updated_tunnel.metadata.update(all_metadata)
    updated_tunnel.routes.update(all_routes)
    updated_tunnel.traffic_selectors.local.update(all_ts_local)
    updated_tunnel.traffic_selectors.remote.update(all_ts_remote)

    service.connections[tunnel_id] = updated_tunnel

    output = yaml.safe_dump(
        service.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)

    show(ctx)


@app.command()
def unset(
    ctx: typer.Context,
    # pylint: disable=unused-argument
    metadata: Annotated[Optional[list[str]], typer.Option()] = None,
    remote_id: Annotated[bool, typer.Option("--remote-id")] = False,
    ike_version: Annotated[bool, typer.Option()] = False,
    ike_proposal: Annotated[bool, typer.Option()] = False,
    ike_lifetime: Annotated[bool, typer.Option()] = False,
    ipsec_proposal: Annotated[bool, typer.Option()] = False,
    ipsec_lifetime: Annotated[bool, typer.Option()] = False,
    initiation: Annotated[bool, typer.Option()] = False,
    routes: Annotated[
        Optional[list[IPNetwork]],
        typer.Option(parser=ip_network),
    ] = None,
    traffic_selectors_local: Annotated[
        Optional[list[IPNetwork]],
        typer.Option(parser=ip_network),
    ] = None,
    traffic_selectors_remote: Annotated[
        Optional[list[IPNetwork]],
        typer.Option(parser=ip_network),
    ] = None,
    priority: Annotated[bool, typer.Option()] = False,
):
    """
    Unset properties for an uplink
    """
    all_args = {k: v for k, v in locals().items() if v}
    all_args.pop("ctx")
    all_metadata = all_args.pop("metadata", {})
    all_routes = all_args.pop("routes", [])
    all_ts_local = all_args.pop("traffic_selectors_local", [])
    all_ts_remote = all_args.pop("traffic_selectors_remote", [])
    path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    tunnel_id = ctx.obj["tunnel_id"]
    if not service.connections.get(tunnel_id):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = service.connections[tunnel_id]
    tunnel_dict = tunnel.model_dump(mode="json")

    for k in all_args:
        tunnel_dict.pop(k)

    for k in all_metadata:
        tunnel_dict.get("metadata", {}).pop(k, None)

    set(tunnel_dict.get("routes", set())).symmetric_difference(all_routes)
    set(
        tunnel_dict.get("traffic_selectors", {}).get("local", set())
    ).symmetric_difference(set(all_ts_local))
    set(
        tunnel_dict.get("traffic_selectors", {}).get("remote", set())
    ).symmetric_difference(set(all_ts_remote))

    updated_tunnel = models.ConnectionConfigIPsec(**tunnel_dict)
    service.connections[tunnel_id] = updated_tunnel

    output = yaml.safe_dump(
        service.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)

    show(ctx)


@app.command()
def delete(
    ctx: typer.Context,
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force"),
    # pylint: disable=unused-argument
):
    """
    Deletes an uplink.
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name != "HUB":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return

    tunnel_id = ctx.obj["tunnel_id"]
    if not service.connections.get(tunnel_id):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = service.connections.get(tunnel_id)
    if not tunnel:
        print(f"Tunnel with id '{tunnel_id}' doesn't exist.")
        return
    service.connections.pop(tunnel_id)

    output = yaml.safe_dump(
        service.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    print(output)
    if dry_run:
        print(f"(Simulated) Deleted uplink '{tunnel_id}'")
    elif force:
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Deleted uplink '{tunnel_id}'")
    elif typer.confirm(
        f"Are you sure you want to delete uplink '{tunnel_id}'?",
        abort=True,
    ):
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Deleted uplink '{tunnel_id}'")


if __name__ == "__main__":
    app()
