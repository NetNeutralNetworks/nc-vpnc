#!/usr/bin/env python3

import json
from ipaddress import IPv4Address, IPv4Network, IPv6Network
from typing import Optional

import typer
import yaml
from deepdiff import DeepDiff
from typing_extensions import Annotated

from .. import config, models

app = typer.Typer()


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
    for k, v in service.uplinks.items():
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
    tunnel = service.uplinks.get(tunnel_id)
    if not tunnel:
        return
    output = {tunnel_id: tunnel.model_dump(mode="json")}
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def add(
    ctx: typer.Context,
    # pylint: disable=unused-argument
    asn: Annotated[int, typer.Option()],
    psk: Annotated[str, typer.Option()],
    remote_peer_ip: Annotated[IPv4Address, typer.Option(parser=IPv4Address)],
    description: str | None = None,
    metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
    prefix_uplink_tunnel: Annotated[
        Optional[IPv6Network], typer.Option(parser=IPv6Network)
    ] = None,
    remote_id: Annotated[Optional[str], typer.Option()] = None,
):
    """
    Add a new uplink
    """
    all_args = {k: v for k, v in locals().items() if v}
    all_args.pop("ctx")
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name != "HUB":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return

    tunnel_id = ctx.obj["tunnel_id"]
    if service.uplinks.get(tunnel_id):
        print(f"Connection '{tunnel_id}' already exists'.")
        return

    tunnel = models.Uplink(**all_args)

    service.uplinks[tunnel_id] = tunnel

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
    asn: Annotated[Optional[int], typer.Option()] = None,
    psk: Annotated[Optional[str], typer.Option()] = None,
    description: str | None = None,
    metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
    prefix_uplink_tunnel: Annotated[
        Optional[IPv6Network], typer.Option(parser=IPv6Network)
    ] = None,
    remote_id: Annotated[Optional[str], typer.Option()] = None,
    remote_peer_ip: Annotated[
        Optional[IPv4Address], typer.Option(parser=IPv4Address)
    ] = None,
):
    """
    Set properties for an uplink
    """
    all_args = {k: v for k, v in locals().items() if v}
    all_args.pop("ctx")
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name != "HUB":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return

    tunnel_id = ctx.obj["tunnel_id"]
    if not service.uplinks.get(tunnel_id):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = service.uplinks[tunnel_id]

    updated_tunnel = tunnel.model_copy(update=all_args)
    service.uplinks[tunnel_id] = updated_tunnel

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
    description: Annotated[bool, typer.Option("--description")] = False,
    metadata: Annotated[Optional[list[str]], typer.Option()] = None,
    prefix_uplink_tunnel: Annotated[
        bool, typer.Option("--prefix-uplink-tunnel")
    ] = False,
    remote_id: Annotated[bool, typer.Option("--remote-id")] = False,
):
    """
    Unset properties for an uplink
    """
    all_args = {k: v for k, v in locals().items() if v}
    all_args.pop("ctx")
    all_metadata: list[str] = all_args.pop("metadata", [])
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if not path.exists():
        return

    tunnel_id = ctx.obj["tunnel_id"]
    if not service.uplinks.get(tunnel_id):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = service.uplinks[tunnel_id]
    tunnel_dict = tunnel.model_dump(mode="json")

    for k in all_args:
        tunnel_dict.pop(k)

    for i in all_metadata:
        tunnel_dict["metadata"].pop(i)

    updated_tunnel = models.Uplink(**tunnel_dict)
    service.uplinks[tunnel_id] = updated_tunnel

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
    if not service.uplinks.get(tunnel_id):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = service.uplinks.get(tunnel_id)
    if not tunnel:
        print(f"Tunnel with id '{tunnel_id}' doesn't exist.")
        return
    service.uplinks.pop(tunnel_id)

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
