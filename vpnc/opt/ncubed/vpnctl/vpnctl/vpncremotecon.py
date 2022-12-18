#!/usr/bin/env python3

import json
from dataclasses import asdict
from enum import Enum

import typer
import yaml

from . import consts, datacls
from .helpers import (
    validate_ip_address,
    validate_ip_interface,
    validate_ip_networks,
)

app = typer.Typer()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, tunnel_id: int = typer.Argument(None)):
    """
    Edit remote connections (tunnels)
    """
    _ = tunnel_id

    ctx.obj.update(ctx.params)
    if ctx.invoked_subcommand is None and tunnel_id is not None:
        ctx.fail("Missing command.")
    if ctx.invoked_subcommand is None:
        list_(ctx)


@app.command(name="list")
def list_(ctx: typer.Context):
    """
    List all tunnels for a remote
    """
    id_: str = ctx.obj["id_"]
    path = consts.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = datacls.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    print("tunnel description\n------ -----------")
    for k, v in remote.tunnels.items():
        print(f"{k:<6} {v.description}")


@app.command()
def show(
    ctx: typer.Context,
    active: bool = typer.Option(False, "--active/--candidate"),
):
    """
    Show a specific tunnel for a remote
    """
    id_: str = ctx.obj["id_"]
    tunnel_id: int = ctx.obj["tunnel_id"]
    if active:
        path = consts.VPNC_A_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")
    else:
        path = consts.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = datacls.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    tunnel = remote.tunnels.get(tunnel_id)
    if not tunnel:
        return
    output = {tunnel_id: asdict(tunnel)}
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


class IkeVersion(str, Enum):
    "IKE versions"
    ONE = 1
    TWO = 2


@app.command()
def add(
    ctx: typer.Context,
    ike_version: IkeVersion = IkeVersion.TWO,
    ike_proposal: str = typer.Option(...),
    ipsec_proposal: str = typer.Option(...),
    psk: str = typer.Option(..., "--pre-shared-key"),
    remote_peer_ip: str = typer.Option(..., callback=validate_ip_address),
    remote_id: str = "",
    tunnel_ip: str = typer.Option(None, callback=validate_ip_interface),
    description: str = typer.Option(...),
    metadata: str = "{}",
    routes: list[str] = typer.Option(None, callback=validate_ip_networks),
    traffic_selectors_local: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
    traffic_selectors_remote: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
):
    """
    Add a tunnel to a remote
    """
    id_: str = ctx.obj["id_"]
    tunnel_id: int = ctx.obj["tunnel_id"]
    ctx.params["metadata"] = json.loads(metadata)
    path = consts.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = datacls.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    if remote.tunnels.get(int(tunnel_id)):
        print(f"Connection '{tunnel_id}' already exists'.")
        return

    data = ctx.params
    if data.get("traffic_selectors_local") or data.get("traffic_selectors_remote"):
        data["traffic_selectors"] = {}
        data["traffic_selectors"]["local"] = set(data.pop("traffic_selectors_local"))
        data["traffic_selectors"]["remote"] = set(data.pop("traffic_selectors_remote"))
    else:
        data.pop("traffic_selectors_local")
        data.pop("traffic_selectors_remote")
    tunnel = datacls.Tunnel(**data)
    remote.tunnels[int(tunnel_id)] = tunnel

    output = yaml.safe_dump(asdict(remote), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(ctx, active=False)


@app.command(name="set")
def set_(
    ctx: typer.Context,
    ike_version: IkeVersion = IkeVersion.TWO,
    ike_proposal: str = typer.Option(None),
    ipsec_proposal: str = typer.Option(None),
    psk: str = typer.Option("", "--pre-shared-key"),
    remote_peer_ip: str = typer.Option(None, callback=validate_ip_address),
    remote_id: str = "",
    tunnel_ip: str = typer.Option(None, callback=validate_ip_interface),
    description: str = typer.Option(""),
    metadata: str = "{}",
    routes: list[str] = typer.Option(None, callback=validate_ip_networks),
    traffic_selectors_local: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
    traffic_selectors_remote: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
):
    """
    Set tunnel properties for a remote
    """
    id_: str = ctx.obj["id_"]
    tunnel_id: int = ctx.obj["tunnel_id"]
    ctx.params["metadata"] = json.loads(metadata)
    path = consts.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = datacls.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    if not remote.tunnels.get(int(tunnel_id)):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = remote.tunnels[int(tunnel_id)]

    data = ctx.params
    for k, v in data.items():
        if not v:
            continue
        if k == "routes":
            tunnel.routes = set(tunnel.routes).union(data["routes"])
        elif k == "traffic_selectors_local":
            tunnel.traffic_selectors.local = set(tunnel.traffic_selectors.local).union(
                data["traffic_selectors_local"]
            )
        elif k == "traffic_selectors_remote":
            tunnel.traffic_selectors.remote = set(
                tunnel.traffic_selectors.remote
            ).union(data["traffic_selectors_remote"])
        elif k == "remote_peer_ip":
            tunnel.remote_peer_ip = str(v)
        elif k == "tunnel_ip":
            tunnel.tunnel_ip = str(v)
        elif k == "metadata":
            tunnel.metadata.update(v)
        else:
            setattr(tunnel, k, v)

    if tunnel.routes and (
        tunnel.traffic_selectors.remote or tunnel.traffic_selectors.local
    ):
        raise ValueError("Cannot specify both routes and traffic selectors.")

    output = yaml.safe_dump(asdict(remote), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(ctx, active=False)


@app.command()
def unset(
    ctx: typer.Context,
    tunnel_ip: bool = False,
    metadata: list[str] = typer.Option([]),
    routes: list[str] = typer.Option(None, callback=validate_ip_networks),
    traffic_selectors_local: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
    traffic_selectors_remote: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
):
    """
    Unset tunnel properties for a remote
    """
    id_: str = ctx.obj["id_"]
    tunnel_id: int = ctx.obj["tunnel_id"]
    path = consts.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = datacls.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    if not remote.tunnels.get(int(tunnel_id)):
        print(f"Connection '{tunnel_id}' doesn't exists'.")
        return

    tunnel = remote.tunnels[int(tunnel_id)]

    if tunnel_ip:
        tunnel.tunnel_ip = None
    for i in metadata:
        tunnel.metadata.pop(i)
    if routes:
        tunnel.routes = set(tunnel.routes).difference(routes)
    if traffic_selectors_local:
        tunnel.traffic_selectors.local = set(tunnel.traffic_selectors.local).difference(
            traffic_selectors_local
        )
    if traffic_selectors_remote:
        tunnel.traffic_selectors.remote = set(
            tunnel.traffic_selectors.remote
        ).difference(traffic_selectors_remote)

    if tunnel.routes and (
        tunnel.traffic_selectors.remote or tunnel.traffic_selectors.local
    ):
        raise ValueError("Cannot specify both routes and traffic selectors.")

    output = yaml.safe_dump(asdict(remote), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(ctx, active=False)


@app.command()
def delete(
    ctx: typer.Context,
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force"),
):
    """
    Delete a specific tunnel from a remote
    """
    id_: str = ctx.obj["id_"]
    tunnel_id: int = ctx.obj["tunnel_id"]
    path = consts.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = datacls.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    tunnel = remote.tunnels.get(int(tunnel_id))
    if not tunnel:
        print(f"Tunnel with id '{tunnel_id}' doesn't exist.")
        return
    remote.tunnels.pop(int(tunnel_id))

    output = yaml.safe_dump(asdict(remote), explicit_start=True, explicit_end=True)
    print(yaml.safe_dump({tunnel_id: asdict(tunnel)}))
    if dry_run:
        print(f"(Simulated) Deleted tunnel '{tunnel_id}'")
    elif force:
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Deleted tunnel '{tunnel_id}'")
    elif delete_ := typer.confirm(
        f"Are you sure you want to delete remote '{id_}' connection '{tunnel_id}'",
        abort=True,
    ):
        if delete_:
            with open(path, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Deleted tunnel '{tunnel_id}'")


if __name__ == "__main__":
    app()
