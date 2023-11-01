#!/usr/bin/env python3

import json
from dataclasses import asdict
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    ip_address,
    ip_interface,
)
from typing import Optional

import typer
import yaml
from typing_extensions import Annotated

from .. import config, models
from .helpers import ip_addr, ip_if, validate_ip_networks

app = typer.Typer()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context, tunnel_id: Annotated[Optional[int], typer.Argument()] = None
):
    """
    Edit remote connections (tunnels)
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
    List all tunnels for a remote
    """
    id_: str = ctx.obj["id_"]
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    print("tunnel description\n------ -----------")
    for k, v in remote.tunnels.items():
        print(f"{k:<6} {v.description}")


@app.command()
def show(
    ctx: typer.Context,
    active: Annotated[bool, typer.Option("--active")] = False,
):
    """
    Show a specific tunnel for a remote
    """

    id_: str = ctx.obj["id_"]
    tunnel_id: int = ctx.obj["tunnel_id"]
    if active:
        path = config.VPNC_A_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")
    else:
        path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return
    # print(remote)
    # print(remote.tunnels)
    tunnel = remote.tunnels.get(tunnel_id)
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
    ike_proposal: Annotated[str, typer.Option()],
    ipsec_proposal: Annotated[str, typer.Option()],
    psk: Annotated[str, typer.Option("--pre-shared-key")],
    remote_peer_ip: Annotated[
        IPv4Address | IPv6Address, typer.Option(parser=ip_address)
    ],
    ike_version: Annotated[Optional[IkeVersion], typer.Option()] = None,
    remote_id: Annotated[Optional[str], typer.Option()] = None,
    tunnel_ip: Annotated[
        Optional[IPv4Interface], typer.Option(parser=IPv4Interface)
    ] = None,
    metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
    # routes: Annotated[
    #     Optional[set[Union[IPv4Network, IPv6Network]]], typer.Option()
    # ] = None,
    # traffic_selectors_local: list[str] = typer.Option(
    #     None, callback=validate_ip_networks
    # ),
    # traffic_selectors_remote: list[str] = typer.Option(
    #     None, callback=validate_ip_networks
    # ),
):
    """
    Add a tunnel to a remote
    """
    all_args = {k: v for k, v in locals().items() if v}
    all_args.pop("ctx")
    id_: str = ctx.obj["id_"]
    tunnel_id: int = int(ctx.obj["tunnel_id"])
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    if remote.tunnels.get(int(tunnel_id)):
        print(f"Connection '{tunnel_id}' already exists'.")
        return

    updated_tunnel = models.Tunnel(**all_args)
    # if data.get("traffic_selectors_local") or data.get("traffic_selectors_remote"):
    #     data["traffic_selectors"] = {}
    #     data["traffic_selectors"]["local"] = set(data.pop("traffic_selectors_local"))
    #     data["traffic_selectors"]["remote"] = set(data.pop("traffic_selectors_remote"))
    # else:
    #     data.pop("traffic_selectors_local")
    #     data.pop("traffic_selectors_remote")
    # tunnel = models.Tunnel(**data)
    remote.tunnels[tunnel_id] = updated_tunnel
    # print(tunnel_id)

    output = yaml.safe_dump(
        remote.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)

    show(ctx)


@app.command(name="set")
def set_(
    ctx: typer.Context,
    ike_proposal: str = typer.Option(None),
    ipsec_proposal: str = typer.Option(None),
    psk: str = typer.Option("", "--pre-shared-key"),
    remote_peer_ip: str = typer.Option(None, callback=ip_addr),
    remote_id: str = "",
    tunnel_ip: str = typer.Option(None, callback=ip_if),
    description: str = typer.Option(""),
    metadata: str = "{}",
    routes: list[str] = typer.Option(None, callback=validate_ip_networks),
    traffic_selectors_local: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
    traffic_selectors_remote: list[str] = typer.Option(
        None, callback=validate_ip_networks
    ),
    ike_version: Annotated[Optional[IkeVersion], typer.Option()] = None,
):
    """
    Set tunnel properties for a remote
    """
    id_: str = ctx.obj["id_"]
    tunnel_id: int = ctx.obj["tunnel_id"]
    ctx.params["metadata"] = json.loads(metadata)
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
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
            tunnel.routes = list(set(tunnel.routes).union(data["routes"]))
        elif k == "traffic_selectors_local":
            tunnel.traffic_selectors.local = list(
                set(tunnel.traffic_selectors.local).union(
                    data["traffic_selectors_local"]
                )
            )
        elif k == "traffic_selectors_remote":
            tunnel.traffic_selectors.remote = list(
                set(tunnel.traffic_selectors.remote).union(
                    data["traffic_selectors_remote"]
                )
            )
        elif k == "remote_peer_ip":
            tunnel.remote_peer_ip = ip_addr(v)
        elif k == "tunnel_ip":
            tunnel.tunnel_ip = ip_interface(v)
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
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
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
        tunnel.routes = list(set(tunnel.routes).difference(routes))
    if traffic_selectors_local:
        tunnel.traffic_selectors.local = list(
            set(tunnel.traffic_selectors.local).difference(traffic_selectors_local)
        )
    if traffic_selectors_remote:
        tunnel.traffic_selectors.remote = list(
            set(tunnel.traffic_selectors.remote).difference(traffic_selectors_remote)
        )

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
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
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
    elif typer.confirm(
        f"Are you sure you want to delete remote '{id_}' connection '{tunnel_id}'?",
        abort=True,
    ):
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Deleted tunnel '{tunnel_id}'")


if __name__ == "__main__":
    app()
