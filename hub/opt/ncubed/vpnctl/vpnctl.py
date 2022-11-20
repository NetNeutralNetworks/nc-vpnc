#! /bin/python3

# import difflib
import argparse
import glob
import json
import logging
import pathlib
import sys
from dataclasses import asdict, dataclass
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
from typing import Any

import jinja2
import yaml

logging.basicConfig()
logger = logging.getLogger()

# The configuration
VPNC_VPN_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnc-vpn")
VPNCTL_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnctl")
VPNCTL_TEMPLATE_DIR = pathlib.Path(__file__).parent.joinpath("templates")

VPNCTL_TEMPLATE_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(VPNCTL_TEMPLATE_DIR)
)


def new_vpn(data):
    """
    Outputs an example configuration file.
    """
    _ = data
    template = VPNCTL_TEMPLATE_DIR.joinpath("vpnctl_customer.yaml.j2")
    with open(template, "r", encoding="utf-8") as f:
        print(f.read())


def render_vpn(data):
    """
    Generates Swanctl configuration from vpnctl YAML configuration files.
    """
    remote: str = data.remote
    commit: bool = data.commit
    purge: bool = data.purge
    diff: bool = data.diff

    config_file = VPNCTL_CONFIG_DIR.joinpath(f"{remote}.yaml")

    if not config_file.exists():
        logger.warning("Config '%s' not found", remote)
        return

    with open(config_file, "r", encoding="utf-8") as handle:
        vpnctl_config = yaml.safe_load(handle)

    # if diff:
    #         with open(out_path, "r", encoding="utf-8") as file:
    #             diff_file = file.read()
    #         for i in difflib.unified_diff(
    #             diff_file.splitlines(), tunnel_render.splitlines()
    #         ):
    #             print(i)
    #     else:
    #         print(tunnel_render)
    #     if commit:
    #         with open(out_path, "w+", encoding="utf-8") as file:
    #             file.write(tunnel_render)

    if purge:
        delete_vpn_renders(vpnctl_config)


def delete_vpn_renders(vpn_config: dict[str, str | dict[str, Any]]):
    """Deletes rendered swanctl config if not in vpnctl config."""

    remote = str(vpn_config["remote"])

    files = glob.glob(str(VPN_CONFIG_PATH.joinpath(f"{remote}-*.conf")))
    diff_conn: set[str] = {pathlib.Path(x).stem for x in files}

    ref_conn: set[str] = {f"{remote}-{x:03}" for x in vpn_config["tunnels"].keys()}

    del_connections = diff_conn.difference(ref_conn)
    if not del_connections:
        print("No connections to delete.")
        return

    print("The following connections are not defined and will be deleted:")
    print(list(del_connections))
    print("Are you sure you want to delete the connections?")
    while True:
        confirm = input("[y]Yes or [n]No: ")
        if confirm in ("y", "Y", "yes"):
            break
        if confirm in ("n", "N", "no"):
            print("No connections deleted.")
            sys.exit(0)
        else:
            print("\n Invalid Option. Please Enter a Valid Option.")
    for connection in del_connections:
        del_path = VPN_CONFIG_PATH.joinpath(f"{connection}.conf")
        del_path.unlink(missing_ok=True)
        print(f"Deleted connection '{connection}'.")

    print("Connections succesfully deleted.")


@dataclass
class TrafficSelectors:
    """
    Defines a traffic selector data structure
    """

    local: list[IPv4Network | IPv6Network]
    remote: list[IPv4Network | IPv6Network]

    def __post_init__(self):
        self.local = [str(x) for x in self.local]
        self.remote = [str(x) for x in self.remote]


@dataclass
class Tunnel:
    """
    Defines a tunnel data structure
    """

    ike_proposal: str
    ipsec_proposal: str
    psk: str
    remote_peer_ip: IPv4Address | IPv6Address
    remote_id: str | None = None
    metadata: dict | None = None
    tunnel_ip: IPv4Interface | IPv6Interface | None = None
    ike_version: int = 2
    # Mutually exclusive with traffic selectors
    routes: list[IPv4Network | IPv6Network] | None = None
    # Mutually exclusive with routes
    traffic_selectors: TrafficSelectors | None = None

    def __post_init__(self):
        if self.routes and self.traffic_selectors:
            raise ValueError("Cannot specify both routes and traffic selectors.")
        if not self.remote_id:
            self.remote_id = str(self.remote_peer_ip)
        if self.traffic_selectors:
            self.traffic_selectors = TrafficSelectors(**self.traffic_selectors)
        if self.routes:
            self.routes = [str(x) for x in self.routes]
        self.remote_peer_ip = str(self.remote_peer_ip)
        if self.tunnel_ip:
            self.tunnel_ip = str(self.tunnel_ip)


@dataclass
class Remote:
    """
    Defines a remote side data structure
    """

    id: str
    name: str
    metadata: dict
    tunnels: dict[int, Tunnel]

    def __post_init__(self):
        if self.tunnels:
            self.tunnels = {k: Tunnel(**v) for (k, v) in self.tunnels.items()}
        else:
            self.tunnels = {}


def remote_list(args: argparse.Namespace):
    """
    List all remotes
    """
    _ = args

    for i in VPNCTL_CONFIG_DIR.glob("*.yaml"):
        file_name = i.stem
        with open(i, "r", encoding="utf-8") as f:
            remote = Remote(**yaml.safe_load(f))
        if file_name != remote.id:
            print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        elif file_name == remote.id:
            print(file_name)


def remote_show(args: argparse.Namespace):
    """
    Show a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    output = asdict(remote)
    output["tunnels"] = len(output["tunnels"]) if output.get("tunnels") else 0
    print(yaml.dump(output))


def remote_add(args: argparse.Namespace):
    """
    Add a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")
    if path.exists():
        print(f"Remote '{args.id}' already exists.")
        return

    remote = Remote(args.id, args.name, args.metadata, {})

    output = yaml.dump(asdict(remote))
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    remote_show(args)


def remote_set(args: argparse.Namespace):
    """
    Set a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    if args.name:
        remote.name = args.name
    if args.metadata:
        remote.metadata = args.metadata

    output = yaml.dump(asdict(remote))
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    remote_show(args)


def remote_delete(args: argparse.Namespace):
    """
    Delete a remote side
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")
    if not path.exists():
        print(f"Remote '{args.id}' doesn't exist.")
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    output = asdict(remote)
    if args.dry_run:
        print(f"(Simulated) Deleted remote '{args.id}'")
        print(yaml.dump(output))
    else:
        path.unlink()
        print(f"Deleted remote '{args.id}'")
        print(yaml.dump(output))


def connection_list(args: argparse.Namespace):
    """
    List all tunnels for a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    output = {k: asdict(v) for (k, v) in remote.tunnels.items()}
    print(yaml.dump(output))


def connection_show(args: argparse.Namespace):
    """
    Show a specific tunnel for a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    tunnel = remote.tunnels.get(int(args.tunnel_id))
    if not tunnel:
        return
    output = {int(args.tunnel_id): asdict(tunnel)}
    print(yaml.dump(output))


def connection_add(args: argparse.Namespace):
    """
    Add a tunnel to a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    if remote.tunnels.get(int(args.tunnel_id)):
        print(f"Connection '{args.tunnel_id}' already exists'.")
        return

    data = vars(args).copy()
    data.pop("func")
    data.pop("id")
    data.pop("tunnel_id")
    if data.get("traffic_selectors_local") or data.get("traffic_selectors_remote"):
        data["traffic_selectors"] = {}
        data["traffic_selectors"]["local"] = data.pop("traffic_selectors_local")
        data["traffic_selectors"]["remote"] = data.pop("traffic_selectors_remote")
    else:
        data.pop("traffic_selectors_local")
        data.pop("traffic_selectors_remote")
    tunnel = Tunnel(**data)
    remote.tunnels[int(args.tunnel_id)] = tunnel

    output = yaml.dump(asdict(remote))
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    connection_show(args)


def connection_set(args: argparse.Namespace):
    """
    Set tunnel properties for a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    if not remote.tunnels.get(int(args.tunnel_id)):
        print(f"Connection '{args.tunnel_id}' doesn't exists'.")
        return

    tunnel = remote.tunnels[int(args.tunnel_id)]

    data = vars(args).copy()
    data.pop("func")
    data.pop("id")
    data.pop("tunnel_id")
    for k, v in data.items():
        if not v:
            continue
        if k == "routes":
            tunnel.routes = [str(x) for x in v]
        elif k == "traffic_selectors_local":
            tunnel.traffic_selectors.local = [str(x) for x in v]
        elif k == "traffic_selectors_remote":
            tunnel.traffic_selectors.remote = [str(x) for x in v]
        elif k == "remote_peer_ip":
            tunnel.remote_peer_ip = str(v)
        elif k == "tunnel_ip":
            tunnel.tunnel_ip = str(v)
        else:
            setattr(tunnel, k, v)

    if tunnel.routes and tunnel.traffic_selectors:
        raise ValueError("Cannot specify both routes and traffic selectors.")

    output = yaml.dump(asdict(remote))
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    connection_show(args)


def connection_delete(args: argparse.Namespace):
    """
    Delete a specific tunnel from a remote
    """
    path = VPNCTL_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    tunnel = remote.tunnels.get(int(args.tunnel_id))
    if not tunnel:
        print(f"Tunnel with id '{args.tunnel_id}' doesn't exist.")
        return
    remote.tunnels.pop(int(args.tunnel_id))

    output = yaml.dump(asdict(remote))
    if args.dry_run:
        print(f"(Simulated) Deleted tunnel '{args.tunnel_id}'")
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Deleted tunnel '{args.tunnel_id}'")
    print(output)


def main():
    parser = argparse.ArgumentParser(description="Manage VPNC configuration")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("id", type=str, action="store", help="Resource identifier")
    rem_add = argparse.ArgumentParser(add_help=False)
    rem_add.add_argument(
        "--name",
        "-n",
        type=str,
        action="store",
        default="",
        help="Name of the resource.",
    )
    rem_add.add_argument(
        "--metadata",
        "-m",
        type=json.loads,
        action="store",
        default={},
        help="Metadata for the resource, can contain any random key/value pair except the key 'name'",
    )
    delete = argparse.ArgumentParser(add_help=False)
    # delete.add_argument("--diff", action="store_true", help="Shows a diff")
    delete.add_argument(
        "--dry-run", action="store_true", help="Does not apply the change"
    )

    subparser = parser.add_subparsers(help="Sub command help")

    parser_remote = subparser.add_parser(
        "remote", help="Create a new base configuration."
    )
    parser_remote.set_defaults(func=remote_list)
    parser_remote_sub = parser_remote.add_subparsers()
    parser_remote_list = parser_remote_sub.add_parser("list")
    parser_remote_list.set_defaults(func=remote_list)
    parser_remote_show = parser_remote_sub.add_parser("show", parents=[shared])
    parser_remote_show.set_defaults(func=remote_show)
    parser_remote_add = parser_remote_sub.add_parser("add", parents=[shared, rem_add])
    parser_remote_add.set_defaults(func=remote_add)
    parser_remote_set = parser_remote_sub.add_parser("set", parents=[shared, rem_add])
    parser_remote_set.set_defaults(func=remote_set)
    parser_remote_delete = parser_remote_sub.add_parser(
        "delete", parents=[shared, delete]
    )
    parser_remote_delete.set_defaults(func=remote_delete)

    con_shared = argparse.ArgumentParser(add_help=False)
    con_shared.add_argument(
        "--tunnel_id",
        "-t",
        type=str,
        action="store",
        required=True,
        help="Name of the resource.",
    )
    con_add = argparse.ArgumentParser(add_help=False)
    con_add.add_argument(
        "--ike-proposal",
        "-ikep",
        type=str,
        action="store",
        required=True,
        help="IKE proposal.",
    )
    con_add.add_argument(
        "--ipsec-proposal",
        "-ipsp",
        type=str,
        action="store",
        required=True,
        help="IPSec proposal.",
    )
    con_add.add_argument(
        "--pre-shared-key",
        "-psk",
        dest="psk",
        type=str,
        action="store",
        required=True,
        help="Pre-shared key.",
    )
    con_add.add_argument(
        "--remote-peer-ip",
        "-rpi",
        type=ip_address,
        action="store",
        required=True,
        help="Remote peer IP address.",
    )
    con_set = argparse.ArgumentParser(add_help=False)
    con_set.add_argument(
        "--ike-proposal",
        "-ikep",
        type=str,
        action="store",
        help="IKE proposal.",
    )
    con_set.add_argument(
        "--ipsec-proposal",
        "-ipsp",
        type=str,
        action="store",
        help="IPSec proposal.",
    )
    con_set.add_argument(
        "--pre-shared-key",
        "-psk",
        dest="psk",
        type=str,
        action="store",
        help="Pre-shared key.",
    )
    con_set.add_argument(
        "--remote-peer-ip",
        "-rpi",
        type=ip_address,
        action="store",
        help="Remote peer IP address.",
    )

    con_mod = argparse.ArgumentParser(add_help=False)
    con_mod.add_argument(
        "--metadata",
        "-m",
        type=json.loads,
        action="store",
        default={},
        help="Metadata for the resource, can contain any random key/value pair except the key 'name'",
    )
    con_mod.add_argument(
        "--ike-version",
        "-ikev",
        type=int,
        choices=[1, 2],
        action="store",
        default=2,
        help="IKE version.",
    )
    con_mod.add_argument(
        "--remote-id",
        "-rid",
        type=str,
        action="store",
        help="Remote IKE identifier.",
    )
    con_mod.add_argument(
        "--tunnel-ip",
        "-tip",
        type=ip_interface,
        action="store",
        help="Tunnel interface IP.",
    )
    con_mod.add_argument(
        "--routes",
        "-rt",
        type=ip_network,
        nargs="+",
        action="store",
        help="Tunnel interface IP.",
    )
    con_mod.add_argument(
        "--traffic-selectors-local",
        "-tsl",
        type=ip_network,
        nargs="+",
        action="store",
        help="Traffic selectors local.",
    )
    con_mod.add_argument(
        "--traffic-selectors-remote",
        "-tsr",
        type=ip_network,
        nargs="+",
        action="store",
        help="Traffic selectors remote.",
    )

    parser_connection = subparser.add_parser(
        "connection", help="Create a new base configuration."
    )
    parser_connection_sub = parser_connection.add_subparsers()
    parser_connection_list = parser_connection_sub.add_parser("list", parents=[shared])
    parser_connection_list.set_defaults(func=connection_list)
    parser_connection_show = parser_connection_sub.add_parser(
        "show", parents=[shared, con_shared]
    )
    parser_connection_show.set_defaults(func=connection_show)
    parser_connection_add = parser_connection_sub.add_parser(
        "add", parents=[shared, con_shared, con_add, con_mod]
    )
    parser_connection_add.set_defaults(func=connection_add)
    parser_connection_set = parser_connection_sub.add_parser(
        "set", parents=[shared, con_shared, con_set, con_mod]
    )
    parser_connection_set.set_defaults(func=connection_set)
    parser_connection_delete = parser_connection_sub.add_parser(
        "delete", parents=[shared, delete, con_shared]
    )
    parser_connection_delete.set_defaults(func=connection_delete)
    # parser_remote.set_defaults(func=remote)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
