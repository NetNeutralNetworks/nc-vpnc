#! /bin/python3

import difflib
import argparse
import json
import logging
import pathlib
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

import yaml

logging.basicConfig()
logger = logging.getLogger()

# The configuration
VPNC_REMOTE_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnc-remote")
VPNC_SERVICE_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnc-service")
VPNCTL_REMOTE_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnctl/remote")
VPNCTL_SERVICE_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnctl/service")


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
    description: str | None = None
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
    tunnels: dict[int, Tunnel]
    metadata: dict | None = None

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

    print("remote name\n" "------ ----")
    for i in VPNCTL_REMOTE_CONFIG_DIR.glob("*.yaml"):
        file_name = i.stem
        with open(i, "r", encoding="utf-8") as f:
            remote = Remote(**yaml.safe_load(f))
        if file_name != remote.id:
            print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        elif file_name == remote.id:
            print(f"{remote.id:<6} {remote.name}")


def remote_show(args: argparse.Namespace):
    """
    Show a remote
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    output = asdict(remote)
    if getattr(args, "full", False) and args.full:
        print(yaml.dump(output))
    else:
        output["tunnel_count"] = (
            len(output.pop("tunnels")) if output.get("tunnels") else 0
        )
        print(yaml.dump(output))


def remote_add(args: argparse.Namespace):
    """
    Add a remote
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")
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
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

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


def remote_unset(args: argparse.Namespace):
    """
    Unset a remote
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    if not getattr(args, "r_unset", False):
        return
    for i in args.r_unset:
        setattr(remote, i, None)

    output = yaml.dump(asdict(remote))
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    remote_show(args)


def remote_delete(args: argparse.Namespace):
    """
    Delete a remote side
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")
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


def remote_commit(args: argparse.Namespace):
    """
    Commit configuration
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")
    path_diff = VPNC_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")
    if not path.exists():
        remote_yaml = ""
    else:
        with open(path, "r", encoding="utf-8") as f:
            remote_yaml = f.read()
            remote = Remote(**yaml.safe_load(remote_yaml))
        if args.id != remote.id:
            print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
            return

    if not path_diff.exists():
        remote_diff_yaml = ""
    else:
        with open(path_diff, "r", encoding="utf-8") as f:
            remote_diff_yaml = f.read()
            remote_diff = Remote(**yaml.safe_load(remote_diff_yaml))
        if args.id != remote_diff.id:
            print(
                f"Mismatch between diff file name '{args.id}' and id '{remote_diff.id}'."
            )
            return

    if remote_yaml == remote_diff_yaml:
        print("No changes.")
        return

    if args.revert:
        
        if args.diff:
            for i in difflib.unified_diff(
                remote_yaml.splitlines(), remote_diff_yaml.splitlines()
            ):
                print(i)
        if args.dry_run:
            print("(Simulated) Revert succeeded.")
            return
        if not path_diff.exists():
            path.unlink(missing_ok=True)
            print("Revert succeeded.")
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(remote_diff_yaml)
        print("Revert succeeded.")
        return

    if args.diff:
        for i in difflib.unified_diff(
            remote_diff_yaml.splitlines(), remote_yaml.splitlines()
        ):
            print(i)

    if args.dry_run:
        print("(Simulated) Commit succeeded.")
        return
    if not path.exists():
        path_diff.unlink(missing_ok=True)
        print("Commit succeeded.")
        return

    with open(path_diff, "w", encoding="utf-8") as f:
        f.write(remote_yaml)
    print("Commit succeeded.")


def connection_list(args: argparse.Namespace):
    """
    List all tunnels for a remote
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = Remote(**yaml.safe_load(f))
    if args.id != remote.id:
        print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
        return

    print("tunnel description\n" "------ -----------")
    for k, v in remote.tunnels.items():
        print(f"{k:<6} {v.description}")


def connection_show(args: argparse.Namespace):
    """
    Show a specific tunnel for a remote
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

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
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

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
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

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


def connection_unset(args: argparse.Namespace):
    """
    Unset tunnel properties for a remote
    """
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

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

    for i in args.t_unset:
        setattr(tunnel, i, None)

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
    path = VPNCTL_REMOTE_CONFIG_DIR.joinpath(f"{args.id}.yaml")

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
    """
    Main function to parse arguments
    """

    # shared parsers for remote
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "id", type=str, action="store", help="Remote resource identifier."
    )
    delete = argparse.ArgumentParser(add_help=False)
    delete.add_argument("--diff", action="store_true", help="Show a diff.")
    delete.add_argument(
        "--dry-run", action="store_true", help="Don't apply the change."
    )

    # shared parsers for connection
    con_shared = argparse.ArgumentParser(add_help=False)
    con_shared.add_argument(
        "tunnel_id",
        type=str,
        action="store",
        help="Tunnel resource identifier.",
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
        help="IPsec proposal.",
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
        help="IPsec proposal.",
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
        help="Tunnel resource metdata. Can contain any random key/value pair.",
    )
    con_mod.add_argument(
        "--description",
        "-d",
        type=str,
        action="store",
        default={},
        help="Tunnel description.",
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
        help="Tunnel interface IP with prefix.",
    )
    con_mod.add_argument(
        "--routes",
        "-rt",
        type=ip_network,
        nargs="+",
        action="store",
        help="List of remote accessible prefixes.",
    )
    con_mod.add_argument(
        "--traffic-selectors-local",
        "-tsl",
        type=ip_network,
        nargs="+",
        action="store",
        help="List of local traffic selectors.",
    )
    con_mod.add_argument(
        "--traffic-selectors-remote",
        "-tsr",
        type=ip_network,
        nargs="+",
        action="store",
        help="List of remote traffic selectors.",
    )

    parser = argparse.ArgumentParser(description="Manage VPNC status and configuration")
    sp = parser.add_subparsers()

    # vtysh configure
    sp_conf = sp.add_parser("configure", help="Configure mode.")
    sp_conf_sp = sp_conf.add_subparsers()

    # vtysh configure remote
    sp_conf_rem = sp_conf_sp.add_parser(
        "remote", help="CRUD operations on remotes and tunnels."
    )
    sp_conf_rem.set_defaults(func=remote_list)
    sp_conf_rem_sp = sp_conf_rem.add_subparsers()

    # vtysh configure remote list <id>?
    sp_conf_rem_list = sp_conf_rem_sp.add_parser(
        "list", help="List operations on remotes."
    )
    sp_conf_rem_list.add_argument(
        "id", type=str, nargs="?", action="store", help="Remote resource identifier."
    )
    sp_conf_rem_list.set_defaults(func=remote_list)
    # vtysh configure remote list <id> connection
    sp_conf_rem_list_sp = sp_conf_rem_list.add_subparsers()
    sp_conf_rem_list_con = sp_conf_rem_list_sp.add_parser(
        "connection", help="List operations on tunnels."
    )
    sp_conf_rem_list_con.set_defaults(func=connection_list)
    # vtysh configure remote show <id>
    sp_conf_rem_show = sp_conf_rem_sp.add_parser(
        "show", parents=[shared], help="Show operations on remotes."
    )
    sp_conf_rem_show.add_argument(
        "--full",
        action="store_true",
        help="Shows the full configuration including connections",
    )
    sp_conf_rem_show.set_defaults(func=remote_show)
    # vtysh configure remote show <id> connection <tid>
    sp_conf_rem_show_sp = sp_conf_rem_show.add_subparsers()
    sp_conf_rem_show_con = sp_conf_rem_show_sp.add_parser(
        "connection", parents=[con_shared], help="Show operations on tunnels."
    )
    sp_conf_rem_show_con.set_defaults(func=connection_show)
    # vtysh configure remote add <id>
    sp_conf_rem_add = sp_conf_rem_sp.add_parser(
        "add", parents=[shared], help="Add operations on remotes."
    )
    sp_conf_rem_add.add_argument(
        "--name",
        "-n",
        type=str,
        action="store",
        required=True,
        default="",
        help="Remote resource name.",
    )
    sp_conf_rem_add.add_argument(
        "--metadata",
        "-m",
        type=json.loads,
        action="store",
        default={},
        help="Remote resource metdata. Can contain any random key/value pair.",
    )
    sp_conf_rem_add.set_defaults(func=remote_add)
    # vtysh configure remote add <id> connection <tid>
    sp_conf_rem_add_sp = sp_conf_rem_add.add_subparsers()
    sp_conf_rem_add_con = sp_conf_rem_add_sp.add_parser(
        "connection",
        parents=[con_shared, con_add, con_mod],
        help="Add operations on tunnels.",
    )
    sp_conf_rem_add_con.set_defaults(func=connection_add)
    # vtysh configure remote set <id>
    sp_conf_rem_set = sp_conf_rem_sp.add_parser(
        "set", parents=[shared], help="Set operations on remotes."
    )
    sp_conf_rem_set.add_argument(
        "--name",
        "-n",
        type=str,
        action="store",
        default="",
        help="Remote resource name.",
    )
    sp_conf_rem_set.add_argument(
        "--metadata",
        "-m",
        type=json.loads,
        action="store",
        default={},
        help="Remote resource metdata. Can contain any random key/value pair.",
    )
    sp_conf_rem_set.set_defaults(func=remote_set)
    # vtysh configure remote set <id> connection <tid>
    sp_conf_rem_set_sp = sp_conf_rem_set.add_subparsers()
    sp_conf_rem_set_con = sp_conf_rem_set_sp.add_parser(
        "connection",
        parents=[con_shared, con_set, con_mod],
        help="Set operations on tunnels.",
    )
    sp_conf_rem_set_con.set_defaults(func=connection_set)
    # vtysh configure remote unset <id>
    sp_conf_rem_unset = sp_conf_rem_sp.add_parser(
        "unset", parents=[shared], help="Unset operations on remotes."
    )
    # sp_conf_rem_unset.add_argument(
    #     "r_unset",
    #     type=str,
    #     choices=[
    #         "metadata",
    #     ],
    #     action="store",
    #     nargs="?",
    #     help="Properties to unset.",
    # )
    sp_conf_rem_unset.set_defaults(func=remote_unset)
    # vtysh configure remote set <id> connection <tid>
    sp_conf_rem_unset_sp = sp_conf_rem_unset.add_subparsers()
    sp_conf_rem_unset_con = sp_conf_rem_unset_sp.add_parser(
        "connection", parents=[con_shared], help="Unset operations on tunnels."
    )
    sp_conf_rem_unset_con.add_argument(
        "t_unset",
        type=str,
        choices=[
            "metadata",
            "description",
            "ike_version",
            "remote_id",
            "tunnel_ip",
            "routes",
            "traffic_selectors",
        ],
        action="store",
        nargs="+",
        help="Properties to unset.",
    )
    sp_conf_rem_unset_con.set_defaults(func=connection_unset)
    # vtysh configure remote delete <id>
    sp_conf_rem_delete = sp_conf_rem_sp.add_parser(
        "delete", parents=[shared, delete], help="Delete operations on remotes."
    )
    sp_conf_rem_delete.set_defaults(func=remote_delete)
    # vtysh configure remote delete <id> connection <tid>
    sp_conf_rem_delete_sp = sp_conf_rem_delete.add_subparsers()
    sp_conf_rem_delete_con = sp_conf_rem_delete_sp.add_parser(
        "delete", parents=[delete, con_shared], help="Delete operations on tunnels."
    )
    sp_conf_rem_delete_con.set_defaults(func=connection_delete)
    # vtysh configure remote commit <id>
    sp_conf_rem_commit = sp_conf_rem_sp.add_parser(
        "commit", parents=[shared, delete], help="Commit operations on remotes."
    )
    sp_conf_rem_commit.add_argument(
        "--revert", action="store_true", help="Reverts a configuration"
    )
    sp_conf_rem_commit.set_defaults(func=remote_commit)

    # Parse the arguments
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
