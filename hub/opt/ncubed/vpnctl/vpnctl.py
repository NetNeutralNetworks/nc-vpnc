#! /bin/python3

import argparse
import difflib
import glob
import logging
import pathlib
import sys
from typing import Union, Any

import jinja2
import yaml

logging.basicConfig()
logger = logging.getLogger()

VPN_CONFIG_PATH = pathlib.Path("/etc/swanctl/conf.d")
# Load the configuration
VPNC_CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpnc/config.yaml")
logger.info("Loading configuration from '%s'.", VPNC_CONFIG_PATH)
if not VPNC_CONFIG_PATH.exists():
    logger.critical("Configuration not found at '%s'.", VPNC_CONFIG_PATH)
    sys.exit(1)
with open(VPNC_CONFIG_PATH, "r", encoding="utf-8") as h:
    try:
        VPNC_CONFIG = yaml.safe_load(h)
    except yaml.YAMLError:
        logger.critical(
            "Configuration is not valid '%s'.", VPNC_CONFIG_PATH, exc_info=True
        )
        sys.exit(1)
VPNCTL_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnctl")
VPNCTL_TEMPLATE_DIR = pathlib.Path(__file__).parent.joinpath("templates")

VPNCTL_J2_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(VPNCTL_TEMPLATE_DIR))


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
    # Read the configuration files for vpnctl (not swanctl) to check if there is any configuration.
    # It renders all configurations for a customer or all configured configurations.
    template = VPNCTL_J2_ENV.get_template("customer.conf.j2")

    config_file = VPNCTL_CONFIG_DIR.joinpath(f"{remote}.yaml")

    if not config_file.exists():
        logger.warning("Config '%s' not found", remote)
        return

    with open(config_file, "r", encoding="utf-8") as handle:
        vpnctl_config = yaml.safe_load(handle)

    for tun_id, config in vpnctl_config["tunnels"].items():
        tunnel_config = calculate_vpn(remote, tun_id, config)
        tunnel_render = template.render(connections=[tunnel_config])

        # Save the output to file or print it (or display a diff)
        out_path = VPN_CONFIG_PATH.joinpath(f"{remote}-{tun_id:03}.conf")
        if diff:
            with open(out_path, "r", encoding="utf-8") as file:
                diff_file = file.read()
            for i in difflib.unified_diff(
                diff_file.splitlines(), tunnel_render.splitlines()
            ):
                print(i)
        else:
            print(tunnel_render)
        if commit:
            with open(out_path, "w+", encoding="utf-8") as file:
                file.write(tunnel_render)

    if purge:
        delete_vpn_renders(vpnctl_config)


def delete_vpn_renders(vpn_config: dict[str, Union[str, dict[str, Any]]]):
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


def calculate_vpn(remote, tun_id, config):
    """Calculate variables to render for a tunnel."""
    tunnel_config = {
        "remote": remote,
        "t_id": f"{tun_id:03}",
        "psk": config["psk"],
        "remote_peer_ip": config["remote_peer_ip"],
    }

    tunnel_config["xfrm_id"] = f"{int(remote[1:]) * 1000 + int(tun_id)}"
    tunnel_config["ike_proposal"] = config["ike_proposal"]
    tunnel_config["ipsec_proposal"] = config["ipsec_proposal"]

    # tunnel_config["xfrm_id"] = f"{int(remote[1:]) * 1000 + int(tun_id)}"
    if config.get("local_id"):
        tunnel_config["local_id"] = config["local_id"]
    else:
        tunnel_config["local_id"] = VPNC_CONFIG["local_id"]
    if config.get("remote_id"):
        tunnel_config["remote_id"] = config["remote_id"]
    else:
        tunnel_config["remote_id"] = config["remote_peer_ip"]

    # stuff the variables into a dict to pass to jinja
    if config.get("ike_version") and config.get("ike_version") != 2:
        tunnel_config["ike_version"] = config["ike_version"]
    if config.get("traffic_selectors"):
        ts_local = ",".join(config["traffic_selectors"]["local"])
        ts_remote = ",".join(config["traffic_selectors"]["remote"])
        tunnel_config["ts"] = {"local": ts_local, "remote": ts_remote}

    return tunnel_config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage VPNC configuration")
    subparser = parser.add_subparsers(help="Sub command help")

    parser_render = subparser.add_parser(
        "render", help="Render the configuration for vpnctl"
    )
    parser_render.set_defaults(func=render_vpn)
    parser_render.add_argument(
        "remote", action="store", help="Name of the remote side."
    )
    parser_render.add_argument(
        "--commit",
        action="store_true",
        help="Writes the configuration to vpnc.",
    )
    parser_render.add_argument(
        "--purge",
        action="store_true",
        help="Removes VPN connections from vpnc not defined in vpnctl configuration.",
    )
    parser_render.add_argument(
        "--diff",
        action="store_true",
        help="Displays the difference between the current and desired vpnc configurations.",
    )

    parser_render = subparser.add_parser(
        "new", help="Outputs an example vpnctl yaml configuration file."
    )
    parser_render.set_defaults(func=new_vpn)

    args = parser.parse_args()
    args.func(args)
