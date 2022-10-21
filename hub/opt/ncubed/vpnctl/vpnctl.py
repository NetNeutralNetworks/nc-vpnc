#! /bin/python3

import argparse
import glob
import pathlib
import sys
from typing import Union, Any

import jinja2
import yaml

VPN_CONFIG_PATH = pathlib.Path("/etc/swanctl/conf.d")
# Load the configuration
VPNC_CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpnc/config.yaml")
# logger.info("Loading configuration from '%s'.", VPNC_CONFIG_PATH)
if not VPNC_CONFIG_PATH.exists():
    # logger.critical("Configuration not found at '%s'.", VPNC_CONFIG_PATH)
    sys.exit(1)
with open(VPNC_CONFIG_PATH, encoding="utf-8") as h:
    _vpnc_config = yaml.safe_load(h)
VPNCTL_CONFIG_DIR = pathlib.Path("/opt/ncubed/config/vpnctl")
VPNCTL_TEMPLATE_DIR = pathlib.Path(__file__).parent.joinpath("templates")

J2_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(VPNCTL_TEMPLATE_DIR))


def render_vpn(customer_id: str, save: bool = False, purge: bool = False):
    """
    placeholder
    """
    # Read the configuration files for vpnctl (not swanctl) to check if there is any configuration.
    # It renders all configurations for a customer or all configured configurations.
    template = J2_ENV.get_template("customer.conf.j2")

    config_file = VPNCTL_CONFIG_DIR.joinpath(f"{customer_id}.yaml")

    if not config_file.exists():
        # logger.warning("Config '%s' not found", config_name)
        return
    # if not config_files and config_all:
    #     # logger.warning("No configurations found")
    #     return

    with open(config_file, "r", encoding="utf-8") as handle:
        vpnctl_config = yaml.safe_load(handle)

    for tun_id, config in vpnctl_config["tunnels"].items():
        tunnel_config = calculate_vpn(customer_id, tun_id, config)
        tunnel_render = template.render(connections=[tunnel_config])

        # Save the output to file or print it
        if save:
            out_path = VPN_CONFIG_PATH.joinpath(f"{customer_id}-{tun_id:03}.conf")
            with open(out_path, "w+", encoding=" utf-8") as file:
                file.write(tunnel_render)
        else:
            print(tunnel_render)

    if purge:
        delete_vpn_renders(vpnctl_config)


def delete_vpn_renders(vpn_config: dict[str, Union[str, dict[str, Any]]]):
    """Deletes rendered swanctl config if not in vpnctl config."""

    customer_id = str(vpn_config["customer_id"])

    files = glob.glob(str(VPN_CONFIG_PATH.joinpath(f"{customer_id}-*.conf")))
    diff_conn: set[str] = {pathlib.Path(x).stem for x in files}

    ref_conn: set[str] = {f"{customer_id}-{x:03}" for x in vpn_config["tunnels"].keys()}

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


def calculate_vpn(customer_id, tun_id, config):
    """Calculate variables to render for a tunnel."""
    tunnel_config = {
        "cust_id": customer_id,
        "t_id": f"{tun_id:03}",
        "psk": config["psk"],
        "remote_peer_ip": config["remote_peer_ip"],
        "ike_proposal": config["ike_proposal"],
        "ipsec_proposal": config["ipsec_proposal"],
    }

    tunnel_config["xfrm_id"] = f"{int(customer_id[1:]) * 1000 + int(tun_id)}"
    if config.get("local_id"):
        tunnel_config["local_id"] = config["local_id"]
    else:
        tunnel_config["local_id"] = _vpnc_config["local_id"]
    if config.get("remote_id"):
        tunnel_config["remote_id"] = config["remote_id"]
    else:
        tunnel_config["remote_id"] = config["remote_peer_ip"]

    # stuff the variables into a dict to pass to jinja
    if config.get("ike_version"):
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
        "render", help="Render the configuration for strongswan"
    )
    parser_render.set_defaults(func=render_vpn)
    parser_render.add_argument("customer_id", action="store")
    parser_render.add_argument("--save", action="store_true")
    parser_render.add_argument("--purge", action="store_true")
    # parser_stop = subparser.add_parser("stop", help="Stops the VPN service")
    # parser_stop.set_defaults(func=main_stop)
    args = parser.parse_args(["render", "c0001", "--purge"])
    args.func(args.customer_id, args.save, args.purge)
