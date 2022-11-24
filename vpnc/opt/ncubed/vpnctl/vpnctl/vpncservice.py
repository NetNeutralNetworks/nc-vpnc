#!/usr/bin/env python3

import argparse
from dataclasses import asdict

import typer
import yaml
from deepdiff import DeepDiff

from . import vpncconst, vpncdata

app = typer.Typer()


def service_show(args: argparse.Namespace):
    """
    Show the service configuration
    """
    _ = args

    path = vpncconst.VPNC_C_SERVICE_CONFIG_PATH
    with open(vpncconst.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    svc = vpncdata.Service if mode == "endpoint" else vpncdata.ServiceHub
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = svc(**yaml.safe_load(f))

    output = asdict(service)
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


def service_connection_show(args: argparse.Namespace):
    """
    Show a specific tunnel for an uplink
    """
    path = vpncconst.VPNC_C_SERVICE_CONFIG_PATH
    with open(vpncconst.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = vpncdata.ServiceHub(**yaml.safe_load(f))

    tunnel = service.uplinks.get(int(args.tunnel_id))
    if not tunnel:
        return
    output = {int(args.tunnel_id): asdict(tunnel)}
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


def service_connection_add(args: argparse.Namespace):
    """
    Add tunnels to an uplink
    """
    path = vpncconst.VPNC_C_SERVICE_CONFIG_PATH
    with open(vpncconst.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = vpncdata.ServiceHub(**yaml.safe_load(f))
    # if args.id != remote.id:
    #     print(f"Mismatch between file name '{args.id}' and id '{remote.id}'.")
    #     return

    if service.uplinks.get(int(args.tunnel_id)):
        print(f"Connection '{args.tunnel_id}' already exists'.")
        return

    data = {
        "psk": args.psk,
        "remote_peer_ip": str(args.remote_peer_ip),
        "remote_id": str(args.remote_id) if args.remote_id else None,
    }
    tunnel = vpncdata.Uplink(**data)

    service.uplinks[int(args.tunnel_id)] = tunnel

    output = yaml.safe_dump(asdict(service), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    service_connection_show(args)


def service_set(args: argparse.Namespace):
    """
    Set service properties
    """
    path = vpncconst.VPNC_C_SERVICE_CONFIG_PATH
    with open(vpncconst.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    svc = vpncdata.Service if mode == "endpoint" else vpncdata.ServiceHub

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = svc(**yaml.safe_load(f))

    if args.untrusted_if_name:
        service.untrusted_if_name = args.untrusted_if_name
    if args.untrusted_if_ip:
        service.untrusted_if_ip = str(args.untrusted_if_ip)
    if args.untrusted_if_gw:
        service.untrusted_if_gw = str(args.untrusted_if_gw)
    if args.local_id:
        service.local_id = args.local_id
    if mode == "hub":
        if args.mgmt_prefix:
            service.mgmt_prefix = str(args.mgmt_prefix)
        if args.trusted_transit_prefix:
            service.trusted_transit_prefix = str(args.trusted_transit_prefix)
        if args.customer_tunnel_prefix:
            service.customer_tunnel_prefix = str(args.customer_tunnel_prefix)
        if args.bgp_asn:
            service.bgp.asn = int(args.bgp_asn)
        if args.bgp.router_id:
            service.bgp.router_id = str(args.bgp_router_id)

    # performs the class post_init construction.
    output = yaml.safe_dump(asdict(service), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    service_show(args)


def service_connection_set(args: argparse.Namespace):
    """
    Set tunnel properties for an uplink
    """
    path = vpncconst.VPNC_C_SERVICE_CONFIG_PATH
    with open(vpncconst.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = vpncdata.ServiceHub(**yaml.safe_load(f))

    if not service.uplinks.get(int(args.tunnel_id)):
        print(f"Connection '{args.tunnel_id}' doesn't exists'.")
        return

    tunnel = service.uplinks[int(args.tunnel_id)]

    if args.remote_peer_ip:
        tunnel.remote_peer_ip = args.remote_peer_ip
    if args.remote_id:
        tunnel.remote_id = args.remote_id
    if args.psk:
        tunnel.psk = args.psk

    output = yaml.safe_dump(asdict(service), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    service_connection_show(args)


def service_connection_delete(args: argparse.Namespace):
    """
    Delete a specific tunnel from an uplink
    """
    path = vpncconst.VPNC_C_SERVICE_CONFIG_PATH
    with open(vpncconst.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = vpncdata.ServiceHub(**yaml.safe_load(f))

    if not service.uplinks.get(int(args.tunnel_id)):
        print(f"Connection '{args.tunnel_id}' doesn't exists'.")
        return

    tunnel = service.uplinks.get(int(args.tunnel_id))
    if not tunnel:
        print(f"Tunnel with id '{args.tunnel_id}' doesn't exist.")
        return
    service.uplinks.pop(int(args.tunnel_id))

    output = yaml.safe_dump(asdict(service), explicit_start=True, explicit_end=True)
    print(output)
    if not args.execute:
        print(f"(Simulated) Deleted tunnel '{args.tunnel_id}'")
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Deleted tunnel '{args.tunnel_id}'")


def service_commit(args: argparse.Namespace):
    """
    Commit configuration
    """
    path = vpncconst.VPNC_C_SERVICE_CONFIG_PATH
    path_diff = vpncconst.VPNC_A_SERVICE_CONFIG_PATH

    with open(vpncconst.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    svc = vpncdata.Service if mode == "endpoint" else vpncdata.ServiceHub

    if not path.exists():
        service_yaml = ""
        service = svc()
    else:
        with open(path, "r", encoding="utf-8") as f:
            service_yaml = f.read()
            service = svc(**yaml.safe_load(service_yaml))
        # if args.id != service.id:
        #     print(f"Mismatch between file name '{args.id}' and id '{service.id}'.")
        #     return

    if not path_diff.exists():
        service_diff_yaml = ""
        service_diff = svc()
    else:
        with open(path_diff, "r", encoding="utf-8") as f:
            service_diff_yaml = f.read()
            service_diff = svc(**yaml.safe_load(service_diff_yaml))
        # if args.id != service_diff.id:
        #     print(
        #         f"Mismatch between diff file name '{args.id}' and id '{service_diff.id}'."
        #     )
        #     return

    if service_yaml == service_diff_yaml:
        print("No changes.")
        return

    if args.revert:

        if args.diff:
            diff = DeepDiff(
                asdict(service), asdict(service_diff), verbose_level=2
            ).to_dict()
            print(yaml.safe_dump(diff, explicit_start=True, explicit_end=True))
        if not args.execute:
            print("(Simulated) Revert succeeded.")
            return
        if not path_diff.exists():
            path.unlink(missing_ok=True)
            print("Revert succeeded.")
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(service_diff_yaml)
        print("Revert succeeded.")
        return

    if args.diff:
        diff = DeepDiff(
            asdict(service_diff), asdict(service), verbose_level=2
        ).to_dict()
        print(yaml.safe_dump(diff, explicit_start=True, explicit_end=True))

    if not args.execute:
        print("(Simulated) Commit succeeded.")
        return
    if not path.exists():
        path_diff.unlink(missing_ok=True)
        print("Commit succeeded.")
        return

    with open(path_diff, "w", encoding="utf-8") as f:
        f.write(service_yaml)
    print("Commit succeeded.")


if __name__ == "__main__":
    app()
