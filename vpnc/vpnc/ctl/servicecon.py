#!/usr/bin/env python3

import argparse
from dataclasses import asdict

import typer
import yaml
from deepdiff import DeepDiff

from .. import config, models

app = typer.Typer()


def service_connection_show(args: argparse.Namespace):
    """
    Show a specific tunnel for an uplink
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(config.VPNC_A_SERVICE_CONFIG_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    tunnel = service.uplinks.get(int(args.tunnel_id))
    if not tunnel:
        return
    output = {int(args.tunnel_id): asdict(tunnel)}
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


def service_connection_add(args: argparse.Namespace):
    """
    Add tunnels to an uplink
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(config.VPNC_A_SERVICE_CONFIG_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))
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
    tunnel = models.Uplink(**data)

    service.uplinks[int(args.tunnel_id)] = tunnel

    output = yaml.safe_dump(asdict(service), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    service_connection_show(args)


def service_connection_set(args: argparse.Namespace):
    """
    Set tunnel properties for an uplink
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(config.VPNC_A_SERVICE_CONFIG_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

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
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(config.VPNC_A_SERVICE_CONFIG_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    if mode != "hub":
        print("Service is not running in hub mode")
        return

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

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


if __name__ == "__main__":
    app()
