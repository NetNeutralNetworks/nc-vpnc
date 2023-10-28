#!/usr/bin/env python3

import os
import tempfile
from dataclasses import asdict
from ipaddress import ip_address, ip_interface, IPv4Address, IPv4Network, IPv6Network
from subprocess import call

import typer
import yaml
from deepdiff import DeepDiff

from . import servicecon
from .. import config, models
from .helpers import (
    validate_ip_address,
    validate_ip_network,
)

app = typer.Typer()
app.add_typer(servicecon.app, name="connection")


@app.command()
def show(
    full: bool = False, active: bool = typer.Option(False, "--active/--candidate")
):
    """
    Show the service configuration
    """
    if active:
        path = config.VPNC_A_SERVICE_CONFIG_PATH
    else:
        path = config.VPNC_C_SERVICE_CONFIG_PATH

    with open(config.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    svc = models.Service if mode == "endpoint" else models.ServiceHub
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = svc(**yaml.safe_load(f))

    output = asdict(service)
    if full:
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
    elif mode == "hub":
        output["uplink_count"] = len(output.pop("uplinks"))
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
    else:
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def edit():
    """
    Edit a candidate config file
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH

    with open(config.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    svc = models.Service if mode == "endpoint" else models.ServiceHub
    editor = os.environ.get("EDITOR", "vim")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service_content = f.read()

    with tempfile.NamedTemporaryFile(suffix=".tmp", mode="w+", encoding="utf-8") as tf:
        tf.write(service_content)
        tf.flush()
        call([editor, tf.name])

        tf.seek(0)
        edited_message = tf.read()

    edited_service = svc(**yaml.safe_load(edited_message))
    print("Edited file")

    output = yaml.safe_dump(
        asdict(edited_service), explicit_start=True, explicit_end=True
    )
    with open(path, mode="w", encoding="utf-8") as f:
        f.write(output)

    show(active=False)


@app.command(name="set")
def set_(
    untrusted_if_name: str = typer.Option(None),
    untrusted_if_ip: str = typer.Option(None, callback=validate_ip_network),
    untrusted_if_gw: str = typer.Option(None, callback=validate_ip_address),
    local_id: str = typer.Option(None),
    prefix_uplink: str = typer.Option(None, callback=validate_ip_network),
    prefix_downlink_v4: str = typer.Option(None, callback=validate_ip_network),
    prefix_downlink_v6: str = typer.Option(None, callback=validate_ip_network),
    bgp_asn: str = typer.Option(None, callback=validate_ip_address),
    bgp_router_id: str = typer.Option(None, callback=validate_ip_address),
):
    """
    Set service properties
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    with open(config.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    svc = models.Service if mode == "endpoint" else models.ServiceHub

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        service = svc(**yaml.safe_load(f))

    if untrusted_if_name:
        service.untrusted_if_name = untrusted_if_name
    if untrusted_if_ip:
        service.untrusted_if_ip = ip_interface(untrusted_if_ip)
    if untrusted_if_gw:
        service.untrusted_if_gw = ip_address(untrusted_if_gw)
    if local_id:
        service.local_id = local_id
    if mode == "hub":
        if prefix_uplink:
            service.prefix_uplink = IPv6Network(prefix_uplink)
        if prefix_downlink_v4:
            service.prefix_downlink_v4 = IPv4Network(prefix_downlink_v4)
        if prefix_downlink_v6:
            service.prefix_downlink_v6 = IPv6Network(prefix_downlink_v6)
        if bgp_asn:
            service.bgp.asn = int(bgp_asn)
        if bgp_router_id:
            service.bgp.router_id = IPv4Address(bgp_router_id)

    # performs the class post_init construction.
    output = yaml.safe_dump(asdict(service), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(active=False)


@app.command()
def commit(
    dry_run: bool = typer.Option(False, "--dry-run"),
    revert: bool = False,
    diff: bool = False,
):
    """
    Commit configuration
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    path_diff = config.VPNC_A_SERVICE_CONFIG_PATH

    with open(config.VPNC_A_SERVICE_MODE_PATH, "r", encoding="utf-8") as f:
        mode = yaml.safe_load(f)["mode"]

    svc = models.Service if mode == "endpoint" else models.ServiceHub

    if not path.exists():
        service_yaml = ""
        service = svc()
    else:
        with open(path, "r", encoding="utf-8") as f:
            service_yaml = f.read()
            service = svc(**yaml.safe_load(service_yaml))

    if not path_diff.exists():
        service_diff_yaml = ""
        service_diff = svc()
    else:
        with open(path_diff, "r", encoding="utf-8") as f:
            service_diff_yaml = f.read()
            service_diff = svc(**yaml.safe_load(service_diff_yaml))

    if service_yaml == service_diff_yaml:
        print("No changes.")
        return

    if revert:
        if diff:
            diff_output = DeepDiff(
                asdict(service),
                asdict(service_diff),
                verbose_level=2,
                ignore_type_in_groups=config.DEEPDIFF_IGNORE,
            ).to_dict()
            print(yaml.safe_dump(diff_output, explicit_start=True, explicit_end=True))
        if dry_run:
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

    if diff:
        diff_output = DeepDiff(
            service_diff,
            service,
            verbose_level=2,
            ignore_type_in_groups=config.DEEPDIFF_IGNORE,
        )
        print(diff_output)

    if dry_run:
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
