#!/usr/bin/env python3

import os
import tempfile
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Network,
    ip_address,
    ip_interface,
)
from subprocess import call
from typing import Optional

import typer
import yaml
from deepdiff import DeepDiff
from typing_extensions import Annotated

from .. import config, models
from . import servicebgp, serviceuplink

app = typer.Typer()
app.add_typer(serviceuplink.app, name="uplink")
app.add_typer(servicebgp.app, name="bgp")


@app.command()
def show(
    full: Annotated[bool, typer.Option("--full/--summary")] = False,
    active: Annotated[bool, typer.Option("--active/--candidate")] = False,
):
    """
    Show the service configuration
    """
    if active:
        path = config.VPNC_A_SERVICE_CONFIG_PATH
    else:
        path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    output = service.model_dump(mode="json")
    if full:
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
    elif service.mode.name == "HUB":
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

    edited_service = models.Service(**yaml.safe_load(edited_message))
    print("Edited file")

    output = yaml.safe_dump(
        edited_service.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, mode="w", encoding="utf-8") as f:
        f.write(output)

    show(active=False)


@app.command(name="set")
def set_(
    # pylint: disable=unused-argument
    untrusted_if_name: Optional[str] = None,
    untrusted_if_ip: Annotated[
        Optional[IPv4Interface], typer.Option(parser=ip_interface)
    ] = None,
    untrusted_if_gw: Annotated[
        Optional[IPv4Address], typer.Option(parser=ip_address)
    ] = None,
    local_id: Annotated[Optional[IPv4Address], typer.Option(parser=ip_address)] = None,
    prefix_uplink: Annotated[
        Optional[IPv6Network], typer.Option(parser=IPv6Network)
    ] = None,
    prefix_downlink_v4: Annotated[
        Optional[IPv4Network], typer.Option(parser=IPv4Network)
    ] = None,
    prefix_downlink_v6: Annotated[
        Optional[IPv6Network], typer.Option(parser=IPv6Network)
    ] = None,
):
    """
    Set service properties
    """
    all_args = {k: v for k, v in locals().items() if v is not None}

    path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    updated_service = service.model_copy(update=all_args)

    # performs the class post_init construction.
    output = yaml.safe_dump(
        updated_service.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(active=False)


@app.command()
def commit(
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    revert: bool = False,
    diff: bool = False,
):
    """
    Commit configuration
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    path_diff = config.VPNC_A_SERVICE_CONFIG_PATH

    if not path.exists():
        return "Candidate configuration file doesn't exist. Generate a blank one with the 'service generate' command."
    with open(path, "r", encoding="utf-8") as f:
        service_yaml = f.read()
        service = models.Service(**yaml.safe_load(service_yaml))

    if not path_diff.exists():
        return "Active configuration file doesn't exist. Generate a blank one with the 'service generate --active' command."
    with open(path_diff, "r", encoding="utf-8") as f:
        service_diff_yaml = f.read()
        service_diff = models.Service(**yaml.safe_load(service_diff_yaml))

    if service_yaml == service_diff_yaml:
        print("No changes.")
        return

    if revert:
        if diff:
            diff_output = DeepDiff(
                service.model_dump(mode="json"),
                service_diff.model_dump(mode="json"),
                verbose_level=2,
                ignore_type_in_groups=config.DEEPDIFF_IGNORE,
            ).to_dict()
            print(yaml.safe_dump(diff_output, explicit_start=True, explicit_end=True))
        if dry_run:
            print("(Simulated) Revert succeeded.")
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(service_diff_yaml)
        print("Revert succeeded.")
        return

    if diff:
        diff_output = DeepDiff(
            service_diff.model_dump(mode="json"),
            service.model_dump(mode="json"),
            verbose_level=2,
            ignore_type_in_groups=config.DEEPDIFF_IGNORE,
        )
        print(diff_output)

    if dry_run:
        print("(Simulated) Commit succeeded.")
        return

    with open(path_diff, "w", encoding="utf-8") as f:
        f.write(service_yaml)
    print("Commit succeeded.")


if __name__ == "__main__":
    app()
