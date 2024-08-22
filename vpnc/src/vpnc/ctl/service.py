#!/usr/bin/env python3

import os
import tempfile
from pprint import pprint
from subprocess import call
from typing import Any

import typer
import yaml
from deepdiff import DeepDiff
from pydantic import ValidationError
from typing_extensions import Annotated

from .. import config, models
from . import helpers, service_ni, servicebgp

app = typer.Typer()
app.add_typer(service_ni.app, name="network-instances")
app.add_typer(servicebgp.app, name="bgp")


@app.command()
def show(
    ctx: typer.Context,
    full: Annotated[bool, typer.Option("--full")] = False,
    active: Annotated[bool, typer.Option("--active")] = False,
):
    """
    Show the service configuration
    """
    path = helpers.get_service_config_path(ctx, active)

    service = helpers.get_service_config(ctx, path)

    output = service.model_dump(mode="json")
    if full:
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
    elif service.mode == models.ServiceMode.HUB:
        output["uplink_count"] = len(
            output.get("network_instances", {})
            .get(config.CORE_NI, {})
            .pop("connections")
        )
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
    else:
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def edit(ctx: typer.Context):
    """
    Edit a candidate config file
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    if not path.exists():
        return

    editor = os.environ.get("EDITOR", "vim")

    with open(path, "r", encoding="utf-8") as f:
        service_content = f.read()

    with tempfile.NamedTemporaryFile(suffix=".tmp", mode="w+", encoding="utf-8") as tf:
        tf.write(service_content)
        tf.flush()

        edited_config: models.ServiceEndpoint | models.ServiceHub
        while True:
            try:
                call([editor, tf.name])

                tf.seek(0)
                edited_config_str = tf.read()
                try:
                    edited_config = models.ServiceEndpoint(
                        **yaml.safe_load(edited_config_str)
                    )
                except ValidationError:
                    edited_config = models.ServiceHub(
                        **yaml.safe_load(edited_config_str)
                    )
            except (ValidationError, yaml.YAMLError) as err:
                print(f"Error: {err}")
                retry_or_abort = (
                    input("Invalid input. Do you want to retry or abort? (r/a): ")
                    .strip()
                    .lower()
                )
                if retry_or_abort == "a":
                    print("Aborting configuration edit.")
                    return
                if retry_or_abort == "r":
                    print("Retrying...")
                    continue
                print("Invalid choice. Aborting by default.")
                return
            break

    print("Edited file")

    output = yaml.safe_dump(
        edited_config.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, mode="w", encoding="utf-8") as f:
        f.write(output)

    show(ctx)


# @app.command(name="set")
# def set_(
#     # pylint: disable=unused-argument
#     untrusted_if_name: Optional[str] = None,
#     untrusted_if_ip: Annotated[
#         Optional[IPv4Interface], typer.Option(parser=ip_interface)
#     ] = None,
#     untrusted_if_gw: Annotated[
#         Optional[IPv4Address], typer.Option(parser=ip_address)
#     ] = None,
#     local_id: Annotated[Optional[IPv4Address], typer.Option(parser=ip_address)] = None,
#     prefix_downlink_interface_v4: Annotated[
#         Optional[IPv4Network], typer.Option(parser=IPv4Network)
#     ] = None,
#     prefix_downlink_nat64: Annotated[
#         Optional[IPv6Network], typer.Option(parser=IPv6Network)
#     ] = None,
# ):
#     """
#     Set service properties
#     """
#     all_args = {k: v for k, v in locals().items() if v is not None}

#     path = config.VPNC_C_SERVICE_CONFIG_PATH

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         service = models.ServiceEndpoint(**yaml.safe_load(f))

#     updated_service = service.model_copy(update=all_args)

#     # performs the class post_init construction.
#     output = yaml.safe_dump(
#         updated_service.model_dump(mode="json"), explicit_start=True, explicit_end=True
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)
#     show(active=False)


@app.command()
def commit(
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    revert: bool = False,
    diff: bool = False,
):
    """
    Commit configuration
    """
    path_candidate = config.VPNC_C_SERVICE_CONFIG_PATH
    path_active = config.VPNC_A_SERVICE_CONFIG_PATH

    service_config_candidate: models.ServiceEndpoint | models.ServiceHub
    if not path_candidate.exists():
        return "Candidate configuration file doesn't exist. Generate a blank one with the 'service generate' command."
    with open(path_candidate, "r", encoding="utf-8") as f:
        service_config_candidate_str = f.read()
        try:
            service_config_candidate = models.ServiceEndpoint(
                **yaml.safe_load(service_config_candidate_str)
            )
        except ValidationError:
            service_config_candidate = models.ServiceHub(
                **yaml.safe_load(service_config_candidate_str)
            )

    service_config_active: models.ServiceEndpoint | models.ServiceHub
    if not path_active.exists():
        return "Active configuration file doesn't exist. Generate a blank one with the 'service generate --active' command."
    with open(path_active, "r", encoding="utf-8") as f:
        service_config_active_str = f.read()
        try:
            service_config_active = models.ServiceEndpoint(
                **yaml.safe_load(service_config_active_str)
            )
        except ValidationError:
            service_config_active = models.ServiceHub(
                **yaml.safe_load(service_config_active_str)
            )

    if service_config_candidate_str == service_config_active_str:
        print("No changes.")
        return

    if revert:
        if diff:
            diff_output: dict[str, Any] = DeepDiff(
                service_config_candidate.model_dump(mode="json"),
                service_config_active.model_dump(mode="json"),
                verbose_level=2,
                ignore_type_in_groups=config.DEEPDIFF_IGNORE,
            ).to_dict()
            pprint(diff_output)
        if dry_run:
            print("(Simulated) Revert succeeded.")
            return
        if not path_active.exists():
            path_candidate.unlink(missing_ok=True)
            print("Revert succeeded.")
            return

        with open(path_candidate, "w", encoding="utf-8") as f:
            f.write(service_config_active_str)
        print("Revert succeeded.")
        return

    if diff:
        diff_output: dict[str, Any] = DeepDiff(
            service_config_active.model_dump(mode="json"),
            service_config_candidate.model_dump(mode="json"),
            verbose_level=2,
            ignore_type_in_groups=config.DEEPDIFF_IGNORE,
        ).to_dict()
        pprint(diff_output)

    if dry_run:
        print("(Simulated) Commit succeeded.")
        return

    with open(path_active, "w", encoding="utf-8") as f:
        f.write(service_config_candidate_str)
    print("Commit succeeded.")


if __name__ == "__main__":
    app()
