#!/usr/bin/env python3

import json
import os
import tempfile
from dataclasses import asdict
from enum import Enum
from subprocess import call

import typer
import yaml
from deepdiff import DeepDiff

from . import remotecon
from .. import config, models

app = typer.Typer()
app.add_typer(remotecon.app, name="connection")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, id_: str = typer.Argument(None)):
    """
    Edit settings for remote connections
    """
    _ = id_
    ctx.obj = ctx.params
    if ctx.invoked_subcommand is None and id_ is not None:
        ctx.fail("Missing command.")
    if ctx.invoked_subcommand is None:
        list_()


# @app.command(name="list")
def list_():
    """
    List all remotes
    """

    print(f"{'id':<6} name\n{'-'*6} {'-'*4}")
    for i in config.VPNC_C_REMOTE_CONFIG_DIR.glob("*.yaml"):
        file_name = i.stem
        with open(i, "r", encoding="utf-8") as f:
            remote = models.Remote(**yaml.safe_load(f))
        if file_name != remote.id:
            print(f"Mismatch between file name '{file_name}' and id '{remote.id}'.")
        elif file_name == remote.id:
            print(f"{remote.id:<6} {remote.name}")


@app.command()
def show(
    ctx: typer.Context,
    full: bool = False,
    active: bool = typer.Option(False, "--active/--candidate"),
):
    """
    Show a remote
    """
    id_: str = ctx.obj["id_"]
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

    output = asdict(remote)
    if full:
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
    else:
        output["tunnel_count"] = len(output.pop("tunnels"))
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def edit(ctx: typer.Context):
    """
    Edit a candidate config file
    """
    id_: str = ctx.obj["id_"]
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    editor = os.environ.get("EDITOR", "vim")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote_content = f.read()
        remote = models.Remote(**yaml.safe_load(remote_content))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    with tempfile.NamedTemporaryFile(suffix=".tmp", mode="w+", encoding="utf-8") as tf:
        tf.write(remote_content)
        tf.flush()
        call([editor, tf.name])

        tf.seek(0)
        edited_message = tf.read()

    edited_remote = models.Remote(**yaml.safe_load(edited_message))
    print("Edited file")
    print(edited_message)

    output = yaml.safe_dump(
        asdict(edited_remote), explicit_start=True, explicit_end=True
    )
    with open(path, mode="w", encoding="utf-8") as f:
        f.write(output)


@app.command()
def add(ctx: typer.Context, name: str, metadata: str = "{}"):
    """
    Add a remote
    """
    id_: str = ctx.obj["id_"]
    metadict: dict = json.loads(metadata)
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")
    if path.exists():
        print(f"Remote '{id_}' already exists.")
        return

    data = {"id": id_, "name": name, "metadata": metadict, "tunnels": {}}
    remote = models.Remote(**data)

    output = yaml.safe_dump(asdict(remote), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(ctx, active=False)


@app.command(name="set")
def set_(ctx: typer.Context, name: str = "", metadata: str = "{}"):
    """
    Set a remote
    """
    id_: str = ctx.obj["id_"]
    metadict: dict = json.loads(metadata)
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")

    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    if name:
        remote.name = name
    if metadict:
        remote.metadata = metadict

    output = yaml.safe_dump(asdict(remote), explicit_start=True, explicit_end=True)
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(ctx, active=False)


class RemoteUnset(str, Enum):
    """Items that can be unset from a remote."""

    # NAME: str = "name"
    METADATA = "metadata"


@app.command()
def unset(ctx: typer.Context, metadata: list[str] = typer.Option([])):
    """
    Unset a remote
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

    for i in metadata:
        remote.metadata.pop(i)

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
    Delete a remote side
    """
    id_: str = ctx.obj["id_"]
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")
    if not path.exists():
        print(f"Remote '{id_}' doesn't exist.")
        return
    with open(path, "r", encoding="utf-8") as f:
        remote = models.Remote(**yaml.safe_load(f))
    if id_ != remote.id:
        print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
        return

    output = yaml.safe_dump(asdict(remote), explicit_start=True, explicit_end=True)
    print(output)
    if dry_run:
        print(f"(Simulated) Deleted remote '{id_}'")
    elif force:
        path.unlink()
        print(f"Deleted remote '{id_}'")
    elif delete_ := typer.confirm(
        f"Are you sure you want to delete remote '{id_}'", abort=True
    ):
        if delete_:
            path.unlink()
            print(f"Deleted remote '{id_}'")


@app.command()
def commit(
    ctx: typer.Context,
    dry_run: bool = typer.Option(False, "--dry-run"),
    revert: bool = False,
    diff: bool = False,
):
    """
    Commit configuration
    """
    id_: str = ctx.obj["id_"]
    path = config.VPNC_C_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")
    path_diff = config.VPNC_A_REMOTE_CONFIG_DIR.joinpath(f"{id_}.yaml")
    if not path.exists():
        remote_yaml = ""
        remote = models.Remote()
    else:
        with open(path, "r", encoding="utf-8") as f:
            remote_yaml = f.read()
            remote = models.Remote(**yaml.safe_load(remote_yaml))
        if id_ != remote.id:
            print(f"Mismatch between file name '{id_}' and id '{remote.id}'.")
            return

    if not path_diff.exists():
        remote_diff_yaml = ""
        remote_diff = models.Remote()
    else:
        with open(path_diff, "r", encoding="utf-8") as f:
            remote_diff_yaml = f.read()
            remote_diff = models.Remote(**yaml.safe_load(remote_diff_yaml))
        if id_ != remote_diff.id:
            print(f"Mismatch between diff file name '{id_}' and id '{remote_diff.id}'.")
            return

    if remote_yaml == remote_diff_yaml:
        print("No changes.")
        return

    if revert:
        if diff:
            diff_output = DeepDiff(
                asdict(remote),
                asdict(remote_diff),
                verbose_level=1,
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
            f.write(remote_diff_yaml)
        print("Revert succeeded.")
        return

    if diff:
        diff_output = DeepDiff(
            asdict(remote_diff),
            asdict(remote),
            verbose_level=2,
            ignore_type_in_groups=config.DEEPDIFF_IGNORE,
        ).to_dict()
        print(yaml.safe_dump(diff_output, explicit_start=True, explicit_end=True))

    if dry_run:
        print("(Simulated) Commit succeeded.")
        return
    if not path.exists():
        path_diff.unlink(missing_ok=True)
        print("Commit succeeded.")
        return

    with open(path_diff, "w", encoding="utf-8") as f:
        f.write(remote_yaml)
    print("Commit succeeded.")


if __name__ == "__main__":
    app()
