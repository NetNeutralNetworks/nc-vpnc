"""Manage tenants."""

import json
import os
import tempfile
from subprocess import call
from typing import Any, Generator, Optional

import tabulate
import typer
import yaml
from deepdiff import DeepDiff
from pydantic import ValidationError
from rich import print
from typing_extensions import Annotated

from vpnc import config, models
from vpnc.ctl import helpers, tenants_nat, tenants_ni

app = typer.Typer()
app.add_typer(tenants_ni.app, name="network-instances")
app.add_typer(tenants_nat.app, name="nat")


def complete_tenant_id(
    ctx: typer.Context,
) -> Generator[tuple[str, str], Any, None]:
    """Autocomplete tenant identifiers."""
    assert ctx.parent is not None

    active: bool = ctx.parent.params.get("active", False)

    path = helpers.get_config_path(ctx, active)

    for i in path.glob("*.yaml"):
        file_name = i.stem
        tenant = helpers.get_tenant_config(ctx, file_name, path)
        yield (tenant.id, tenant.metadata.get("description", ""))


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    tenant_id: Annotated[
        Optional[str],  # noqa: FA100
        typer.Argument(autocompletion=complete_tenant_id),
    ] = None,
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Entrypoint for tenant commands."""
    _ = active
    if ctx.invoked_subcommand is None and tenant_id is not None and tenant_id != "list":
        ctx.fail("Missing command.")
    if ctx.invoked_subcommand:
        return
    list_(ctx)


# @app.command(name="list")
def list_(
    ctx: typer.Context,
) -> None:
    """List all tenants."""
    active: bool = ctx.params.get("active", False)

    path = helpers.get_config_path(ctx, active)

    output: list[dict[str, Any]] = []
    for i in path.glob("*.yaml"):
        file_name = i.stem
        tenant = helpers.get_tenant_config(ctx, file_name, path)
        output.append(
            {
                "tenant": tenant.id,
                "tenant-name": tenant.name,
                "description": tenant.metadata.get("description", ""),
            },
        )

    print(tabulate.tabulate(output, headers="keys"))


@app.command()
def show(
    ctx: typer.Context,
    full: Annotated[bool, typer.Option("--full")] = False,  # noqa: FBT002
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Show a tenant configuration."""
    assert ctx.parent is not None

    tenant_id: str = ctx.parent.params["tenant_id"]

    path = helpers.get_config_path(ctx, active)
    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    output = tenant.model_dump(mode="json")
    if full:
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))
    else:
        output["network_instance_count"] = len(output.pop("network_instances"))
        print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def summary(
    ctx: typer.Context,
) -> None:
    """Show a tenant's connectivity status."""
    assert ctx.parent is not None

    tenant_id: str = ctx.parent.params["tenant_id"]

    path = helpers.get_config_path(ctx, active=True)
    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    output: list[dict[str, Any]] = []
    for network_instance in tenant.network_instances.values():
        for connection in tenant.network_instances[
            network_instance.id
        ].connections.values():
            output.append(connection.status_summary(network_instance))

    print(tabulate.tabulate(output, headers="keys"))


@app.command()
def edit(ctx: typer.Context) -> None:
    """Edit a candidate config file."""
    assert ctx.parent is not None

    editor = os.environ.get("EDITOR", "vim")
    tenant_id: str = ctx.parent.params["tenant_id"]

    path = helpers.get_config_path(ctx, active=False)
    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    with tempfile.NamedTemporaryFile(suffix=".tmp", mode="w+", encoding="utf-8") as tf:
        tf.write(
            yaml.safe_dump(
                tenant.model_dump(mode="json"),
                explicit_start=True,
                explicit_end=True,
            ),
        )
        tf.flush()
        while True:
            try:
                call([editor, tf.name])  # noqa: S603
                tf.seek(0)

                edited_config_str = tf.read()
                if tenant_id == config.DEFAULT_TENANT:
                    edited_config = models.Service(
                        config=yaml.safe_load(edited_config_str),
                    ).config
                else:
                    edited_config = models.Tenant(**yaml.safe_load(edited_config_str))
                if tenant_id != edited_config.id:
                    msg = f"Mismatch between file name '{tenant_id}' and id '{edited_config.id}'"
                    raise ValueError(
                        msg,
                    )
            except (ValidationError, ValueError, yaml.YAMLError) as err:
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
        edited_config.model_dump(mode="json"),
        explicit_start=True,
        explicit_end=True,
    )
    with path.joinpath(f"{tenant_id}.yaml").open(mode="w", encoding="utf-8") as f:
        f.write(output)

    show(ctx)


@app.command()
def add(
    ctx: typer.Context,
    # pylint: disable=unused-argument
    name: Annotated[str, typer.Option()],
    metadata: Annotated[
        Optional[dict[str, Any]],
        typer.Option(parser=json.loads),
    ] = None,
) -> None:
    """Add a tenant configuration."""
    assert ctx.parent is not None

    all_args = {k: v for k, v in locals().items() if v}
    all_args["version"] = "0.1.0"
    all_args.pop("ctx")

    tenant_id: str = ctx.parent.params["tenant_id"]
    if tenant_id == config.DEFAULT_TENANT:
        print(f"Tenant '{tenant_id}' already exists.")
        return
    path = helpers.get_config_path(ctx, False)
    tenant_path = path.joinpath(f"{tenant_id}.yaml")
    if tenant_path.exists():
        print(f"Tenant '{tenant_id}' already exists.")
        return

    all_args.update({"id": tenant_id})
    tenant = models.Tenant(**all_args)

    output = yaml.safe_dump(
        tenant.model_dump(mode="json"),
        explicit_start=True,
        explicit_end=True,
    )
    with path.open("w+", encoding="utf-8") as f:
        f.write(output)

    show(ctx)


# @app.command(name="set")
# def set_(
#     ctx: typer.Context,
#     # pylint: disable=unused-argument
#     name: Annotated[Optional[str], typer.Option()] = None,
#     metadata: Annotated[Optional[dict], typer.Option(parser=json.loads)] = None,
# ):
#     """
#     Set a remote
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     all_metadata: list[str] = all_args.pop("metadata", {})
#     tenant_id: str = ctx.params["tenant_id"]
#     path = config.VPNC_C_TENANT_CONFIG_DIR.joinpath(f"{tenant_id}.yaml")

#     if not path.exists():
#         return

#     with open(path, "r", encoding="utf-8") as f:
#         remote = models.Tenant(**yaml.safe_load(f))
#     if tenant_id != remote.id:
#         print(f"Mismatch between file name '{tenant_id}' and id '{remote.id}'.")
#         return

#     updated_remote = remote.model_copy(update=all_args)
#     updated_remote.metadata.update(all_metadata)

#     output = yaml.safe_dump(
#         updated_remote.model_dump(mode="json"), explicit_start=True, explicit_end=True
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)

#     show(ctx)


# class RemoteUnset(str, Enum):
#     """Items that can be unset from a remote."""

#     # NAME: str = "name"
#     METADATA = "metadata"


# @app.command()
# def unset(
#     ctx: typer.Context, metadata: Annotated[Optional[list[str]], typer.Option()] = None
# ):
#     """
#     Unset a remote
#     """
#     all_args = {k: v for k, v in locals().items() if v}
#     all_args.pop("ctx")
#     all_metadata: list[str] = all_args.pop("metadata", [])

#     tenant_id: str = ctx.params["tenant_id"]
#     path = config.VPNC_C_TENANT_CONFIG_DIR.joinpath(f"{tenant_id}.yaml")

#     if not path.exists():
#         return
#     with open(path, "r", encoding="utf-8") as f:
#         remote = models.Tenant(**yaml.safe_load(f))
#     if tenant_id != remote.id:
#         print(f"Mismatch between file name '{tenant_id}' and id '{remote.id}'.")
#         return

#     remote_dict = remote.model_dump(mode="json")

#     for k in all_args:
#         remote_dict.pop(k)
#     for i in all_metadata:
#         remote_dict["metadata"].pop(i, None)

#     updated_remote = models.Tenant(**remote_dict)

#     output = yaml.safe_dump(
#         updated_remote.model_dump(mode="json"), explicit_start=True, explicit_end=True
#     )
#     with open(path, "w+", encoding="utf-8") as f:
#         f.write(output)

#     show(ctx)


@app.command()
def delete(
    ctx: typer.Context,
    dry_run: bool = typer.Option(False, "--dry-run"),  # noqa: FBT001, FBT003
    force: bool = typer.Option(False, "--force"),  # noqa: FBT001, FBT003
) -> None:
    """Delete a tenant configuration."""
    assert ctx.parent is not None

    tenant_id: str = ctx.parent.params["tenant_id"]

    if tenant_id == config.DEFAULT_TENANT:
        print(f"Tenant '{tenant_id}' cannot be removed.")
        return
    path = config.VPNC_C_CONFIG_DIR.joinpath(f"{tenant_id}.yaml")
    if not path.exists():
        print(f"Tenant '{tenant_id}' doesn't exist.")
        return
    with path.open(encoding="utf-8") as f:
        tenant = models.Tenant(**yaml.safe_load(f))
    if tenant_id != tenant.id:
        print(f"Mismatch between file name '{tenant_id}' and id '{tenant.id}'.")
        return

    output = yaml.safe_dump(
        tenant.model_dump(mode="json"),
        explicit_start=True,
        explicit_end=True,
    )
    print(output)
    if dry_run:
        print(f"(Simulated) Deleted tenant '{tenant_id}'")
    elif force or typer.confirm(
        f"Are you sure you want to delete tenant '{tenant_id}'",
        abort=True,
    ):
        path.unlink()
        print(f"Deleted tenant '{tenant_id}'")


@app.command()
def commit(
    ctx: typer.Context,
    dry_run: bool = typer.Option(False, "--dry-run"),  # noqa: FBT001, FBT003
    revert: bool = False,  # noqa: FBT001, FBT002
    diff: bool = False,  # noqa: FBT001, FBT002
) -> None:
    """Commit a tenant configuration."""
    assert ctx.parent is not None

    tenant_id: str = ctx.parent.params["tenant_id"]

    path_candidate = helpers.get_config_path(ctx, active=False)
    path_active = helpers.get_config_path(ctx, active=True)

    path_candidate_tenant = path_candidate.joinpath(f"{tenant_id}.yaml")
    path_active_tenant = path_active.joinpath(f"{tenant_id}.yaml")
    if not path_candidate_tenant.exists():
        tenant_config_candidate = models.Tenant(id=tenant_id, name="", version="0.1.0")
    else:
        tenant_config_candidate = helpers.get_tenant_config(
            ctx,
            tenant_id,
            path_candidate,
        )

    if not path_active_tenant.exists():
        tenant_config_active = models.Tenant(id=tenant_id, name="", version="0.1.0")
    else:
        tenant_config_active = helpers.get_tenant_config(ctx, tenant_id, path_active)

    if tenant_config_candidate == tenant_config_active:
        print("No changes.")
        return

    if revert:
        if diff:
            diff_output: dict[str, Any] = DeepDiff(
                tenant_config_candidate.model_dump(mode="json"),
                tenant_config_active.model_dump(mode="json"),
                verbose_level=1,
                ignore_type_in_groups=config.DEEPDIFF_IGNORE,
            ).to_dict()
            print(diff_output)
        if dry_run:
            print("(Simulated) Revert succeeded.")
            return
        if not path_active_tenant.exists():
            path_candidate_tenant.unlink(missing_ok=True)
            print("Revert succeeded.")
            return

        with path_candidate_tenant.open("w", encoding="utf-8") as f:
            f.write(
                yaml.dump(
                    tenant_config_active.model_dump(mode="json"),
                    explicit_start=True,
                    explicit_end=True,
                ),
            )
        print("Revert succeeded.")
        return

    if diff:
        diff_output: dict[str, Any] = DeepDiff(
            tenant_config_active.model_dump(mode="json"),
            tenant_config_candidate.model_dump(mode="json"),
            verbose_level=2,
            ignore_type_in_groups=config.DEEPDIFF_IGNORE,
        ).to_dict()
        print(diff_output)

    if dry_run:
        print("(Simulated) Commit succeeded.")
        return
    if not path_candidate_tenant.exists():
        path_active_tenant.unlink(missing_ok=True)
        print("Commit succeeded.")
        return

    with path_active_tenant.open("w", encoding="utf-8") as f:
        f.write(
            yaml.dump(
                tenant_config_candidate.model_dump(mode="json"),
                explicit_start=True,
                explicit_end=True,
            ),
        )
    print("Commit succeeded.")


if __name__ == "__main__":
    app()
