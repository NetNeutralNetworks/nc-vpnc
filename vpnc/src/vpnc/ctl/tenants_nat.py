"""Manage tenant network instances."""

from __future__ import annotations

from typing import Any, Generator, Optional

import tabulate
import typer
from rich import print
from typing_extensions import Annotated

import vpnc.models.network_instance
import vpnc.models.tenant
import vpnc.services.configuration

from . import helpers, tenant_ni_con

app = typer.Typer()
app.add_typer(tenant_ni_con.app, name="connections")

IPAddress = Any
IPInterface = Any
IPNetwork = Any


def complete_network_instance(
    ctx: typer.Context,
) -> Generator[tuple[str, str], Any, None]:
    """Autocompletes network-instance identifiers."""
    # tenants.main
    assert ctx.parent is not None

    active: bool = ctx.parent.params.get("active", False)
    tenant_id: str = ctx.parent.params["tenant_id"]

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    for network_instance in tenant.network_instances.values():
        yield (network_instance.id, network_instance.metadata.get("description", ""))


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    instance_id: Annotated[
        Optional[str],  # noqa: UP007
        typer.Argument(autocompletion=complete_network_instance),
    ] = None,
    active: Annotated[bool, typer.Option("--active")] = False,  # noqa: FBT002
) -> None:
    """Entrypoint for tenant network-instance commands."""
    _ = active

    assert ctx.parent is not None

    tenant_id = ctx.parent.params["tenant_id"]

    if tenant_id == "DEFAULT":
        print("No NAT mappings: Tenant is 'DEFAULT'")
        return

    path = helpers.get_config_path(ctx, active)

    tenant = helpers.get_tenant_config(ctx, tenant_id, path)

    if isinstance(tenant, vpnc.models.tenant.ServiceEndpoint):
        print("No NAT mappings: VPNC running in 'endpoint' mode.")
        return

    if instance_id:
        list_instances = [instance_id]
    else:
        list_instances = [x[0] for x in complete_network_instance(ctx)]

    output: list[dict[str, Any]] = []
    for instance in list_instances:
        if (
            nat64_mapping
            := vpnc.services.configuration.get_network_instance_nat64_mappings_state(
                instance,
            )
        ):
            nat64_local, nat64_remote = nat64_mapping
            output.append(
                {
                    "tenant": ctx.parent.params["tenant_id"],
                    "network-instance": instance,
                    "type": "NAT64",
                    "local": nat64_local,
                    "remote": nat64_remote,
                },
            )
        for (
            mapping
        ) in vpnc.services.configuration.get_network_instance_nptv6_mappings_state(
            instance,
        ):
            nptv6_local, nptv6_remote = mapping
            output.append(
                {
                    "tenant": ctx.parent.params["tenant_id"],
                    "network-instance": instance,
                    "type": "NPTv6",
                    "local": nptv6_local,
                    "remote": nptv6_remote,
                },
            )
    print(tabulate.tabulate(output, headers="keys"))


if __name__ == "__main__":
    app()
