"""Shared functions used throughout the vpnctl CLI tool."""

from __future__ import annotations

from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

import vpnc.models.tenant
from vpnc import config

if TYPE_CHECKING:
    import pathlib

    import typer


def ip_addr(x: str) -> IPv4Address | IPv6Address | None:
    """Validate if an object is an IP address."""
    if not x:
        return None
    output: str | int = x
    if x.isdigit():
        output = int(x)
    return ip_address(output)


def ip_if(x: str) -> IPv4Interface | IPv6Interface | None:
    """Validate if an object is an IP interface."""
    if not x:
        return None
    return ip_interface(x)


def ip_net(x: str) -> IPv4Network | IPv6Network | None:
    """Validate if an object is an IP network."""
    if not x:
        return None
    return ip_network(x)


def validate_ip_networks(x: list[str]) -> list[IPv4Network | IPv6Network]:
    """Validate if an object is a list of IP networks."""
    output: list[IPv4Network | IPv6Network] = [
        network for i in x if (network := ip_net(i))
    ]

    return output


def get_service_config(
    _: typer.Context,
    path: pathlib.Path,
) -> vpnc.models.tenant.ServiceEndpoint | vpnc.models.tenant.ServiceHub:
    """Get the service configuration from a file."""
    service: vpnc.models.tenant.ServiceEndpoint | vpnc.models.tenant.ServiceHub
    with path.open(encoding="utf-8") as f:
        try:
            service = vpnc.models.tenant.ServiceEndpoint(**yaml.safe_load(f))
        except ValidationError:
            f.seek(0)
            service = vpnc.models.tenant.ServiceHub(**yaml.safe_load(f))

    return service


def get_config_path(ctx: typer.Context, active: bool) -> pathlib.Path:  # noqa: FBT001
    """Get the correct tenant path."""
    path = config.VPNC_C_CONFIG_DIR
    if active:
        path = config.VPNC_A_CONFIG_DIR
    if not path.exists():
        ctx.fail("Tenant configuration directory not found.")

    return path


def get_tenant_config(
    ctx: typer.Context,
    tenant_id: str,
    path: pathlib.Path,
) -> (
    vpnc.models.tenant.ServiceEndpoint
    | vpnc.models.tenant.ServiceHub
    | vpnc.models.tenant.Tenant
):
    """Get the tenant configuration from a file."""
    if (
        not config.DOWNLINK_TEN_RE.match(tenant_id)
        and tenant_id != config.DEFAULT_TENANT
    ):
        ctx.fail(f"Tenant name '{tenant_id}' is invalid.")

    config_path = path.joinpath(f"{tenant_id}.yaml")
    tenant: (
        vpnc.models.tenant.ServiceEndpoint
        | vpnc.models.tenant.ServiceHub
        | vpnc.models.tenant.Tenant
    )
    with config_path.open(encoding="utf-8") as fh:
        if tenant_id == config.DEFAULT_TENANT:
            tenant = get_service_config(ctx, config_path)
        else:
            tenant = vpnc.models.tenant.Tenant(**yaml.safe_load(fh))
    if tenant_id != tenant.id:
        ctx.fail(f"Mismatch between file name '{tenant_id}' and id '{tenant.id}'.")

    return tenant
