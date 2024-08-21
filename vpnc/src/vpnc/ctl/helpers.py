#!/usr/bin/env python3

import pathlib
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

import typer
import yaml
from pydantic import ValidationError

from vpnc.models import models

from .. import config


def ip_addr(x: str) -> IPv4Address | IPv6Address | None:
    """
    Validates if an object is an IP address.
    """
    if not x:
        return None
    if x.isdigit():
        x = int(x)
    return ip_address(x)


def ip_if(x: str) -> IPv4Interface | IPv6Interface | None:
    """
    Validates if an object is an IP interface.
    """
    if not x:
        return None
    return ip_interface(x)


def ip_net(x: str) -> IPv4Network | IPv6Network | None:
    """
    Validates if an object is an IP network.
    """
    if not x:
        return None
    return ip_network(x)


def validate_ip_networks(x: list[str]) -> list[IPv4Network | IPv6Network]:
    """
    Validates if an object is a list of IP networks.
    """
    output: list[IPv4Network | IPv6Network] = []
    for i in x:
        output.append(ip_net(i))
    return output


def get_service_config_path(ctx: typer.Context, active: bool) -> pathlib.Path:
    """
    Get the correct service path
    """
    path = config.VPNC_C_SERVICE_CONFIG_PATH
    if active:
        path = config.VPNC_A_SERVICE_CONFIG_PATH
    if not path.exists():
        ctx.fail("Service configuration file not found.")

    return path


def get_service_config(
    ctx: typer.Context, path: pathlib.Path
) -> models.ServiceEndpoint | models.ServiceHub:
    """
    Get the service configuration from a file
    """

    service: models.ServiceEndpoint | models.ServiceHub
    with open(path, "r", encoding="utf-8") as f:
        try:
            service = models.ServiceEndpoint(**yaml.safe_load(f))
        except ValidationError:
            f.seek(0)
            service = models.ServiceHub(**yaml.safe_load(f))

    return service


def get_tenant_config_path(ctx: typer.Context, active: bool) -> pathlib.Path:
    """
    Get the correct tenant path
    """
    path = config.VPNC_C_TENANT_CONFIG_DIR
    if active:
        path = config.VPNC_A_TENANT_CONFIG_DIR
    if not path.exists():
        ctx.fail("Tenant configuration directory not found.")

    return path


def get_tenant_config(
    ctx: typer.Context, tenant_id: str, path: pathlib.Path
) -> models.Tenant:
    """
    Get the tenant configuration from a file
    """

    if not config.DOWNLINK_TEN_RE.match(tenant_id):
        ctx.fail(f"Tenant name '{tenant_id}' is invalid.")

    config_path = path.joinpath(f"{tenant_id}.yaml")
    with open(config_path, "r", encoding="utf-8") as fh:
        tenant = models.Tenant(**yaml.safe_load(fh))
    if tenant_id != tenant.id:
        ctx.fail(f"Mismatch between file name '{tenant_id}' and id '{tenant.id}'.")

    return tenant
