"""Parse tenant information into a datamodel for easy use."""

from __future__ import annotations

from pydantic import BaseModel

from vpnc import config


class TenantInformation(BaseModel):
    """Contains the parsed tenant/network/connection information."""

    tenant: str
    tenant_ext: int
    tenant_ext_str: str
    tenant_id: int
    tenant_id_str: str
    network_instance: str | None
    network_instance_id: int | None
    connection: str | None
    connection_id: int | None


def parse_downlink_network_instance_name(
    name: str,
) -> TenantInformation:
    """Parse a connection name into it's components."""
    if config.DOWNLINK_CON_RE.match(name):
        return TenantInformation(
            tenant=name[:5],
            tenant_ext=int(name[0], 16),
            tenant_ext_str=name[0],
            tenant_id=int(name[1:5], 16),
            tenant_id_str=name[1:5],
            network_instance=name[:8],
            network_instance_id=int(name[6:8], 16),
            connection=name,
            connection_id=int(name[-1], 16),
        )

    if config.DOWNLINK_NI_RE.match(name):
        return TenantInformation(
            tenant=name[:5],
            tenant_ext=int(name[0], 16),
            tenant_ext_str=name[0],
            tenant_id=int(name[1:5], 16),
            tenant_id_str=name[1:5],
            network_instance=name[:8],
            network_instance_id=int(name[6:8], 16),
            connection=None,
            connection_id=None,
        )
    if config.DOWNLINK_TEN_RE.match(name):
        return TenantInformation(
            tenant=name[:5],
            tenant_ext=int(name[0], 16),
            tenant_ext_str=name[0],
            tenant_id=int(name[1:5], 16),
            tenant_id_str=name[1:5],
            network_instance=None,
            network_instance_id=None,
            connection=None,
            connection_id=None,
        )

    msg = f"Invalid network instance/connection name '{name}'"
    raise ValueError(msg)
