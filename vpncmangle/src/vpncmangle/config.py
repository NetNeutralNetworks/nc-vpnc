"""Global configuration storing the configuration data."""

from __future__ import annotations

# needed for pydantic to create the classes
import ipaddress
import logging
import pathlib

import pydantic

logger = logging.getLogger("vpncmangle")


class VpncMangleConfig(pydantic.BaseModel):
    """Basic mapping for DNS64 and DNS64."""

    dns64: list[tuple[ipaddress.IPv6Network, ipaddress.IPv4Network]]
    dns66: list[tuple[ipaddress.IPv6Network, ipaddress.IPv6Network]]


class Config(pydantic.BaseModel):
    """Object to check for validity."""

    config: dict[str, VpncMangleConfig]


class Limits(pydantic.BaseModel):
    """What a network instance's DNS responses may cost: one thread handles all."""

    # kbytes of responses per second, per network instance.
    rate_limit: int = pydantic.Field(default=50, ge=1)
    # Bytes of a response (the IPv6 packet).
    max_size: int = pydantic.Field(default=4096, ge=512, le=65535)
    # Records in a response's answer, authority and additional sections.
    max_records: int = pydantic.Field(default=100, ge=1, le=65535)


CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpncmangle/translations.json")
# Optional; written by vpnc from the service's dns settings.
LIMITS_PATH = CONFIG_PATH.with_name("limits.json")
CONFIG: dict[str, VpncMangleConfig] = {}
LIMITS = Limits()

# Per translated network its network instance and that one's translations.
ACL_MATCH: list[tuple[ipaddress.IPv6Network, str, VpncMangleConfig]] = []
