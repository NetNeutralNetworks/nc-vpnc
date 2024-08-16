"""
Global configuration storing the configuration data
"""

import ipaddress
import logging
import pathlib

import pydantic

logger = logging.getLogger("vpncmangle")


class VpncMangleConfig(pydantic.BaseModel):
    """
    Basic mapping for DNS64 and DNS64
    """

    dns64: list[tuple[ipaddress.IPv6Network, ipaddress.IPv4Network]]
    dns66: list[tuple[ipaddress.IPv6Network, ipaddress.IPv6Network]]


class Config(pydantic.BaseModel):
    """
    Object to check for validity.
    """

    config: dict[str, VpncMangleConfig]


CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpncmangle/translations.json")
CONFIG: dict[str, VpncMangleConfig] = {}

ACL_MATCH: list[tuple[ipaddress.IPv6Network, str]] = []
