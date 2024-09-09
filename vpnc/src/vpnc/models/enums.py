"""Various enums used throughout the package."""

from enum import Enum


class ConnectionType(Enum):
    """Define the modes in which the connections can run."""

    IPSEC = "ipsec"
    PHYSICAL = "physical"
    SSH = "ssh"


class ServiceMode(Enum):
    """Define the modes in which the service can run."""

    HUB = "hub"
    ENDPOINT = "endpoint"


class NetworkInstanceType(Enum):
    """Define the modes in which the service can run."""

    DEFAULT = "default"
    EXTERNAL = "external"
    CORE = "core"
    DOWNLINK = "downlink"
