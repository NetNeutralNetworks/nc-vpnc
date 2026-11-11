"""Various enums used throughout the package."""

from enum import Enum


class ConnectionType(str, Enum):
    """Define the modes in which the connections can run."""

    IPSEC = "ipsec"
    PHYSICAL = "physical"
    SSH = "ssh"
    WIREGUARD = "wireguard"


class ServiceMode(str, Enum):
    """Define the modes in which the service can run."""

    HUB = "hub"
    ENDPOINT = "endpoint"


class NetworkInstanceType(str, Enum):
    """Define the modes in which the service can run."""

    ENDPOINT = "endpoint"
    EXTERNAL = "external"
    CORE = "core"
    DOWNLINK = "downlink"
