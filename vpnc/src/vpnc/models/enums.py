"""Various enums used throughout the package. Their values are upper case."""

from enum import Enum


class ConnectionType(str, Enum):
    """Define the modes in which the connections can run."""

    IPSEC = "IPSEC"
    PHYSICAL = "PHYSICAL"
    SSH = "SSH"
    WIREGUARD = "WIREGUARD"


class ServiceMode(str, Enum):
    """Define the modes in which the service can run."""

    HUB = "HUB"
    ENDPOINT = "ENDPOINT"


class NetworkInstanceType(str, Enum):
    """Define the modes in which the service can run."""

    ENDPOINT = "ENDPOINT"
    EXTERNAL = "EXTERNAL"
    CORE = "CORE"
    DOWNLINK = "DOWNLINK"
