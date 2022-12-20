#!/usr/bin/env python3

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


def validate_ip_address(x: str) -> IPv4Address | IPv6Address | None:
    """
    Validates if an object is an IP address.
    """
    if x is None:
        return None
    if x.isdigit():
        x = int(x)
    return ip_address(x)


def validate_ip_interface(x: str) -> IPv4Interface | IPv6Interface | None:
    """
    Validates if an object is an IP interface.
    """
    if x is None:
        return None
    return ip_interface(x)


def validate_ip_network(x: str) -> IPv4Network | IPv6Network | None:
    """
    Validates if an object is an IP network.
    """
    if x is None:
        return None
    return ip_network(x)


def validate_ip_networks(x: list[str]) -> list[IPv4Network | IPv6Network]:
    """
    Validates if an object is a list of IP networks.
    """
    output = []
    for i in x:
        output.append(ip_network(i))
    return output
