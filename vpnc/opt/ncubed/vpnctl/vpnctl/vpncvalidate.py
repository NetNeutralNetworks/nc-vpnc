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


def _validate_ip_address(x: str) -> IPv4Address | IPv6Address | None:
    if x is None:
        return None
    if x.isdigit():
        x = int(x)
    return ip_address(x)


def _validate_ip_interface(x: str) -> IPv4Interface | IPv6Interface | None:
    if x is None:
        return None
    return ip_interface(x)


def _validate_ip_network(x: str) -> IPv4Network | IPv6Network | None:
    if x is None:
        return None
    return ip_network(x)


def _validate_ip_networks(x: list[str]) -> list[IPv4Network | IPv6Network]:
    output = []
    for i in x:
        output.append(str(ip_network(i)))
    return output
