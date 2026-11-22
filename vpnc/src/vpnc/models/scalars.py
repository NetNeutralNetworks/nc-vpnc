"""Numbers and addresses that are only read from a value of their own kind.

pydantic reads true as the number 1 and 5 as the address 0.0.0.5. In
configuration and in requests that's a mistake, so it's refused.
"""

from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Annotated

from pydantic import BeforeValidator

# The checks raise a ValueError: pydantic reports that as invalid input.


def number(value: object) -> object:
    """Refuse true and false as a number."""
    if isinstance(value, bool):
        msg = "a number can't be true or false"
        raise ValueError(msg)  # noqa: TRY004
    return value


def address(value: object) -> object:
    """Refuse a number as an address or a network; true and false are numbers too."""
    if isinstance(value, int):
        msg = "an address can't be a number, true or false"
        raise ValueError(msg)  # noqa: TRY004
    return value


Int = Annotated[int, BeforeValidator(number)]
# Not Int | None with limits: the schema would lose its minimum and maximum.
OptionalInt = Annotated[int | None, BeforeValidator(number)]
Float = Annotated[float, BeforeValidator(number)]

Address4 = Annotated[IPv4Address, BeforeValidator(address)]
Address6 = Annotated[IPv6Address, BeforeValidator(address)]
Address = Annotated[IPv4Address | IPv6Address, BeforeValidator(address)]
Network4 = Annotated[IPv4Network, BeforeValidator(address)]
Network6 = Annotated[IPv6Network, BeforeValidator(address)]
Network = Annotated[IPv4Network | IPv6Network, BeforeValidator(address)]
Interface4 = Annotated[IPv4Interface, BeforeValidator(address)]
Interface6 = Annotated[IPv6Interface, BeforeValidator(address)]
