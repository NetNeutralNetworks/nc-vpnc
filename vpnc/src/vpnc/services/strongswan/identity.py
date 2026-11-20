"""The IKE id type charon makes of an id string (docs: config/identityParsing)."""

from __future__ import annotations

import ipaddress
import re

# RFC 7296 names by number, for the {n}:value form.
TYPES = {
    1: "IPV4_ADDR",
    2: "FQDN",
    3: "RFC822_ADDR",
    4: "IPV4_ADDR_SUBNET",
    5: "IPV6_ADDR",
    6: "IPV6_ADDR_SUBNET",
    7: "IPV4_ADDR_RANGE",
    8: "IPV6_ADDR_RANGE",
    9: "DER_ASN1_DN",
    10: "DER_ASN1_GN",
    11: "KEY_ID",
}
PREFIXES = {
    "ipv4": "IPV4_ADDR",
    "ipv6": "IPV6_ADDR",
    "ipv4net": "IPV4_ADDR_SUBNET",
    "ipv6net": "IPV6_ADDR_SUBNET",
    "ipv4range": "IPV4_ADDR_RANGE",
    "ipv6range": "IPV6_ADDR_RANGE",
    "rfc822": "RFC822_ADDR",
    "email": "RFC822_ADDR",
    "userfqdn": "RFC822_ADDR",
    "fqdn": "FQDN",
    "dns": "FQDN",
    "asn1dn": "DER_ASN1_DN",
    "asn1gn": "DER_ASN1_GN",
    "keyid": "KEY_ID",
}
ANY = ("", "%any", "%any6", "0.0.0.0", "::", "*")  # noqa: S104
# Leading @ forms, longest first.
_AT = (("@#", "KEY_ID"), ("@@", "RFC822_ADDR"), ("@", "FQDN"))
# What a string that isn't an address becomes: with a colon, a key id.
_NOT_AN_ADDRESS = {4: "FQDN", 6: "KEY_ID"}
_TYPED = re.compile(
    r"^(?:\{(?P<number>\d+)\}|(?P<prefix>[a-z0-9]+)):(?P<value>.*)$", re.IGNORECASE
)


def _typed(text: str) -> tuple[str, str] | None:
    """Return the type and value of a <type>:<value> id."""
    if not (match := _TYPED.match(text)):
        return None
    if number := match["number"]:
        kind = TYPES.get(int(number), f"{{{number}}}")
    elif not (kind := PREFIXES.get(match["prefix"].lower(), "")):
        return None
    return kind, match["value"]


def _address(text: str, version: int) -> str | None:
    """Return the type of an address, subnet or range of an IP version."""
    kind = "IPV4" if version == 4 else "IPV6"  # noqa: PLR2004
    try:
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
            return f"{kind}_ADDR_SUBNET"
        if "-" in text:
            first, last = text.split("-", 1)
            ipaddress.ip_address(first)
            ipaddress.ip_address(last)
            return f"{kind}_ADDR_RANGE"
        if ipaddress.ip_address(text).version == version:
            return f"{kind}_ADDR"
    except ValueError:
        pass
    return None


def parse(text: str) -> tuple[str | None, str]:
    """Return an id's type (None for %any) and its value as charon shows it."""
    if typed := _typed(text):
        return typed
    if "=" in text:
        return "DER_ASN1_DN", text
    for prefix, kind in _AT:
        if text.startswith(prefix):
            return kind, text[len(prefix) :]
    if "@" in text:
        return "RFC822_ADDR", text
    if text in ANY:
        return None, text
    version = 6 if ":" in text else 4
    return _address(text, version) or _NOT_AN_ADDRESS[version], text
