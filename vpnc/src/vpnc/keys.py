"""Random secrets: for vpnctl generate, and for commits that fill them in.

Standard library only: vpnctl imports it.
"""

import base64
import secrets
import string

# What vpnctl generate writes: text is 64 letters and digits (about 381 bits);
# hex and base64 are 256 bits.
FORMATS = ("text", "hex", "base64")


def random_secret(fmt: str, *, prefix: bool = False) -> str:
    """Return a random secret; with prefix, hex is 0x... as strongSwan reads a PPK."""
    if fmt == "text":
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(64))
    if fmt == "hex":
        return ("0x" if prefix else "") + secrets.token_hex(32)
    return base64.b64encode(secrets.token_bytes(32)).decode()


def wireguard_private_key() -> str:
    """Return a new WireGuard private key, clamped as wg genkey does."""
    key = bytearray(secrets.token_bytes(32))
    key[0] &= 248
    key[31] = (key[31] & 127) | 64
    return base64.b64encode(bytes(key)).decode()
