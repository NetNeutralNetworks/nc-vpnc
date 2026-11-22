"""Post-quantum cryptography settings of connections."""

from __future__ import annotations

import base64
import binascii
from enum import StrEnum
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from vpnc import helpers
from vpnc.models.secret import Secret

# RFC 8784: a PPK has at least 256 bits of entropy.
PPK_MIN_BYTES = 32
# WireGuard's preshared key: exactly 32 bytes, in base64.
WIREGUARD_PPK_BYTES = 32


class MlKem(StrEnum):
    """ML-KEM parameter sets (FIPS 203)."""

    ML_KEM_768 = "ML_KEM_768"
    ML_KEM_1024 = "ML_KEM_1024"


# strongSwan's proposal keywords.
STRONGSWAN_KE = {MlKem.ML_KEM_768: "mlkem768", MlKem.ML_KEM_1024: "mlkem1024"}
# OpenSSH's hybrid key exchanges; it has none with ML-KEM-1024.
OPENSSH_KEX = {MlKem.ML_KEM_768: "mlkem768x25519-sha256"}


def ppk_bytes(value: str) -> bytes:
    """Return a key as strongSwan reads it: text, 0x hex or 0s base64."""
    if value.startswith("0x"):
        return bytes.fromhex(value[2:])
    if value.startswith("0s"):
        return base64.b64decode(value[2:], validate=True)
    return value.encode()


def _min_length(value: SecretStr) -> SecretStr:
    try:
        key = ppk_bytes(value.get_secret_value())
    except (ValueError, binascii.Error) as exc:
        msg = "invalid 0x (hex) or 0s (base64) value"
        raise ValueError(msg) from exc
    if len(key) < PPK_MIN_BYTES:
        msg = f"a PPK needs at least {PPK_MIN_BYTES} bytes (256 bits)"
        raise ValueError(msg)
    return value


PpkSecret = Annotated[Secret, AfterValidator(_min_length)]


class PostQuantumPresharedKey(BaseModel):
    """A postquantum preshared key (RFC 8784)."""

    # Sent to the peer to select the key: the same on both sides, unique per node.
    # Default: the connection's name and the hostname, e.g. C0001-00-0-hub00.
    id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9@._:+-]{0,63}$",
    )
    key: PpkSecret

    @field_validator("key", mode="before")
    @classmethod
    def not_a_number(cls, v: object) -> object:
        """YAML reads an unquoted 0x value as a number."""
        if isinstance(v, int):
            msg = "quote the key: unquoted, YAML reads 0x... as a number"
            raise ValueError(msg)  # noqa: TRY004
        return v


class PostQuantumIPsec(BaseModel):
    """Hybrid ML-KEM key exchange (RFC 9370), optionally with a PPK."""

    enabled: bool = False
    ml_kem: MlKem = MlKem.ML_KEM_768
    ppk: PostQuantumPresharedKey | None = None

    _upper = helpers.upper("ml_kem")


class PostQuantumSSH(BaseModel):
    """Hybrid ML-KEM key exchange of OpenSSH."""

    enabled: bool = False
    ml_kem: MlKem = MlKem.ML_KEM_768

    _upper = helpers.upper("ml_kem")

    @field_validator("ml_kem")
    @classmethod
    def supported(cls, v: MlKem) -> MlKem:
        """OpenSSH only has ML-KEM-768."""
        if v not in OPENSSH_KEX:
            msg = f"{v.value} isn't supported by OpenSSH"
            raise ValueError(msg)
        return v


def _wireguard_ppk(value: SecretStr) -> SecretStr:
    try:
        key = base64.b64decode(value.get_secret_value(), validate=True)
    except binascii.Error:
        key = b""
    if len(key) != WIREGUARD_PPK_BYTES:
        msg = (
            f"a WireGuard PPK is {WIREGUARD_PPK_BYTES} bytes in base64 "
            "(vpnctl generate ppk, or wg genpsk)"
        )
        raise ValueError(msg)
    return value


WireGuardPpk = Annotated[Secret, AfterValidator(_wireguard_ppk)]


class PostQuantumWireGuard(BaseModel):
    """A PPK mixed into WireGuard's handshake (its preshared key)."""

    enabled: bool = False
    ppk: WireGuardPpk | None = None

    @model_validator(mode="after")
    def ppk_when_enabled(self) -> PostQuantumWireGuard:
        """WireGuard's only post-quantum protection is the PPK."""
        if self.enabled and self.ppk is None:
            msg = "post_quantum needs a ppk for WireGuard"
            raise ValueError(msg)
        return self

    def key(self) -> str | None:
        """Return the PPK in use; None if disabled."""
        return self.ppk.get_secret_value() if self.enabled and self.ppk else None
