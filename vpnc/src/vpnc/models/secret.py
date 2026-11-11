"""Secret string type, masked unless explicitly revealed."""

from typing import Annotated, Any

from pydantic import AfterValidator, PlainSerializer, SecretStr, SerializationInfo

# Pass as model_dump(context=...) when writing config files.
REVEAL: dict[str, Any] = {"reveal_secrets": True}
# How a secret that isn't revealed is shown.
MASK = str(SecretStr("masked"))


def _serialize(value: SecretStr, info: SerializationInfo) -> str:
    if info.context and info.context.get("reveal_secrets"):
        return value.get_secret_value()
    return str(value)


def _not_masked(value: SecretStr) -> SecretStr:
    """Refuse a masked secret, e.g. a configuration sent back as it was shown."""
    if value.get_secret_value() == MASK:
        msg = "a masked secret; read the configuration with reveal_secrets"
        raise ValueError(msg)
    return value


Secret = Annotated[
    SecretStr,
    AfterValidator(_not_masked),
    PlainSerializer(_serialize, when_used="json"),
]
