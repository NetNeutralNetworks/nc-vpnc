"""Secret string type, masked unless explicitly revealed."""

from typing import Annotated, Any

from pydantic import PlainSerializer, SecretStr, SerializationInfo

# Pass as model_dump(context=...) when writing config files.
REVEAL: dict[str, Any] = {"reveal_secrets": True}


def _serialize(value: SecretStr, info: SerializationInfo) -> str:
    if info.context and info.context.get("reveal_secrets"):
        return value.get_secret_value()
    return str(value)


Secret = Annotated[SecretStr, PlainSerializer(_serialize, when_used="json")]
