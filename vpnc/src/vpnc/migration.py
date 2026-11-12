"""Convert configuration of earlier versions to the current one.

A file of an earlier version is backed up and converted in place. Only the
last SUPPORTED earlier versions are converted: a new version adds a step to
STEPS, and the steps before those can be removed.
"""

from __future__ import annotations

import datetime
import logging
import re
from typing import TYPE_CHECKING, Any, NamedTuple

import yaml

from vpnc import config, files

if TYPE_CHECKING:
    import pathlib
    from collections.abc import Callable

logger = logging.getLogger("vpnc")

# The configuration version this vpnc reads and writes.
CURRENT = "0.1.4"
# The number of earlier versions that are converted.
SUPPORTED = 2

KEY_RE = re.compile(r"^( *)([^\s#:-][^:]*):")
VERSION_RE = re.compile(r"^version:.*$", re.MULTILINE)


class Step(NamedTuple):
    """The conversion of a version to the next."""

    version: str
    to: str
    # Returns the converted configuration.
    data: Callable[[dict[str, Any]], dict[str, Any]]
    # Optional: returns the converted text of a file, to keep its comments.
    text: Callable[[str, dict[str, Any]], str] | None = None


def _data_0_1_3(data: dict[str, Any]) -> dict[str, Any]:
    """Shorten the network instance keys (C0001-00 to 00) and drop the ids."""
    prefix = f"{data.get('id')}-"
    network_instances = {}
    for key, value in (data.get("network_instances") or {}).items():
        network_instance = value
        if isinstance(value, dict):
            network_instance = {k: v for k, v in value.items() if k != "id"}
            if isinstance(connections := value.get("connections"), dict):
                network_instance["connections"] = {
                    connection_key: {k: v for k, v in connection.items() if k != "id"}
                    if isinstance(connection, dict)
                    else connection
                    for connection_key, connection in connections.items()
                }
        short = key.removeprefix(prefix) if isinstance(key, str) else key
        network_instances[short] = network_instance
    return {**data, "network_instances": network_instances}


def _text_0_1_3(text: str, data: dict[str, Any]) -> str:
    """Do the same line by line, following the keys by their indentation."""
    full_key = re.compile(rf"{re.escape(str(data.get('id')))}-(\d\d)")
    lines = []
    stack: list[tuple[int, str]] = []
    for line in text.splitlines(keepends=True):
        if not (match := KEY_RE.match(line)):
            lines.append(line)
            continue
        indent, key = len(match[1]), match[2].strip("\"' ")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        path = [k for _, k in stack]
        if path[0] != "network_instances":
            lines.append(line)
        elif len(path) == 2 and (short := full_key.fullmatch(key)):  # noqa: PLR2004
            lines.append(f"{match[1]}{short[1]}:{line[match.end() :]}")
        elif path[-1] != "id" or not (
            len(path) == 3 or (len(path) == 5 and path[2] == "connections")  # noqa: PLR2004
        ):
            lines.append(line)
    return "".join(lines)


# Oldest first; each converts to the version of the next.
STEPS = (Step("0.1.3", "0.1.4", _data_0_1_3, _text_0_1_3),)[-SUPPORTED:]


def unsupported(version: object) -> str:
    """Return the error for a version that isn't the current one."""
    earlier = ", ".join(step.version for step in STEPS)
    return (
        f"configuration version {version} isn't supported: it should be {CURRENT}"
        f" (converted from: {earlier})"
    )


def _steps(data: dict[str, Any]) -> tuple[Step, ...]:
    """Return the steps that convert the configuration to the current version."""
    version = str(data.get("version"))
    for index, step in enumerate(STEPS):
        if step.version == version:
            return STEPS[index:]
    return ()


def upgrade(data: dict[str, Any]) -> dict[str, Any]:
    """Return configuration as the current version.

    Configuration of another version that can't be converted is returned as is.
    """
    for step in _steps(data):
        data = {**step.data(data), "version": step.to}
    return data


def _plain(value: Any) -> Any:  # noqa: ANN401
    """Return data with keys as YAML reads them unquoted: 00 as 0."""
    if isinstance(value, dict):
        return {
            int(k) if isinstance(k, str) and k.isdigit() else k: _plain(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _upgrade_text(text: str, data: dict[str, Any]) -> str:
    """Return the text of a file as the current version.

    Comments are kept, unless that text doesn't read as the converted data.
    """
    expected = upgrade(data)
    try:
        for step in _steps(data):
            if step.text is None:
                msg = f"no text conversion of {step.version}"
                raise ValueError(msg)  # noqa: TRY301
            text = VERSION_RE.sub(f"version: {step.to}", step.text(text, data), 1)
            data = {**step.data(data), "version": step.to}
        if _plain(yaml.safe_load(text)) == _plain(expected):
            return text
    except (ValueError, TypeError, AttributeError, yaml.YAMLError):
        pass
    return yaml.safe_dump(expected, explicit_start=True, explicit_end=True)


def _backup_path(path: pathlib.Path, version: str, text: str) -> pathlib.Path:
    """Return where to keep a file: backup/<version>/<its directory>/<its name>."""
    backup = config.VPNC_BACKUP_DIR / version / path.parent.name / path.name
    try:
        if backup.read_text(encoding="utf-8") != text:
            # Another file was converted before.
            stamp = datetime.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S")
            backup = backup.with_name(f"{backup.name}.{stamp}")
    except FileNotFoundError:
        pass
    return backup


def migrate_file(path: pathlib.Path) -> bool:
    """Back up and convert a file of an earlier version; return whether it was."""
    with files.CONFIG_LOCK:
        try:
            text = path.read_text(encoding="utf-8")
            data = yaml.safe_load(text)
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            return False
        if not isinstance(data, dict) or not _steps(data):
            return False
        version = str(data["version"])
        try:
            converted = _upgrade_text(text, data)
        except Exception:
            logger.exception("Converting %s from version %s failed.", path, version)
            return False
        backup = _backup_path(path, version, text)
        backup.parent.mkdir(parents=True, exist_ok=True)
        files.ensure_file(backup, text, secret=True)
        files.secure_tree(config.VPNC_BACKUP_DIR)
        files.ensure_file(path, converted, secret=True)
    logger.warning(
        "Converted %s from version %s to %s; the original is kept as %s.",
        path,
        version,
        CURRENT,
        backup,
    )
    return True


def migrate_all() -> None:
    """Convert the active, candidate and history files of earlier versions."""
    paths = [
        *config.VPNC_A_CONFIG_DIR.glob("*.yaml"),
        *config.VPNC_C_CONFIG_DIR.glob("*.yaml"),
        *config.VPNC_HISTORY_DIR.glob("*/*.yaml"),
    ]
    for path in sorted(paths):
        migrate_file(path)
