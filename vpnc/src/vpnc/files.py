"""Write configuration files idempotently."""

from __future__ import annotations

import os
import secrets
import stat
import threading
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader

# Held while reading and then writing a tenant's configuration files (the API
# and the reconciler's NPTv6 prefixes), so no change is lost.
CONFIG_LOCK = threading.RLock()

# Files with secrets (pre-shared and private keys) and their directories.
SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700


def templates(module_file: str) -> Environment:
    """Return the Jinja environment of the templates directory next to a module."""
    # Config files, not HTML: values must be written as they are.
    return Environment(
        loader=FileSystemLoader(Path(module_file).parent / "templates"),
        autoescape=False,  # noqa: S701
    )


def to_yaml(data: Any) -> str:  # noqa: ANN401
    """Return data as a YAML document, as in the configuration files."""
    return yaml.safe_dump(data, explicit_start=True, explicit_end=True)


def ensure_file(path: Path, content: str, *, secret: bool = False) -> bool:
    """Write a file only if its content differs; return whether it was written.

    Unchanged files aren't rewritten, so file watchers don't reload them; a
    written file shows up as moved. A secret file is only readable by its owner.
    """
    try:
        changed = path.read_text(encoding="utf-8") != content
    except FileNotFoundError:
        changed = True
    if changed:
        # Replaced in one step, so readers never see a partly written file. The
        # name isn't matched by the file watchers, and is new: an existing file
        # or symbolic link isn't written to.
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        mode = SECRET_FILE_MODE if secret else 0o666
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(temporary, flags, mode)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            temporary.replace(path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    elif secret and stat.S_IMODE(path.stat().st_mode) != SECRET_FILE_MODE:
        path.chmod(SECRET_FILE_MODE)
    return changed


def secure_tree(directory: Path) -> None:
    """Make a directory with secrets, and all in it, only accessible by root.

    Owned by another user, that user could replace what vpnc writes there.
    """
    if directory.is_symlink() or not directory.is_dir():
        return
    os.chown(directory, 0, 0)
    directory.chmod(SECRET_DIR_MODE)
    for path in directory.rglob("*"):
        if path.is_symlink():
            continue
        os.chown(path, 0, 0)
        path.chmod(SECRET_DIR_MODE if path.is_dir() else SECRET_FILE_MODE)
