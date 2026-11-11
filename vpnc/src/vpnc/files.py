"""Write configuration files idempotently."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# Files with secrets (pre-shared and private keys) and their directories.
SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700


def ensure_file(path: Path, content: str, *, secret: bool = False) -> bool:
    """Write a file only if its content differs; return whether it was written.

    Unchanged files aren't rewritten, so file watchers don't reload them. A
    secret file is only readable by its owner.
    """
    try:
        changed = path.read_text(encoding="utf-8") != content
    except FileNotFoundError:
        changed = True
    if changed and secret:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECRET_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    elif changed:
        path.write_text(content, encoding="utf-8")
    if secret and stat.S_IMODE(path.stat().st_mode) != SECRET_FILE_MODE:
        path.chmod(SECRET_FILE_MODE)
    return changed


def secure_tree(directory: Path) -> None:
    """Make a directory with secrets, and all in it, only accessible by its owner."""
    if not directory.is_dir():
        return
    directory.chmod(SECRET_DIR_MODE)
    for path in directory.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(SECRET_DIR_MODE if path.is_dir() else SECRET_FILE_MODE)
