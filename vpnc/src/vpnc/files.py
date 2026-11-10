"""Write configuration files idempotently."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def ensure_file(path: Path, content: str) -> bool:
    """Write a file only if its content differs; return whether it was written.

    Unchanged files aren't rewritten, so file watchers don't reload them.
    """
    try:
        if path.read_text(encoding="utf-8") == content:
            return False
    except FileNotFoundError:
        pass
    path.write_text(content, encoding="utf-8")
    return True
