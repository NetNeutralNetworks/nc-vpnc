"""The accounts programs run as, so they don't have root's privileges."""

from __future__ import annotations

import pwd

# Created by make.
VPNCMANGLE = "vpnc-mangle"
# Its home holds the keys ssh logs in with (.ssh).
SSH = "vpnc-ssh"

SETPRIV = "/usr/bin/setpriv"


def user(account: str) -> pwd.struct_passwd:
    """Return an account's user (KeyError if missing)."""
    return pwd.getpwnam(account)


def exists(account: str) -> bool:
    """Return whether an account exists."""
    try:
        user(account)
    except KeyError:
        return False
    return True


def command(account: str, capabilities: tuple[str, ...] = ()) -> list[str]:
    """Return the start of a command that runs as an account (KeyError if missing).

    With only these capabilities (e.g. net_admin), and no way to gain others.
    """
    entry = user(account)
    kept = ",".join(f"+{capability}" for capability in capabilities)
    return [
        SETPRIV,
        "--reuid",
        str(entry.pw_uid),
        "--regid",
        str(entry.pw_gid),
        "--clear-groups",
        "--bounding-set",
        ",".join(filter(None, ("-all", kept))),
        *(["--inh-caps", kept, "--ambient-caps", kept] if kept else []),
        "--no-new-privs",
    ]
