"""The accounts programs run as, so they don't have root's privileges."""

from __future__ import annotations

import pwd

# Created by make.
VPNCMANGLE = "vpnc-mangle"

SETPRIV = "/usr/bin/setpriv"


def exists(account: str) -> bool:
    """Return whether an account exists."""
    try:
        pwd.getpwnam(account)
    except KeyError:
        return False
    return True


def command(account: str, capabilities: tuple[str, ...] = ()) -> list[str]:
    """Return the start of a command that runs as an account (KeyError if missing).

    With only these capabilities (e.g. net_admin), and no way to gain others.
    """
    user = pwd.getpwnam(account)
    kept = ",".join(f"+{capability}" for capability in capabilities)
    return [
        SETPRIV,
        "--reuid",
        str(user.pw_uid),
        "--regid",
        str(user.pw_gid),
        "--clear-groups",
        "--bounding-set",
        ",".join(filter(None, ("-all", kept))),
        *(["--inh-caps", kept, "--ambient-caps", kept] if kept else []),
        "--no-new-privs",
    ]
