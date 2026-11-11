"""Run nft commands through the nft program, in this process's namespace.

The same way as vpnc, which can't use libnftables (see vpnc.network.nftables).
"""

import subprocess

NFT = "/usr/sbin/nft"
TIMEOUT = 30


class NftablesError(Exception):
    """An nftables command failed."""


def run(commands: str) -> None:
    """Run nft commands (as in an nft -f file) in one transaction."""
    proc = subprocess.run(  # noqa: S603
        [NFT, "-f", "-"],
        input=commands.encode(),
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    if proc.returncode:
        error = proc.stderr.decode(errors="replace").strip()
        raise NftablesError(error or f"nft failed ({proc.returncode})")
