"""Helpers shared by the lab test suites.

Run commands in the containerlab containers and wait for the lab to reach a state.
"""

from __future__ import annotations

import contextlib
import itertools
import subprocess
import time
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

T = TypeVar("T")

CONTAINER_PREFIX = "clab-vpnc-"

# Server of the hubs' SSH tunnels.
SSH_SERVER = "cli00"
# Behind the SSH server; C0001-00 routes it via the SSH tunnel.
SSH_TUNNEL_TARGET = "172.16.31.1/22"
SSH_REJECT_NEW = (
    "INPUT -i eth1 -p tcp --dport 22 -m conntrack --ctstate NEW"
    " -j REJECT --reject-with tcp-reset"
)


def run_cmd(host: str, command: str) -> str:
    """Run a command in the docker container and return its output.

    The command is split on whitespace; use run_cmd_shell for quoting, pipes, etc.
    """
    cmd = ["docker", "exec", f"{CONTAINER_PREFIX}{host}"]
    cmd.extend(command.split())

    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def run_cmd_shell(host: str, command: str) -> str:
    """Run a shell command line in the docker container and return its output.

    The host shell interprets the command line, so pipes and redirects run on the
    host; wrap them in "bash -c '...'" to run them in the container.
    """
    cmd = f"docker exec {CONTAINER_PREFIX}{host} {command}"

    return subprocess.run(  # noqa: S602
        cmd,
        capture_output=True,
        text=True,
        check=True,
        shell=True,
    ).stdout


def write_file(host: str, path: str, content: str) -> None:
    """Write a file in the docker container."""
    subprocess.run(  # noqa: S603
        ["docker", "exec", "-i", f"{CONTAINER_PREFIX}{host}", "tee", path],  # noqa: S607
        input=content,
        capture_output=True,
        text=True,
        check=True,
    )


def run_cmd_vtysh(host: str, command: str) -> str:
    """Run a vtysh command in the docker container and return its output."""
    cmd = ["docker", "exec", f"{CONTAINER_PREFIX}{host}", "vtysh", "-c", command]

    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def wait_until(
    func: Callable[[], T],
    timeout: float,
    interval: float = 1,
    message: str = "condition",
) -> T:
    """Poll func until it returns a truthy value and return that value.

    Exceptions raised by func count as "not yet". Raises TimeoutError with the last
    result or exception after timeout seconds.
    """
    deadline = time.monotonic() + timeout
    last: object = None
    while True:
        try:
            if result := func():
                return result
            last = result
        except Exception as exc:  # noqa: BLE001
            last = exc
        if time.monotonic() >= deadline:
            msg = f"Timed out after {timeout}s waiting for {message}. Last: {last!r}"
            raise TimeoutError(msg)
        time.sleep(interval)


def ssh_tunnel_works(host: str) -> bool:
    """Return whether a TCP connection through the hub's SSH tunnel succeeds."""
    try:
        run_cmd_shell(
            host,
            f"ip netns exec C0001-00 timeout 2 bash -c '</dev/tcp/{SSH_TUNNEL_TARGET}'",
        )
    except subprocess.CalledProcessError:
        return False
    return True


def close_ssh_sessions() -> None:
    """Close all SSH sessions on the SSH server, as a server restart would."""
    # OpenSSH 10 names session processes "sshd-session", older ones "sshd".
    closed = run_cmd_shell(
        SSH_SERVER,
        "pkill -c -f '^sshd(-session)?: .*@notty' || true",
    ).strip()
    assert closed not in ("", "0"), "No SSH sessions to close"


@contextlib.contextmanager
def ssh_server_down() -> Iterator[None]:
    """Close the SSH sessions and reject new ones until the context exits."""
    run_cmd_shell(SSH_SERVER, f"iptables -I {SSH_REJECT_NEW}")
    try:
        close_ssh_sessions()
        yield
    finally:
        run_cmd_shell(SSH_SERVER, f"iptables -D {SSH_REJECT_NEW}")


_nft_tables = itertools.count()


@contextlib.contextmanager
def nft_drop(host: str, netns: str, *matches: str) -> Iterator[None]:
    """Drop incoming packets matching nft expressions in a network namespace.

    Uses its own nftables table, which vpnc's iptables management leaves alone.
    """
    table = f"vpnc_test_{next(_nft_tables)}"
    nft = f"ip netns exec {netns} nft"
    rules = "; ".join(f"add rule inet {table} input {m} drop" for m in matches)
    run_cmd_shell(
        host,
        f"{nft} 'add table inet {table}; add chain inet {table} input"
        f" {{ type filter hook input priority -10; }}; {rules}'",
    )
    try:
        yield
    finally:
        run_cmd_shell(host, f"{nft} delete table inet {table} || true")
