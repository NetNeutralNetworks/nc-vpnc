"""Helpers shared by the lab test suites.

Run commands in the containerlab containers and wait for the lab to reach a state.
"""

from __future__ import annotations

import contextlib
import ipaddress
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

# Polls the nodes with SNMP over the management network, like a monitoring system.
SNMP_POLLER = "mgt00"
SNMP_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
SNMP_ROUTE_TYPE = "1.3.6.1.2.1.10.166.11.1.4.1.1.8"


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


def _key_exchange(algorithms: str) -> str:
    """Return the key exchanges of an SA's algorithms, e.g. ECP_384/KE1_ML_KEM_768.

    Without the encryption, integrity and PRF algorithms; /PPK if one was used.
    """
    skip = ("AES_", "CHACHA20", "HMAC_", "PRF_", "ESN", "NO_EXT_SEQ")
    return "/".join(p for p in algorithms.split("/") if not p.startswith(skip))


def key_exchanges(host: str) -> dict[str, dict[str, set[str]]]:
    """Return per connection the key exchanges of its established SAs.

    {"ike": ..., "child": ...}; a child SA has none ("") until it's rekeyed.
    """
    output = run_cmd_shell(host, "swanctl --list-sas 2>/dev/null")
    result: dict[str, dict[str, set[str]]] = {}
    name = ""
    established = False
    for line in output.splitlines():
        if line[:1].isalnum():
            name = line.split(":")[0]
            established = ", ESTABLISHED, " in line
            continue
        if not established:
            continue
        sas = result.setdefault(name, {"ike": set(), "child": set()})
        if "PRF_" in line and "'" not in line:
            sas["ike"].add(_key_exchange(line.strip()))
        elif ", INSTALLED, " in line and "ESP:" in line:
            sas["child"].add(_key_exchange(line.split("ESP:")[1].strip()))
    return result


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


@contextlib.contextmanager
def route(host: str, route: str, netns: str = "") -> Iterator[None]:
    """Give a lab node an IPv6 route (as for "ip route") until the context exits."""
    ip = f"{netns}ip -6 route"
    run_cmd(host, f"{ip} add {route}")
    try:
        yield
    finally:
        run_cmd(host, f"{ip} del {route}")


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


# Sends an IKEv2 IKE_SA_INIT with a proposal vpnc doesn't use (AES-CBC, SHA-256,
# ECP-256) from an ephemeral port. charon answers it with NO_PROPOSAL_CHOSEN.
IKE_PROBE = """\
import os, socket, struct, sys


def payload(next_type, body):
    return struct.pack("!BBH", next_type, 0, 4 + len(body)) + body


def transform(last, kind, transform_id, attributes=b""):
    more, length = (0 if last else 3), 8 + len(attributes)
    return struct.pack("!BBHBBH", more, 0, length, kind, 0, transform_id) + attributes


transforms = (
    transform(False, 1, 12, struct.pack("!HH", 0x800E, 128))
    + transform(False, 2, 5)
    + transform(False, 3, 12)
    + transform(True, 4, 19)
)
proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4)
# SA, KE (ECP-256) and nonce.
body = (
    payload(34, proposal + transforms)
    + payload(40, struct.pack("!HH", 19, 0) + os.urandom(64))
    + payload(0, os.urandom(32))
)
# Initiator SPI, responder SPI 0, IKEv2, IKE_SA_INIT request, message id 0.
header = os.urandom(8) + bytes(8)
header += struct.pack("!BBBBII", 33, 0x20, 34, 0x08, 0, 28 + len(body))
address = sys.argv[1]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
with socket.socket(family, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.sendto(header + body, (address, 500))
    try:
        sock.recv(65535)
    except TimeoutError:
        print("dropped")
    else:
        print("answered")
"""


def ike_answered(host: str, netns: str, address: str) -> bool:
    """Return whether IKE to address, from a network namespace of host, is answered.

    charon answers any IKE_SA_INIT it receives, so no answer means it was dropped.
    """
    path = "/tmp/ike_probe.py"  # noqa: S108
    write_file(host, path, IKE_PROBE)
    output = run_cmd(host, f"ip netns exec {netns} python3 {path} {address}")
    return output.strip() == "answered"


def snmp_walk(host: str, oid: str) -> dict[tuple[int, ...], str]:
    """Walk a column of a node with SNMP and return its values by index."""
    output = run_cmd(
        SNMP_POLLER,
        f"snmpbulkwalk -v2c -c public -Oqn udp6:{host} {oid}",
    )
    values = {}
    for line in output.splitlines():
        name, _, value = line.partition(" ")
        if name.startswith(f".{oid}."):
            index = name.removeprefix(f".{oid}.").split(".")
            values[tuple(int(number) for number in index)] = value.strip('"')
    return values


def snmp_interfaces(host: str) -> dict[str, tuple[int, ...]]:
    """Return the SNMP index of every interface of a node by its name."""
    return {name: index for index, name in snmp_walk(host, SNMP_IF_NAME).items()}


def snmp_route(index: tuple[int, ...]) -> tuple[str, str, str | None]:
    """Return the network instance, destination and next hop of a route's index."""
    numbers = list(index)

    def take() -> bytes:
        length = numbers.pop(0)
        value = bytes(numbers[:length])
        del numbers[:length]
        return value

    name = take().decode()
    del numbers[:1]
    address = ipaddress.ip_address(take())
    prefix_length = numbers.pop(0)
    take()
    del numbers[:1]
    # Without a gateway the zero address.
    gateway = ipaddress.ip_address(take())
    return (name, f"{address}/{prefix_length}", str(gateway) if int(gateway) else None)


def snmp_routes(host: str) -> set[tuple[str, str, str | None]]:
    """Return the routes of a node's network instances as SNMP has them."""
    return {snmp_route(index) for index in snmp_walk(host, SNMP_ROUTE_TYPE)}
