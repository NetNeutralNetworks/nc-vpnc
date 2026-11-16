"""Manages SSH tunnels."""

from __future__ import annotations

import atexit
import base64
import binascii
import functools
import hashlib
import logging
import os
import pathlib
import re
import socket
import subprocess
import threading
import time
from typing import TYPE_CHECKING

import vpnc.models.connections
import vpnc.models.ssh
from vpnc import accounts, config, files, helpers
from vpnc.models import enums
from vpnc.models.post_quantum import OPENSSH_KEX

if TYPE_CHECKING:
    import vpnc.models.network_instance


logger = logging.getLogger("vpnc")

# Of ssh's account; not in /run/vpnc, which is root's.
SSH_SOCKET_DIR = pathlib.Path("/run/vpnc-ssh/")

# Seconds before reconnecting, doubled after each failed attempt.
RESTART_DELAY_MIN = 1
RESTART_DELAY_MAX = 30
# A tunnel that stayed up this long (seconds) resets the delay.
STABLE_AFTER = 60
# Characters logged of a line ssh prints.
MAX_LINE = 500


class SshTunnel(threading.Thread):
    """Run ssh and reconnect whenever it exits, until stopped.

    Replaces autossh, which gives up when ssh exits with 0 (e.g. when the server
    closes the session).
    """

    def __init__(self, name: str, command: list[str]) -> None:
        """Create the tunnel thread; call start() to run it."""
        super().__init__(name=f"ssh-{name}", daemon=True)
        self.connection_name = name
        self.command = command
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[str] | None = None
        # When the running ssh started (Unix time), None if it doesn't run.
        self.started: float | None = None

    def run(self) -> None:
        """Keep ssh running."""
        delay = RESTART_DELAY_MIN
        while True:
            started = time.monotonic()
            with self._lock:
                if self._stop_event.is_set():
                    return
                proc = self._proc = subprocess.Popen(  # noqa: S603
                    self.command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                )
                self.started = time.time()
            # Logged with the connection name, so it shows in its logs.
            last = ""
            for line in proc.stderr or []:
                # From the server: no control characters (e.g. terminal escapes).
                if line := helpers.printable(line.strip())[:MAX_LINE]:
                    logger.info("SSH tunnel %s: %s", self.connection_name, line)
                    last = line
            proc.wait()
            self.started = None
            if self._stop_event.is_set():
                return
            if time.monotonic() - started > STABLE_AFTER:
                delay = RESTART_DELAY_MIN
            logger.warning(
                "SSH tunnel %s exited (rc=%s), reconnecting in %ss: %s",
                self.connection_name,
                proc.returncode,
                delay,
                last[-500:],
            )
            self._stop_event.wait(delay)
            delay = min(delay * 2, RESTART_DELAY_MAX)

    @property
    def pid(self) -> int | None:
        """Return the process id of the running ssh."""
        proc = self._proc
        return proc.pid if proc is not None and proc.poll() is None else None

    def stop(self) -> None:
        """Stop ssh and the thread."""
        with self._lock:
            self._stop_event.set()
            proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.join(timeout=10)


SSH_CONNECTIONS: dict[str, vpnc.models.connections.Connection] = {}
SSH_TUNNELS: dict[str, SshTunnel] = {}
# The reconciler and the API start and stop tunnels.
LOCK = threading.RLock()


TEMPLATES_ENV = files.templates(__file__)
# A public key without its comment, e.g. "ssh-ed25519 AAAA...".
PUBLIC_KEY_RE = re.compile(r"[a-z0-9@.-]+ [A-Za-z0-9+/=]+")


class SetupError(Exception):
    """A connection has no remote side to set up for an account."""


def key(connection_name: str) -> pathlib.Path:
    """Return the file with a connection's private key."""
    return pathlib.Path(accounts.user(accounts.SSH).pw_dir, ".ssh", connection_name)


def _keygen(*args: str) -> str:
    """Run ssh-keygen as ssh's account and return its output."""
    return subprocess.run(  # noqa: S603
        [*accounts.command(accounts.SSH), "/usr/bin/ssh-keygen", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout


def ensure_key(connection_name: str) -> bool:
    """Make a connection's key if it has none; return whether it has one."""
    path = key(connection_name)
    # The reconciler and the API (remote_setup) both ask for it.
    with LOCK:
        if path.exists():
            return True
        arguments = ("-q", "-t", "ed25519", "-N", "", "-C", connection_name)
        try:
            _keygen(*arguments, "-f", str(path))
        except (OSError, subprocess.SubprocessError):
            logger.exception("Making the SSH key of %s failed.", connection_name)
            return False
    logger.info("Made the SSH key of %s.", connection_name)
    return True


def delete_key(connection_name: str) -> None:
    """Delete a connection's key."""
    path = key(connection_name)
    path.unlink(missing_ok=True)
    path.with_name(f"{path.name}.pub").unlink(missing_ok=True)


def public_key(connection_name: str) -> str | None:
    """Return a connection's public key, made if needed; None if that failed."""
    if not ensure_key(connection_name):
        return None
    try:
        # As the account, from the private key: the files are the account's.
        text = _keygen("-y", "-f", str(key(connection_name)))
    except (OSError, subprocess.SubprocessError):
        logger.warning("Reading the public key of %s failed.", connection_name)
        return None
    public = " ".join(text.split()[:2])
    return public if PUBLIC_KEY_RE.fullmatch(public) else None


def remote_setup(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
    username: str | None = None,
    interface: str | None = None,
) -> str:
    """Return a script that sets up the remote side for an unprivileged account.

    Root runs it there once; vpnc itself only opens the tunnel. By default for
    the connection's username, with what comes through the tunnel masqueraded
    out of its remote_config_interface.
    """
    cfg = connection.config
    name = connection.name(network_instance)
    if cfg.type != enums.ConnectionType.SSH:
        msg = f"{name} isn't an SSH connection."
        raise SetupError(msg)
    username = username or cfg.username
    if username == "root":
        msg = f"The setup of {name} is for an account other than root."
        raise SetupError(msg)
    if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(network_instance)
    return TEMPLATES_ENV.get_template("ssh-setup.sh.j2").render(
        connection=name,
        hub=re.sub(r"[^A-Za-z0-9._-]", "", socket.gethostname()),
        username=username,
        tun=f"tun{cfg.remote_tunnel_id}",
        routes=[str(address.network) for address in (*if_ipv4, *if_ipv6)],
        interface=interface or cfg.remote_config_interface,
        key=public_key(name),
    )


@functools.cache
def key_exchanges() -> frozenset[str]:
    """Return the key exchange methods the local OpenSSH supports."""
    output = subprocess.run(
        ["/usr/bin/ssh", "-Q", "kex"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return frozenset(output.split())


def unsupported_kex(config: vpnc.models.ssh.ConnectionConfigSSH) -> str | None:
    """Return the post-quantum key exchange if the local OpenSSH lacks it."""
    if not config.post_quantum.enabled:
        return None
    kex = OPENSSH_KEX[config.post_quantum.ml_kem]
    try:
        supported = key_exchanges()
    except (OSError, subprocess.CalledProcessError):
        logger.exception("Listing the key exchanges of OpenSSH failed.")
        return kex
    return None if kex in supported else kex


def known_hosts(connection_name: str) -> pathlib.Path:
    """Return the file with the host key of a connection's server."""
    return config.VPNC_KNOWN_HOSTS_DIR.joinpath(connection_name)


def session(connection_name: str) -> tuple[int, float] | None:
    """Return the process id and start (Unix time) of a tunnel's running ssh."""
    tunnel = SSH_TUNNELS.get(connection_name)
    if tunnel is None:
        return None
    pid, started = tunnel.pid, tunnel.started
    return (pid, started) if pid is not None and started is not None else None


def host_key(connection_name: str) -> str | None:
    """Return the type and fingerprint of the accepted host key of a server.

    E.g. ssh-ed25519 SHA256:abc..., as ssh-keygen -l shows it.
    """
    try:
        lines = known_hosts(connection_name).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        # [marker] hosts type key [comment]
        if fields and fields[0].startswith("@"):
            fields = fields[1:]
        if len(fields) < 3:  # noqa: PLR2004
            continue
        try:
            blob = base64.b64decode(fields[2], validate=True)
        except binascii.Error:
            continue
        digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        return f"{fields[1]} SHA256:{digest}"
    return None


def _prepare_directories() -> None:
    """Give the directories ssh writes in to its account."""
    user = accounts.user(accounts.SSH)
    SSH_SOCKET_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chown(SSH_SOCKET_DIR, user.pw_uid, user.pw_gid)
    directory = config.VPNC_KNOWN_HOSTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    # Root's before, with the files ssh made as root.
    if directory.stat().st_uid != user.pw_uid:
        for path in directory.iterdir():
            os.chown(path, user.pw_uid, user.pw_gid, follow_symlinks=False)
        os.chown(directory, user.pw_uid, user.pw_gid)
        directory.chmod(0o700)


def start(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Start an SSH tunnel."""
    if connection.config.type != enums.ConnectionType.SSH:
        logger.warning("Invalid module type specified.")
        return

    with LOCK:
        _start(network_instance, connection)


def _start(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    connection_name = connection.name(network_instance)
    ssh_master_socket = SSH_SOCKET_DIR.joinpath(f"{connection_name}.sock")
    if not connection.enabled:
        stop(network_instance, connection)
        return

    # Probes don't concern ssh: changing them doesn't restart it.
    connection = connection.model_copy(update={"probes": []})
    tunnel = SSH_TUNNELS.get(connection_name)
    if (
        connection == SSH_CONNECTIONS.get(connection_name)
        and tunnel is not None
        and tunnel.is_alive()
    ):
        logger.debug("No changes detected in connection '%s'.", connection_name)
        return

    stop(network_instance, connection)

    if kex := unsupported_kex(connection.config):
        logger.error(
            "Not starting SSH tunnel %s: OpenSSH lacks %s (Ubuntu 26.04 is required).",
            connection_name,
            kex,
        )
        return

    _prepare_directories()
    if not ensure_key(connection_name):
        return
    # A stale socket (e.g. after a kill) would stop ssh from becoming master.
    ssh_master_socket.unlink(missing_ok=True)

    command = [
        "/usr/sbin/ip",
        "netns",
        "exec",
        network_instance.id,
        # It talks to the tenant's server: not as root, without capabilities.
        *accounts.command(accounts.SSH),
        "/usr/bin/ssh",
        # The server is set up beforehand (remote_setup): no command to run.
        "-N",
        "-o",
        "ControlMaster=yes",
        "-o",
        f"ControlPath={ssh_master_socket}",
        "-o",
        "Tunnel=point-to-point",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=5",
        # Only the connection's own key.
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        str(key(connection_name)),
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts(connection_name)}",
        *(
            [
                "-o",
                f"KexAlgorithms={OPENSSH_KEX[connection.config.post_quantum.ml_kem]}",
            ]
            if connection.config.post_quantum.enabled
            else []
        ),
        "-w",
        f"{connection.id}:{connection.config.remote_tunnel_id}",
        f"{connection.config.username}@{connection.config.remote_addrs[0]}",
    ]
    tunnel = SshTunnel(connection_name, command)
    tunnel.start()
    SSH_TUNNELS[connection_name] = tunnel
    SSH_CONNECTIONS[connection_name] = connection


def stop(
    network_instance: vpnc.models.network_instance.NetworkInstance,
    connection: vpnc.models.connections.Connection,
) -> None:
    """Stop an SSH tunnel."""
    connection_name = connection.name(network_instance)
    with LOCK:
        SSH_CONNECTIONS.pop(connection_name, None)
        tunnel = SSH_TUNNELS.pop(connection_name, None)
        if tunnel is not None:
            tunnel.stop()


@atexit.register
def stop_all() -> None:
    """Stop all SSH tunnels."""
    for name in list(SSH_TUNNELS):
        SSH_CONNECTIONS.pop(name, None)
        SSH_TUNNELS.pop(name).stop()
