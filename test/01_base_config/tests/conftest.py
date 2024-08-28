from __future__ import annotations

import subprocess


def run_cmd(host: str, command: str) -> str:
    """Run a command in the docker container and returns the results."""
    cmd = ["docker", "exec", f"clab-vpnc-{host}"]
    cmd.extend(command.split())

    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def run_cmd_shell(host: str, command: str) -> str:
    """Run a command in the docker container and returns the results."""
    cmd = f"docker exec clab-vpnc-{host} {command}"

    return subprocess.run(  # noqa: S602
        cmd,
        capture_output=True,
        text=True,
        check=True,
        shell=True,
    ).stdout


def run_cmd_vtysh(host: str, command: str) -> str:
    """Run a command in the docker container and returns the results."""
    cmd = ["docker", "exec", f"clab-vpnc-{host}", "vtysh", "-c", command]
    cmd.extend(command.split())

    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
