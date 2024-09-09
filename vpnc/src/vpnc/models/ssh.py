"""Code to configure SSH connections."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, field_validator

import vpnc.services.ssh
from vpnc.models import enums, models
from vpnc.services import ssh

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address


logger = logging.getLogger("vpnc")


class ConnectionConfigSSH(BaseModel):
    """Defines an SSH connection data structure."""

    type: Literal[enums.ConnectionType.SSH] = enums.ConnectionType.SSH
    remote_addrs: list[IPv4Address | IPv6Address]
    remote_config: bool = False
    # Required. Specifies the remote
    # tunnel identifier to avoid overlap.
    remote_tunnel_id: int
    # Optional interface on the remote side to configure for masquerade.
    remote_config_interface: str | None = None
    username: str

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type(cls, v: str) -> enums.ConnectionType:
        return enums.ConnectionType(v)

    def add(
        self,
        network_instance: models.NetworkInstance,
        connection: models.Connection,
    ) -> str:
        """Create an XFRM interface."""
        if network_instance.type != models.NetworkInstanceType.DOWNLINK:
            err = (
                "Connections of type SSH can only be used in DOWNLINK network instances"
            )
            logger.error(err)
            raise ValueError(err)
        tun = self.intf_name(connection.id)

        if_ipv4, if_ipv6 = connection.calculate_ip_addresses(
            network_instance,
            connection.id,
        )

        cmds = f"""\
# configure SSH interfaces
/usr/sbin/ip -netns {network_instance.id} tuntap add {tun} mode tun
        """
        proc = subprocess.run(  # noqa: S602
            cmds,
            capture_output=True,
            shell=True,
            check=False,
        )
        logger.info(proc.args)
        logger.debug(proc.stdout, proc.stderr)

        proc = subprocess.run(  # noqa: S602
            f"""
/usr/sbin/ip -netns {network_instance.id} link set dev {tun} up
/usr/sbin/ip -netns {network_instance.id} -4 address flush dev {tun} scope global
/usr/sbin/ip -netns {network_instance.id} -6 address flush dev {tun} scope global
            """,
            capture_output=True,
            shell=True,
            check=False,
        )
        logger.info(proc.args)
        logger.debug(proc.stdout, proc.stderr)

        cmds = ""
        for ipv4 in if_ipv4:
            cmds += f"/usr/sbin/ip -netns {network_instance.id} address add {ipv4} dev {tun}\n"
        # Add the configured IPv6 address to the XFRM interface.
        for ipv6 in if_ipv6:
            cmds += f"/usr/sbin/ip -netns {network_instance.id} address add {ipv6} dev {tun}\n"

        proc = subprocess.run(  # noqa: S602
            cmds,
            capture_output=True,
            shell=True,
            check=False,
        )
        logger.info(proc.args)
        logger.debug(proc.stdout, proc.stderr)

        ssh.start(network_instance, connection)
        return tun

    def delete(
        self,
        network_instance: models.NetworkInstance,
        connection: models.Connection,
    ) -> None:
        """Delete a connection."""
        connection_name = f"{network_instance.id}-{connection.id}"
        interface_name = self.intf_name(connection.id)
        ssh.stop(connection_name)
        # run the commands
        proc = subprocess.run(
            [
                "/usr/sbin/ip",
                "-netns",
                network_instance.id,
                "link",
                "del",
                "dev",
                interface_name,
            ],
            capture_output=True,
            check=False,
        )
        logger.info(proc.args)
        logger.debug(proc.stdout, proc.stderr)

    def intf_name(self, connection_id: int) -> str:
        """Return the name of the connection interface."""
        return f"tun{connection_id}"

    def status_summary(
        self,
        network_instance: models.NetworkInstance,
        connection_id: int,
    ) -> dict[str, Any]:
        """Get the connection status."""
        connection_name = f"{network_instance}-{connection_id}"
        ssh_master_socket = vpnc.services.ssh.SSH_SOCKET_DIR.joinpath(
            f"{connection_name}.sock",
        )
        if_name = self.intf_name(connection_id)
        status_command = subprocess.run(  # noqa: S603
            [
                "/usr/sbin/ip",
                "--json",
                "netns",
                "exec",
                network_instance.id,
                "ssh",
                "-o",
                f"ControlPath={ssh_master_socket}",
                "-O",
                "check",
                f"{self.username}@{self.remote_addrs[0]}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        logger.info(status_command.args)
        logger.info(status_command.stdout, status_command.stderr)

        status = "ACTIVE" if "Master running" in status_command.stdout else "INACTIVE"

        output = json.loads(
            subprocess.run(  # noqa: S603
                [
                    "/usr/sbin/ip",
                    "--json",
                    "--netns",
                    network_instance.id,
                    "address",
                    "show",
                    "dev",
                    if_name,
                ],
                stdout=subprocess.PIPE,
                check=True,
            ).stdout,
        )[0]

        output_dict: dict[str, Any] = {
            "tenant": f"{network_instance.id.split('-')[0]}",
            "network-instance": network_instance.id,
            "connection": connection_id,
            "type": self.type.name,
            "status": status,
            "interface-name": if_name,
            "interface-ip": [
                f"{x['local']}/{x['prefixlen']}" for x in output["addr_info"]
            ],
            "remote-addr": self.remote_addrs[0],
        }

        return output_dict
