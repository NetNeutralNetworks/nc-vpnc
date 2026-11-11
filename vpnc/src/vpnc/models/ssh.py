"""Code to configure SSH connections."""

from __future__ import annotations

import json
import logging
import subprocess
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

import vpnc.models.network_instance
import vpnc.services.ssh
from vpnc.models import connections, enums
from vpnc.network import state

logger = logging.getLogger("vpnc")


class ConnectionConfigSSH(BaseModel):
    """Defines an SSH connection data structure."""

    type: Literal[enums.ConnectionType.SSH] = enums.ConnectionType.SSH
    remote_addrs: list[IPv4Address | IPv6Address] = Field(min_length=1)
    remote_config: bool = False
    # Required. Specifies the remote
    # tunnel identifier to avoid overlap.
    remote_tunnel_id: int
    # Optional interface on the remote side to configure for masquerade.
    # Used in a script on the remote side: an interface name only.
    remote_config_interface: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$",
    )
    # Used as an ssh argument: a user name only, not an option.
    username: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type(cls, v: str) -> enums.ConnectionType:
        return enums.ConnectionType(v)

    def add(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create an SSH connection."""
        if network_instance.type != enums.NetworkInstanceType.DOWNLINK:
            err = (
                "Connections of type SSH can only be used in DOWNLINK network instances"
            )
            logger.error(err)
            raise ValueError(err)
        tun = self.intf_name(network_instance, connection)

        if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(
            network_instance,
        )

        with state.netns(network_instance.id) as dl:
            ni_dl, ni_state = dl.ipr, dl.state
            state.ensure_tun(ni_dl, ni_state, tun)
            state.ensure_link_state(ni_dl, ni_state, tun, up=True)
            state.ensure_addresses(ni_dl, ni_state, tun, [*if_ipv4, *if_ipv6])

        vpnc.services.ssh.start(network_instance, connection)
        return tun

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        vpnc.services.ssh.stop(network_instance, connection)
        interface_name = self.intf_name(network_instance, connection)
        with state.netns(network_instance.id) as dl:
            state.delete_link(dl.ipr, dl.state, interface_name)

    def intf_name(
        self,
        _: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return f"tun{connection.id}"

    def status_summary(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> dict[str, Any]:
        """Get the connection status."""
        connection_name = f"{network_instance.id}-{connection.id}"
        ssh_master_socket = vpnc.services.ssh.SSH_SOCKET_DIR.joinpath(
            f"{connection_name}.sock",
        )
        if_name = self.intf_name(network_instance, connection)
        status_command = subprocess.run(  # noqa: S603
            [
                "/usr/bin/ssh",
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

        status = "ACTIVE" if status_command.returncode == 0 else "INACTIVE"

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
            "connection": connection.id,
            "type": self.type.name,
            "status": status,
            "interface-name": if_name,
            "interface-ip": [
                f"{x['local']}/{x['prefixlen']}" for x in output["addr_info"]
            ],
            "remote-addr": self.remote_addrs[0],
        }

        return output_dict
