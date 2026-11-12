"""Code to configure SSH connections."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel, Field

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

        with state.netns(network_instance.id) as dl:
            state.ensure_tun(dl.ipr, dl.state, tun)
            state.ensure_link_state(dl.ipr, dl.state, tun, up=True)
            connection.ensure_addresses(network_instance, dl)

        vpnc.services.ssh.start(network_instance, connection)
        return tun

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        vpnc.services.ssh.stop(network_instance, connection)
        connection.delete_interface(network_instance)

    def intf_name(
        self,
        _: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return f"tun{connection.id}"
