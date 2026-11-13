"""Code to configure IPSEC connections."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from vpnc import config, helpers
from vpnc.models import connections, enums
from vpnc.models.secret import Secret
from vpnc.network import state
from vpnc.services import wireguard

if TYPE_CHECKING:
    import vpnc.models.network_instance

logger = logging.getLogger("vpnc")


class ConnectionConfigWireGuard(BaseModel):
    """Defines an IPsec connection data structure."""

    type: Literal[enums.ConnectionType.WIREGUARD] = enums.ConnectionType.WIREGUARD
    _upper = helpers.upper("type")
    # Set a local id for the connection specifically.
    local_port: int = Field(default=51820, ge=1, le=65535)
    remote_addrs: list[IPv4Address | IPv6Address] = Field(min_length=1)
    remote_port: int = Field(default=51820, ge=1, le=65535)
    private_key: Secret
    public_key: str

    def add(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create a WireGuard interface and accept its port in EXTERNAL."""
        # Imported here: network_instance imports this module.
        from vpnc.models.network_instance import (  # noqa: PLC0415
            open_wireguard_ports,
            wireguard_port_users,
        )

        name = connection.name(network_instance)
        users = wireguard_port_users().get(self.local_port, [name])
        if len(users) > 1:
            # The interface that has the port keeps it; otherwise the first name.
            holders = [
                user
                for user in users
                if wireguard.listen_port(
                    helpers.split_connection_name(user)[0],
                    helpers.wireguard_interface_name(user),
                )
                == self.local_port
            ]
            holder = (holders or users)[0]
            if holder != name:
                msg = (
                    f"WireGuard port {self.local_port} of {name}"
                    f" is in use by {holder}."
                )
                raise ValueError(msg)

        open_wireguard_ports()
        wg = self.intf_name(network_instance, connection)

        with (
            state.netns(network_instance.id) as dl,
            state.netns(config.EXTERNAL_NI) as ext,
        ):
            state.ensure_wireguard(dl.ipr, ext.ipr, dl.state, wg)
            state.ensure_link_state(dl.ipr, dl.state, wg, up=connection.enabled)
            connection.ensure_mtu_and_addresses(network_instance, dl)

        wireguard.generate_config(network_instance, connection)
        wireguard.sync(network_instance, connection, wg)

        return wg

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        connection.delete_interface(network_instance)
        interface_name = self.intf_name(network_instance, connection)
        wireguard.config_path(interface_name).unlink(missing_ok=True)

        from vpnc.models.network_instance import open_wireguard_ports  # noqa: PLC0415

        open_wireguard_ports()

    def intf_name(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return helpers.wireguard_interface_name(connection.name(network_instance))
