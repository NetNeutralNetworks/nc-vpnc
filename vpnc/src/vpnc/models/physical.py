"""Code to configure PHYSICAL connections."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Literal

import pyroute2
from pydantic import BaseModel, field_validator

from vpnc.models import connections, enums
from vpnc.network import state

if TYPE_CHECKING:
    import vpnc.models.network_instance

logger = logging.getLogger("vpnc")


class ConnectionConfigPhysical(BaseModel):
    """Defines a local connection data structure."""

    type: Literal[enums.ConnectionType.PHYSICAL] = enums.ConnectionType.PHYSICAL
    interface_name: str

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type(cls, v: str) -> enums.ConnectionType:
        return enums.ConnectionType(v)

    def add(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create a local connection."""
        if connection.config.type != enums.ConnectionType.PHYSICAL:
            logger.critical(
                "Wrong connection configuration provided for %s",
                network_instance.id,
            )
            raise TypeError

        ifname = connection.config.interface_name
        if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(network_instance)
        with (
            state.netns(network_instance.id) as dl,
            pyroute2.IPRoute() as ni_default,
        ):
            ni_dl, ni_state = dl.ipr, dl.state
            state.ensure_moved(ni_dl, ni_default, ni_state, ifname)
            if ifname not in ni_state.links:
                logger.critical("Physical interface %s not found.", ifname)
                raise ValueError
            state.ensure_link_state(ni_dl, ni_state, ifname, up=True)
            state.ensure_addresses(ni_dl, ni_state, ifname, [*if_ipv4, *if_ipv6])

        return ifname

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        interface_name = self.intf_name(network_instance, connection)
        # run the commands
        with state.netns(network_instance.id) as dl:
            if not (indexes := dl.ipr.link_lookup(ifname=interface_name)):
                return
            # The namespace of PID 1 (DEFAULT); a number as net_ns_fd is a file
            # descriptor.
            dl.ipr.link("set", index=indexes[0], net_ns_pid=1)
            dl.invalidate()

    def intf_name(
        self,
        _: vpnc.models.network_instance.NetworkInstance,
        __: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return self.interface_name
