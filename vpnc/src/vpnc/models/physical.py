"""Code to configure PHYSICAL connections."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Literal

import pyroute2
from pydantic import BaseModel

from vpnc import helpers
from vpnc.models import connections, enums
from vpnc.network import state

if TYPE_CHECKING:
    import vpnc.models.network_instance

logger = logging.getLogger("vpnc")


class ConnectionConfigPhysical(BaseModel):
    """Defines a local connection data structure."""

    type: Literal[enums.ConnectionType.PHYSICAL] = enums.ConnectionType.PHYSICAL
    _upper = helpers.upper("type")
    interface_name: str

    def add(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create a local connection."""
        ifname = self.interface_name
        with (
            state.netns(network_instance.id) as dl,
            pyroute2.IPRoute() as ni_default,
        ):
            state.ensure_moved(dl.ipr, ni_default, dl.state, ifname)
            if ifname not in dl.state.links:
                logger.critical("Physical interface %s not found.", ifname)
                raise ValueError
            state.ensure_link_state(dl.ipr, dl.state, ifname, up=connection.enabled)
            connection.ensure_mtu_and_addresses(network_instance, dl)

        return ifname

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        _: connections.Connection,
    ) -> None:
        """Delete a connection."""
        with state.netns(network_instance.id) as dl:
            if not (indexes := dl.ipr.link_lookup(ifname=self.interface_name)):
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
