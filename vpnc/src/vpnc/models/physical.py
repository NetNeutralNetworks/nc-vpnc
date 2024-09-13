"""Code to configure PHYSICAL connections."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Literal

import pyroute2
from pydantic import BaseModel, field_validator

from vpnc.models import enums, models

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
        network_instance: models.NetworkInstance,
        connection: models.Connection,
    ) -> str:
        """Create a local connection."""
        if not isinstance(connection.config, models.ConnectionConfigPhysical):
            logger.critical(
                "Wrong connection configuration provided for %s",
                network_instance.id,
            )
            raise TypeError

        with pyroute2.NetNS(
            netns=network_instance.id,
        ) as ni_dl, pyroute2.IPRoute() as ni_default:
            if not ni_dl.link_lookup(ifname=connection.config.interface_name):
                if not ni_default.link_lookup(
                    ifname=connection.config.interface_name,
                ):
                    raise Exception("WTF")
                ifidx_default_phy = ni_default.link_lookup(
                    ifname=connection.config.interface_name,
                )[0]
                ni_default.link(
                    "set",
                    index=ifidx_default_phy,
                    net_ns_fd=network_instance.id,
                )

            ifidx_phy = ni_dl.link_lookup(ifname=connection.config.interface_name)[0]
            ni_dl.flush_addr(index=ifidx_phy, scope=enums.IPRouteScope.GLOBAL.value)
            ni_dl.link(
                "set",
                index=ifidx_phy,
                state="up",
            )

            if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(
                network_instance,
                connection.id,
            )
            for ipv4 in if_ipv4:
                ni_dl.addr(
                    "replace",
                    index=ifidx_phy,
                    address=str(ipv4.ip),
                    prefixlen=ipv4.network.prefixlen,
                )
            # Add the configured IPv6 address to the XFRM interface.
            for ipv6 in if_ipv6:
                ni_dl.addr(
                    "replace",
                    index=ifidx_phy,
                    address=str(ipv6.ip),
                    prefixlen=ipv6.network.prefixlen,
                )

        return connection.config.interface_name

    def delete(
        self,
        network_instance: models.NetworkInstance,
        connection: models.Connection,
    ) -> None:
        """Delete a connection."""
        interface_name = self.intf_name(connection.id)
        # run the commands
        with pyroute2.NetNS(netns=network_instance.id) as ni_dl:
            if not ni_dl.link_lookup(ifname=interface_name):
                return
            ifidx = ni_dl.link_lookup(ifname=interface_name)[0]
            ni_dl.link("set", index=ifidx, net_ns_fd=1)

    def intf_name(self, _: int) -> str:
        """Return the name of the connection interface."""
        return self.interface_name

    def status_summary(
        self,
        network_instance: models.NetworkInstance,
        connection_id: int,
    ) -> dict[str, Any]:
        """Get the connection status."""
        if_name = self.intf_name(connection_id)
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
            "status": output["operstate"],
            "interface-name": if_name,
            "interface-ip": [
                f"{x['local']}/{x['prefixlen']}" for x in output["addr_info"]
            ],
            "remote-addr": None,
        }

        return output_dict
