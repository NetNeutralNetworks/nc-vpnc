"""Code to configure IPSEC connections."""

from __future__ import annotations

import datetime
import json
import logging
import subprocess
from typing import TYPE_CHECKING, Any, Literal

import pyroute2
from pydantic import BaseModel, Field, field_validator

from vpnc import config
from vpnc.models import connections, enums
from vpnc.services import wireguard

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

    import vpnc.models.network_instance

logger = logging.getLogger("vpnc")


class ConnectionConfigWireGuard(BaseModel):
    """Defines an IPsec connection data structure."""

    type: Literal[enums.ConnectionType.WIREGUARD] = enums.ConnectionType.WIREGUARD
    # Set a local id for the connection specifically.
    local_port: int = Field(default=51820, ge=0, le=65535)
    remote_addrs: list[IPv4Address | IPv6Address]
    remote_port: int = Field(default=51820, ge=0, le=65535)
    private_key: str
    public_key: str

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type(cls, v: str) -> enums.ConnectionType:
        return enums.ConnectionType(v)

    def add(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create an XFRM interface."""
        wg = self.intf_name(network_instance, connection)

        if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(
            network_instance,
        )

        with pyroute2.NetNS(netns=network_instance.id) as ni_dl, pyroute2.NetNS(
            netns=config.EXTERNAL_NI,
        ) as ni_ext:
            if not ni_dl.link_lookup(ifname=wg):
                ni_ext.link(
                    "add",
                    ifname=wg,
                    kind="wireguard",
                )
                ifid_ext_wg = ni_ext.link_lookup(ifname=wg)[0]
                ni_ext.link(
                    "set",
                    index=ifid_ext_wg,
                    net_ns_fd=network_instance.id,
                )

            ifidx_wg = ni_dl.link_lookup(ifname=wg)[0]
            ni_dl.flush_addr(index=ifidx_wg, scope=enums.IPRouteScope.GLOBAL.value)

            ni_dl.link(
                "set",
                index=ifidx_wg,
                state="up",
            )

            for ipv4 in if_ipv4:
                ni_dl.addr(
                    "replace",
                    index=ifidx_wg,
                    address=str(ipv4.ip),
                    prefixlen=ipv4.network.prefixlen,
                )
            # Add the configured IPv6 address to the XFRM interface.
            for ipv6 in if_ipv6:
                ni_dl.addr(
                    "replace",
                    index=ifidx_wg,
                    address=str(ipv6.ip),
                    prefixlen=ipv6.network.prefixlen,
                )

        wireguard.generate_config(network_instance)

        return wg

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        interface_name = self.intf_name(network_instance, connection)
        # run the commands
        with pyroute2.NetNS(netns=network_instance.id) as ni_dl:
            if not ni_dl.link_lookup(ifname=interface_name):
                return
            ifidx = ni_dl.link_lookup(ifname=interface_name)[0]
            ni_dl.link("del", index=ifidx)

        config_file = config.WIREGUARD_CONFIG_DIR.joinpath(
            f"wg-{network_instance.id}-{connection.id}",
        )

        config_file.unlink(missing_ok=True)

    def intf_name(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return f"wg-{network_instance.id}-{connection.id}"

    def status_summary(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> dict[str, Any]:
        """Get the connection status."""
        if_name = self.intf_name(network_instance, connection)
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

        proc = pyroute2.NSPopen(
            network_instance.id,
            ["wg", "show", if_name, "dump"],
            stdout=subprocess.PIPE,
        )
        wg_output, _ = proc.communicate()
        proc.release()
        wg_list = wg_output.split()
        (
            priv,
            pub,
            local_port,
            _,
            rpub,
            _,
            remote_addr,
            allowed_ips,
            last_handshake,
            transfer,
            received,
            keepalive,
        ) = wg_list
        last_handshake_obj = datetime.datetime.fromtimestamp(int(last_handshake))
        now = datetime.datetime.now() - datetime.timedelta(minutes=2)
        output_dict: dict[str, Any] = {
            "tenant": f"{network_instance.id.split('-')[0]}",
            "network-instance": network_instance.id,
            "connection": connection.id,
            "type": self.type.name,
            "status": "ACTIVE" if last_handshake_obj >= now else "INACTIVE",
            "interface-name": if_name,
            "interface-ip": [
                f"{x['local']}/{x['prefixlen']}" for x in output["addr_info"]
            ],
            "remote-addr": remote_addr,
        }

        return output_dict
