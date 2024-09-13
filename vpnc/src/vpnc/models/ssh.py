"""Code to configure SSH connections."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import TYPE_CHECKING, Any, Literal

import pyroute2
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

        if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(
            network_instance,
            connection.id,
        )

        with pyroute2.NetNS(netns=network_instance.id) as ni_dl:
            if not ni_dl.link_lookup(ifname=tun):
                ni_dl.link("add", ifname=tun, kind="tuntap", mode="tun")
            ifidx: int = ni_dl.link_lookup(ifname=tun)[0]
            ni_dl.link("set", index=ifidx, state="up")
            ni_dl.flush_addr(index=ifidx, scope=enums.IPRouteScope.GLOBAL.value)

            for ipv4 in if_ipv4:
                ni_dl.addr(
                    "replace",
                    index=ifidx,
                    address=str(ipv4.ip),
                    prefixlen=ipv4.network.prefixlen,
                )
            # Add the configured IPv6 address to the XFRM interface.
            for ipv6 in if_ipv6:
                ni_dl.addr(
                    "replace",
                    index=ifidx,
                    address=str(ipv6.ip),
                    prefixlen=ipv6.network.prefixlen,
                )

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
        with pyroute2.NetNS(netns=network_instance.id) as ni_dl:
            if not ni_dl.link_lookup(ifname=interface_name):
                return
            ifidx = ni_dl.link_lookup(ifname=interface_name)[0]
            ni_dl.link("del", index=ifidx)

    def intf_name(self, connection_id: int) -> str:
        """Return the name of the connection interface."""
        return f"tun{connection_id}"

    def status_summary(
        self,
        network_instance: models.NetworkInstance,
        connection_id: int,
    ) -> dict[str, Any]:
        """Get the connection status."""
        connection_name = f"{network_instance.id}-{connection_id}"
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
