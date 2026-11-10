"""Code to configure IPSEC connections."""

from __future__ import annotations

import datetime
import json
import logging
import subprocess
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field, field_validator

from vpnc import config
from vpnc.models import connections, enums
from vpnc.models.secret import Secret
from vpnc.network import namespace, state
from vpnc.services import wireguard

if TYPE_CHECKING:
    import vpnc.models.network_instance

logger = logging.getLogger("vpnc")


class ConnectionConfigWireGuard(BaseModel):
    """Defines an IPsec connection data structure."""

    type: Literal[enums.ConnectionType.WIREGUARD] = enums.ConnectionType.WIREGUARD
    # Set a local id for the connection specifically.
    local_port: int = Field(default=51820, ge=0, le=65535)
    remote_addrs: list[IPv4Address | IPv6Address]
    remote_port: int = Field(default=51820, ge=0, le=65535)
    private_key: Secret
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

        with (
            state.netns(network_instance.id) as dl,
            state.netns(config.EXTERNAL_NI) as ext,
        ):
            ni_dl, ni_state = dl.ipr, dl.state
            state.ensure_wireguard(ni_dl, ext.ipr, ni_state, wg)
            state.ensure_link_state(ni_dl, ni_state, wg, up=True)
            state.ensure_addresses(ni_dl, ni_state, wg, [*if_ipv4, *if_ipv6])

        wireguard.generate_config(network_instance)
        # Apply only differences (keeps sessions), also after missed file events or
        # manual changes.
        conf = config.WIREGUARD_CONFIG_DIR.joinpath(f"{wg}.conf")
        result = namespace.run(
            network_instance.id,
            ["/usr/bin/wg", "syncconf", wg, str(conf)],
        )
        if result.returncode:
            logger.error("Syncing %s failed: %s", wg, result.stderr.strip())

        return wg

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        interface_name = self.intf_name(network_instance, connection)
        with state.netns(network_instance.id) as dl:
            state.delete_link(dl.ipr, dl.state, interface_name)

        config_file = config.WIREGUARD_CONFIG_DIR.joinpath(f"{interface_name}.conf")
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

        wg_list = namespace.run(
            network_instance.id,
            ["wg", "show", if_name, "dump"],
        ).stdout.split()
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
