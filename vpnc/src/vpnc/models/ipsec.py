"""Code to configure IPSEC connections."""

from __future__ import annotations

import json
import logging
import subprocess
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

import pyroute2
import vici
from pydantic import BaseModel, Field, field_validator

from vpnc import config
from vpnc.models import enums, models

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

logger = logging.getLogger("vpnc")


class Initiation(Enum):
    """Define if the VPN connection automatically starts."""

    INITIATOR = "start"
    RESPONDER = "none"


class TrafficSelectors(BaseModel):
    """Define a traffic selector data structure."""

    local: set[IPv4Network | IPv6Network] = Field(default_factory=set)
    remote: set[IPv4Network | IPv6Network] = Field(default_factory=set)

    @field_validator("local", "remote", mode="before")
    @classmethod
    def _coerce_traffic_selectors(
        cls,
        v: set[IPv4Network | IPv6Network] | None,
    ) -> set[IPv4Network | IPv6Network]:
        if v is None:
            return set()
        return v


class ConnectionConfigIPsec(BaseModel):
    """Defines an IPsec connection data structure."""

    type: Literal[enums.ConnectionType.IPSEC] = enums.ConnectionType.IPSEC
    # Set a local id for the connection specifically.
    local_id: str | None = None
    remote_addrs: list[IPv4Address | IPv6Address]
    remote_id: str | None = None
    ike_version: Literal[1, 2] = 2
    ike_proposal: str = "aes256gcm16-prfsha384-ecp384"
    ike_lifetime: int = 86400
    ipsec_proposal: str = "aes256gcm16-prfsha384-ecp384"
    ipsec_lifetime: int = 3600
    initiation: Initiation = Initiation.INITIATOR
    psk: str
    traffic_selectors: TrafficSelectors = Field(default_factory=TrafficSelectors)

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type(cls, v: str) -> enums.ConnectionType:
        return enums.ConnectionType(v)

    @field_validator("ike_version", mode="before")
    @classmethod
    def coerce_ike_version(cls, v: str | int) -> int | str:
        """Coerces strings to integers."""
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return v

    @field_validator("traffic_selectors", mode="before")
    @classmethod
    def _coerce_traffic_selectors(cls, v: TrafficSelectors | None) -> TrafficSelectors:
        if v is None:
            return TrafficSelectors(local=set(), remote=set())
        return v

    def add(
        self,
        network_instance: models.NetworkInstance,
        connection: models.Connection,
    ) -> str:
        """Create an XFRM interface."""
        xfrm = self.intf_name(connection.id)
        vpn_id = int(f"0x1000000{connection.id}", 16)
        if network_instance.type == enums.NetworkInstanceType.DOWNLINK:
            vpn_id = int(
                f"0x{network_instance.id.replace('-', '')}{connection.id}",
                16,
            )

        if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(
            network_instance,
            connection.id,
        )

        with pyroute2.NetNS(netns=network_instance.id) as ni_dl, pyroute2.NetNS(
            netns=config.EXTERNAL_NI,
        ) as ni_ext:
            if not ni_dl.link_lookup(ifname=xfrm):
                ni_ext.link(
                    "add",
                    ifname=xfrm,
                    kind="xfrm",
                    xfrm_if_id=vpn_id,
                )
                ifid_ext_xfrm = ni_ext.link_lookup(ifname=xfrm)[0]
                ni_ext.link(
                    "set",
                    index=ifid_ext_xfrm,
                    net_ns_fd=network_instance.id,
                )

            ifidx_xfrm = ni_dl.link_lookup(ifname=xfrm)[0]
            ni_dl.flush_addr(index=ifidx_xfrm, scope=enums.IPRouteScope.GLOBAL.value)

            for ipv4 in if_ipv4:
                ni_dl.addr(
                    "replace",
                    index=ifidx_xfrm,
                    address=str(ipv4.ip),
                    prefixlen=ipv4.network.prefixlen,
                )
            # Add the configured IPv6 address to the XFRM interface.
            for ipv6 in if_ipv6:
                ni_dl.addr(
                    "replace",
                    index=ifidx_xfrm,
                    address=str(ipv6.ip),
                    prefixlen=ipv6.network.prefixlen,
                )

        return xfrm

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
            ni_dl.link("del", index=ifidx)

        vcs = vici.Session()
        for i in vcs.terminate(
            {"ike": f"{network_instance.id}-{connection.id}".encode()},
        ):
            logger.info(i)

    def intf_name(self, connection_id: int) -> str:
        """Return the name of the connection interface."""
        return f"xfrm{connection_id}"

    def status_summary(
        self,
        network_instance: models.NetworkInstance,
        connection_id: int,
    ) -> dict[str, Any]:
        """Get the connection status."""
        vcs = vici.Session()
        sa: dict[str, Any] = next(
            iter(vcs.list_sas({"ike": f"{network_instance.id}-{connection_id}"})),
        )

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

        status: str = sa[f"{network_instance.id}-{connection_id}"]["state"].decode()
        remote_addr: str = sa[f"{network_instance.id}-{connection_id}"][
            "remote-host"
        ].decode()
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
            "remote-addr": remote_addr,
        }

        return output_dict
