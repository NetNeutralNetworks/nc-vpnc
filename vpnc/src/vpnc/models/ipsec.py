"""Code to configure IPSEC connections."""

from __future__ import annotations

import json
import logging
import subprocess
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING, Any, Literal

import vici
import vici.exception
from pydantic import BaseModel, Field, field_validator

from vpnc import config
from vpnc.models import connections, enums
from vpnc.models.secret import Secret
from vpnc.network import state
from vpnc.services import charon

if TYPE_CHECKING:
    import vpnc.models.network_instance

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
    remote_addrs: list[IPv4Address | IPv6Address] = Field(min_length=1)
    remote_id: str | None = None
    ike_version: Literal[1, 2] = 2
    ike_proposal: str = "aes256gcm16-prfsha384-ecp384"
    ike_lifetime: int = 86400
    ipsec_proposal: str = "aes256gcm16-prfsha384-ecp384"
    ipsec_lifetime: int = 3600
    initiation: Initiation = Initiation.INITIATOR
    psk: Secret
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
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create an XFRM interface."""
        xfrm = self.intf_name(network_instance, connection)
        vpn_id = int(f"0x1000000{connection.id}", 16)
        if network_instance.type == enums.NetworkInstanceType.DOWNLINK:
            vpn_id = int(
                f"0x{network_instance.id.replace('-', '')}{connection.id}",
                16,
            )

        if_ipv4, if_ipv6 = connection.calc_interface_ip_addresses(
            network_instance,
        )

        with (
            state.netns(network_instance.id) as dl,
            state.netns(config.EXTERNAL_NI) as ext,
        ):
            ni_dl, ni_state = dl.ipr, dl.state
            state.ensure_xfrm(ni_dl, ext.ipr, ni_state, xfrm, vpn_id)
            state.ensure_addresses(ni_dl, ni_state, xfrm, [*if_ipv4, *if_ipv6])

        return xfrm

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        interface_name = self.intf_name(network_instance, connection)
        with state.netns(network_instance.id) as dl:
            state.delete_link(dl.ipr, dl.state, interface_name)

        name = f"{network_instance.id}-{connection.id}"
        try:
            with charon.session() as vcs:
                # Don't wait for an unreachable peer to confirm.
                for i in vcs.terminate({"ike": name.encode(), "timeout": b"-1"}):
                    logger.info(i)
        except (
            OSError,
            vici.exception.SessionException,
            vici.exception.CommandException,
        ):
            logger.warning("Terminating the SAs of %s failed.", name, exc_info=True)

    def intf_name(
        self,
        _: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return f"xfrm{connection.id}"

    def status_summary(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> dict[str, Any]:
        """Get the connection status."""
        vcs = vici.Session()
        sa: dict[str, Any] = next(
            iter(vcs.list_sas({"ike": f"{network_instance.id}-{connection.id}"})),
        )

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

        status: str = sa[f"{network_instance.id}-{connection.id}"]["state"].decode()
        remote_addr: str = sa[f"{network_instance.id}-{connection.id}"][
            "remote-host"
        ].decode()
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
            "remote-addr": remote_addr,
        }

        return output_dict
