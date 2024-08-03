from __future__ import annotations

import logging
import subprocess
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .. import config
from . import base_enums, base_models

logger = logging.getLogger("vpnc")


class Initiation(Enum):
    """
    Defines if the VPN connection automatically starts
    """

    INITIATOR = "start"
    RESPONDER = "none"


class TrafficSelectors(BaseModel):
    """
    Defines a traffic selector data structure
    """

    local: set[IPv4Network | IPv6Network] = Field(default_factory=set)
    remote: set[IPv4Network | IPv6Network] = Field(default_factory=set)

    @field_validator("local", "remote", mode="before")
    @classmethod
    def _coerce_traffic_selectors(cls, v: Any):
        if v is None:
            return set()
        return v


class ConnectionConfigIPsec(BaseModel):
    """
    Defines an IPsec connection data structure
    """

    type: Literal[base_enums.ConnectionType.IPSEC] = base_enums.ConnectionType.IPSEC
    # Set a local id for the connection specifically.
    local_id: str | None = None
    remote_peer_ip: IPv4Address | IPv6Address
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
    def _coerce_type(cls, v: Any):
        return base_enums.ConnectionType(v)

    @field_validator("ike_version", mode="before")
    @classmethod
    def coerce_ike_version(cls, v: Any):
        """
        Coerces strings to integers
        """
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return v

    @field_validator("traffic_selectors", mode="before")
    @classmethod
    def _coerce_traffic_selectors(cls, v: Any):
        if v is None:
            return TrafficSelectors(local=set(), remote=set())
        return v

    def add(
        self,
        network_instance: base_models.NetworkInstance,
        connection_id: int,
        connection: base_models.Connection,
    ) -> str:
        """
        Creates an XFRM interface
        """
        xfrm = self.intf_name(connection_id)
        vpn_id = int(f"0x1000000{connection_id}", 16)
        if network_instance.type == base_enums.NetworkInstanceType.DOWNLINK:
            vpn_id = int(
                f"0x{network_instance.name.replace('-', '')}{connection_id}", 16
            )

        is_downlink = network_instance.type == base_enums.NetworkInstanceType.DOWNLINK
        is_hub = config.VPNC_SERVICE_CONFIG.mode == base_enums.ServiceMode.HUB
        if_ipv4, if_ipv6 = connection.calculate_ip_addresses(
            network_instance, connection_id, is_downlink, is_hub
        )

        # TODO: check if it is OK to always attach to the same external interface.
        external_if_name = (
            config.VPNC_SERVICE_CONFIG.network_instances[config.EXTERNAL_NI]
            .connections[0]
            .config.intf_name(0)
        )
        cmds = f"""
            # configure XFRM interfaces
            ip -n {config.EXTERNAL_NI} link add {xfrm} type xfrm dev {external_if_name} if_id {hex(vpn_id)}
            ip -n {config.EXTERNAL_NI} link set {xfrm} netns {network_instance.name}
        """
        sp = subprocess.run(
            cmds,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        logger.info(sp.args)
        logger.info(sp.stdout.decode())

        sp = subprocess.run(
            f"""
            ip -n {network_instance.name} link set dev {xfrm} up
            ip -n {network_instance.name} -4 address flush dev {xfrm} scope global
            ip -n {network_instance.name} -6 address flush dev {xfrm} scope global
            """,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        logger.info(sp.args)
        logger.info(sp.stdout.decode())

        cmds = ""
        for ipv4 in if_ipv4:
            cmds += f"ip -n {network_instance.name} address add {ipv4} dev {xfrm}\n"
        # Add the configured IPv6 address to the XFRM interface.
        for ipv6 in if_ipv6:
            cmds += f"ip -n {network_instance.name} address add {ipv6} dev {xfrm}\n"

        sp = subprocess.run(
            cmds,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            check=False,
        )
        logger.info(sp.args)
        logger.info(sp.stdout.decode())

        return xfrm

    def intf_name(self, connection_id: int):
        """
        Returns the name of the connection interface
        """
        return f"xfrm{connection_id}"
