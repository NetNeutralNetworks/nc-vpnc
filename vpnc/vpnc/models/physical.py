"""
Code to configure the local connection
"""

from __future__ import annotations

import logging

from pydantic import BaseModel

from .. import config
from ..network import interface
from . import base_models

logger = logging.getLogger("vpnc")


class ConnectionConfigLocal(BaseModel):
    """
    Defines a local connection data structure
    """

    interface_name: str

    def add(
        self,
        network_instance: base_models.NetworkInstance,
        connection_id: int,
        connection: base_models.Connection,
    ) -> str:
        """
        Creates a local connection
        """

        if not isinstance(connection.config, base_models.ConnectionConfigLocal):
            logger.critical(
                "Wrong connection configuration provided for %s",
                network_instance.name,
            )
            raise ValueError

        intf = interface.get(connection.config.interface_name, ns_name="*")

        if not intf:
            logger.warning(
                "Cannot find interface '%s' in any namespace",
                connection.config.interface_name,
            )
            raise ValueError

        is_downlink = network_instance.type == base_models.NetworkInstanceType.DOWNLINK
        is_hub = config.VPNC_SERVICE_CONFIG.mode == base_models.ServiceMode.HUB
        if_ipv4, if_ipv6 = connection.calculate_ip_addresses(
            connection_id, is_downlink, is_hub
        )
        addresses = if_ipv6 + if_ipv4
        interface.set(
            intf,
            state="up",
            addresses=addresses,
            ns_name=network_instance.name,
        )

        return connection.config.interface_name

    def intf_name(self, connection_id: int):
        """
        Returns the name of the connection interface
        """
        return self.interface_name
