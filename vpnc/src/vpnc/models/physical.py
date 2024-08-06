"""
Code to configure PHYSICAL connections
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from pydantic import BaseModel, field_validator

from ..network import interface
from . import enums, models

logger = logging.getLogger("vpnc")


class ConnectionConfigLocal(BaseModel):
    """
    Defines a local connection data structure
    """

    type: Literal[enums.ConnectionType.PHYSICAL] = enums.ConnectionType.PHYSICAL
    interface_name: str

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type(cls, v: Any):
        return enums.ConnectionType(v)

    def add(
        self,
        network_instance: models.NetworkInstance,
        connection_id: int,
        connection: models.Connection,
    ) -> str:
        """
        Creates a local connection
        """

        if not isinstance(connection.config, models.ConnectionConfigLocal):
            logger.critical(
                "Wrong connection configuration provided for %s",
                network_instance.name,
            )
            raise ValueError

        intf = interface.get(connection.config.interface_name, ns_name="*")

        if not intf:
            logger.warning(
                "Cannot find interface '%s' in any namespace. Skipping connection.",
                connection.config.interface_name,
            )
            raise ValueError

        if_ipv4, if_ipv6 = connection.calculate_ip_addresses(
            network_instance, connection_id
        )
        addresses = if_ipv6 + if_ipv4
        interface.set(
            intf,
            state="up",
            addresses=addresses,
            ns_name=network_instance.name,
        )

        return connection.config.interface_name

    def intf_name(self, _: int):
        """
        Returns the name of the connection interface
        """
        return self.interface_name
