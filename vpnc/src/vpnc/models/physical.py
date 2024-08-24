"""Code to configure PHYSICAL connections."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Literal

from pydantic import BaseModel, field_validator

from vpnc.models import enums, models
from vpnc.network import interface

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

        intf = interface.get(connection.config.interface_name, ns_name="*")

        if not intf:
            logger.warning(
                "Cannot find interface '%s' in any namespace. Skipping connection.",
                connection.config.interface_name,
            )
            raise ValueError

        if_ipv4, if_ipv6 = connection.calculate_ip_addresses(
            network_instance,
            connection.id,
        )
        addresses = if_ipv6 + if_ipv4
        interface.set_(
            intf,
            state="up",
            addresses=addresses,
            ns_name=network_instance.id,
        )

        return connection.config.interface_name

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
