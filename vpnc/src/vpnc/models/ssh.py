"""Code to configure SSH connections."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field, field_validator

from vpnc import accounts, helpers
from vpnc.models import enums
from vpnc.models.post_quantum import PostQuantumSSH
from vpnc.network import state
from vpnc.services import ssh

if TYPE_CHECKING:
    import vpnc.models.network_instance
    from vpnc.models import connections

logger = logging.getLogger("vpnc")

# Used in a script on the remote side and as an ssh argument: names only.
INTERFACE_PATTERN = r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$"
USERNAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$"
# A public key without its comment, e.g. "ssh-ed25519 AAAA...".
HOST_KEY_PATTERN = r"^[a-z0-9@.-]+ [A-Za-z0-9+/]+={0,2}$"


class ConnectionConfigSSH(BaseModel):
    """Defines an SSH connection data structure."""

    type: Literal[enums.ConnectionType.SSH] = enums.ConnectionType.SSH
    _upper = helpers.upper("type")
    remote_addrs: list[IPv4Address | IPv6Address] = Field(min_length=1)
    # Required. Specifies the remote
    # tunnel identifier to avoid overlap.
    remote_tunnel_id: int
    # Optional interface on the remote side to masquerade out of. The remote
    # side isn't configured by vpnc: only in the script of remote_setup.
    remote_config_interface: str | None = Field(
        default=None,
        pattern=INTERFACE_PATTERN,
    )
    username: str = Field(pattern=USERNAME_PATTERN)
    # The server's public host key (a line of its /etc/ssh/ssh_host_*_key.pub),
    # the only one accepted. Not set, vpnc sets it to the key the server
    # presents when first connecting; delete it to accept a new one.
    host_key: str | None = Field(default=None, pattern=HOST_KEY_PATTERN)
    post_quantum: PostQuantumSSH = Field(default_factory=PostQuantumSSH)

    @field_validator("host_key", mode="before")
    @classmethod
    def _without_comment(cls, v: object) -> object:
        """Take a .pub file's line as it is: the comment isn't part of the key."""
        return " ".join(v.split()[:2]) if isinstance(v, str) else v

    _none_as_default = helpers.none_as_default("post_quantum")

    def add(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create an SSH connection."""
        if network_instance.type != enums.NetworkInstanceType.DOWNLINK:
            err = (
                "Connections of type SSH can only be used in DOWNLINK network instances"
            )
            logger.error(err)
            raise ValueError(err)
        tun = self.intf_name(network_instance, connection)

        with state.netns(network_instance.id) as dl:
            # ssh opens it as its account.
            owner = accounts.user(accounts.SSH).pw_uid
            state.ensure_tun(dl.ipr, dl.state, tun, owner)
            state.ensure_link_state(dl.ipr, dl.state, tun, up=connection.enabled)
            connection.ensure_mtu_and_addresses(network_instance, dl)

        ssh.start(network_instance, connection)
        return tun

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection, with its key and its server's host key."""
        ssh.stop(network_instance, connection)
        connection.delete_interface(network_instance)
        name = connection.name(network_instance)
        ssh.known_hosts(name).unlink(missing_ok=True)
        ssh.delete_key(name)

    def intf_name(
        self,
        _: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return f"tun{connection.id}"
