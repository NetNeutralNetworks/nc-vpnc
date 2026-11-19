"""Code to configure IPSEC connections."""

from __future__ import annotations

import logging
import re
import socket
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from vpnc import config, helpers
from vpnc.models import enums
from vpnc.models.post_quantum import PostQuantumIPsec
from vpnc.models.secret import Secret
from vpnc.network import state
from vpnc.services import charon

if TYPE_CHECKING:
    from collections.abc import Iterable

    import vpnc.models.network_instance
    from vpnc.models import connections, tenant

logger = logging.getLogger("vpnc")

# ML-KEM and additional key exchanges are set with post_quantum only.
PQ_KEYWORD_RE = re.compile(r"mlkem|(^|-)ke\d_", re.IGNORECASE)
# A classical key exchange: hybrid ML-KEM needs one in each proposal.
CLASSICAL_KE_RE = re.compile(
    r"(^|-)(ecp\d+(bp)?|x25519|x448|curve25519|curve448|modp\d+(s\d+)?)(-|$)",
    re.IGNORECASE,
)


# A PSK of fewer characters can be guessed: whoever answers a connection as its
# peer gets what's needed to try PSKs offline.
PSK_MIN_LENGTH = 32
# Algorithms RFC 8221 and RFC 8247 say not to use: DES, 3DES, no encryption,
# MD5, and Diffie-Hellman groups under 2048 bits.
WEAK_ALGORITHM_RE = re.compile(
    r"(3?des|null|blowfish\d*|cast128|(prf)?md5(_128)?|modp(768|1024|1536)(s\d+)?)",
    re.IGNORECASE,
)


class Initiation(Enum):
    """Define if the VPN connection automatically starts."""

    INITIATOR = "START"
    RESPONDER = "NONE"


class TrafficSelectors(BaseModel):
    """Define a traffic selector data structure."""

    local: set[IPv4Network | IPv6Network] = Field(default_factory=set)
    remote: set[IPv4Network | IPv6Network] = Field(default_factory=set)

    _none_as_default = helpers.none_as_default("local", "remote")


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
    ipsec_proposal: str = "aes256gcm16-ecp384"
    ipsec_lifetime: int = 3600
    initiation: Initiation = Initiation.INITIATOR
    psk: Secret
    post_quantum: PostQuantumIPsec = Field(default_factory=PostQuantumIPsec)
    traffic_selectors: TrafficSelectors = Field(default_factory=TrafficSelectors)

    @field_validator("ike_version", mode="before")
    @classmethod
    def coerce_ike_version(cls, v: str | int) -> int | str:
        """Coerces strings to integers."""
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return v

    @field_validator("ike_proposal", "ipsec_proposal")
    @classmethod
    def no_pq_keywords(cls, v: str) -> str:
        """Hand-written ML-KEM (also without hybrid) and keN_ aren't allowed."""
        if PQ_KEYWORD_RE.search(v):
            msg = "set ML-KEM with post_quantum, not in the proposal"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def check_post_quantum(self) -> ConnectionConfigIPsec:
        """Hybrid ML-KEM needs IKEv2 and a classical key exchange to add to."""
        if not self.post_quantum.enabled:
            return self
        if self.ike_version != 2:  # noqa: PLR2004
            msg = "post_quantum needs IKEv2"
            raise ValueError(msg)
        for name in ("ike_proposal", "ipsec_proposal"):
            if not CLASSICAL_KE_RE.search(getattr(self, name)):
                msg = f"post_quantum needs a classical key exchange in {name}"
                raise ValueError(msg)
        return self

    _none_as_default = helpers.none_as_default("traffic_selectors", "post_quantum")
    _upper = helpers.upper("type", "initiation")

    def weaknesses(self) -> dict[str, tuple[str, object]]:
        """Return what's weak about the connection's cryptography.

        By what it is (e.g. SHORT_PSK): what to tell, and the setting it's about.
        A commit that adds one, or changes its setting, must allow it.
        """
        found: dict[str, tuple[str, object]] = {}
        psk = self.psk.get_secret_value()
        if len(psk) < PSK_MIN_LENGTH:
            found["SHORT_PSK"] = (
                f"the PSK has fewer than {PSK_MIN_LENGTH} characters"
                " (vpnctl generate psk makes one)",
                psk,
            )
        if self.ike_version == 1:
            found["IKEV1"] = ("IKEv1", 1)
        proposals = (self.ike_proposal, self.ipsec_proposal)
        weak = sorted(
            {
                algorithm.lower()
                for proposal in proposals
                for algorithm in proposal.split("-")
                if WEAK_ALGORITHM_RE.fullmatch(algorithm)
            },
        )
        if weak:
            found["WEAK_PROPOSAL"] = (f"weak algorithms: {', '.join(weak)}", proposals)
        return found

    def add(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Create an XFRM interface."""
        xfrm = self.intf_name(network_instance, connection)
        vpn_id = self.if_id(network_instance, connection)

        with (
            state.netns(network_instance.id) as dl,
            state.netns(config.EXTERNAL_NI) as ext,
        ):
            state.ensure_xfrm(dl.ipr, ext.ipr, dl.state, xfrm, vpn_id)
            connection.ensure_mtu_and_addresses(network_instance, dl)

        return xfrm

    def delete(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> None:
        """Delete a connection."""
        connection.delete_interface(network_instance)

        name = connection.name(network_instance)
        try:
            with charon.session() as vcs:
                charon.terminate(vcs, ike=name)
        except OSError:
            logger.warning("Terminating the SAs of %s failed.", name, exc_info=True)

    def intf_name(
        self,
        _: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str:
        """Return the name of the connection interface."""
        return helpers.xfrm_interface_name(connection.id)

    def if_id(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> int:
        """Return the XFRM if_id, which the interface and charon's SAs share.

        E.g. 0xC0001001 for C0001-00-1, and 0x10000001 for CORE-1.
        """
        base = 0x10000000
        if network_instance.type == enums.NetworkInstanceType.DOWNLINK:
            base = int(network_instance.id.replace("-", ""), 16) << 4
        return base + connection.id

    def ppk_id(
        self,
        network_instance: vpnc.models.network_instance.NetworkInstance,
        connection: connections.Connection,
    ) -> str | None:
        """Return the PPK id: as configured, or the name and hostname by default.

        E.g. C0001-00-0-hub00. None without a PPK.
        """
        if not (self.post_quantum.enabled and self.post_quantum.ppk):
            return None
        return self.post_quantum.ppk.id or (
            f"{connection.name(network_instance)}-{socket.gethostname()}"
        )


def ppk_id_users(tenants: Iterable[tenant.Tenant]) -> dict[str, list[str]]:
    """Return per PPK id the IPsec connections using it, sorted.

    charon selects a PPK by the id the peer sends, so an id must be unique.
    """
    users: dict[str, list[str]] = {}
    for tenant_config in tenants:
        for network_instance in tenant_config.network_instances.values():
            for connection in network_instance.connections.values():
                cfg = connection.config
                if cfg.type == enums.ConnectionType.IPSEC and (
                    ppk_id := cfg.ppk_id(network_instance, connection)
                ):
                    users.setdefault(ppk_id, []).append(
                        connection.name(network_instance),
                    )
    return {ppk_id: sorted(names) for ppk_id, names in users.items()}
