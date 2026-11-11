"""Live state of tenants, network instances and connections, read on request."""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import time
from typing import TYPE_CHECKING, Any, Literal

import vici
from pydantic import BaseModel

from vpnc import config
from vpnc.models import enums, tenant
from vpnc.network import state
from vpnc.services import configuration, wireguard
from vpnc.services.strongswan.monitor import VICI_SOCKET, VICI_TIMEOUT

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# A WireGuard peer without a handshake for this long is down (it renews every
# two minutes while there's traffic, and keepalives cause traffic).
WIREGUARD_TIMEOUT = 180

State = Literal["up", "down", "connecting"]


class ConnectionState(BaseModel):
    """The live state of a connection."""

    id: str
    tenant: str
    network_instance: str
    type: str
    state: State
    interface: str | None
    addresses: list[str]
    remote: str | None
    # Type specific, e.g. IKE state or the last WireGuard handshake.
    details: dict[str, Any]


class Translation(BaseModel):
    """A NAT64 or NPTv6 translation: local (CORE side) to remote prefix."""

    type: Literal["nat64", "nptv6"]
    local: str
    remote: str


class NetworkInstanceState(BaseModel):
    """The live state of a network instance."""

    id: str
    tenant: str
    type: str
    connections_up: int
    connections: int
    nat64_scope: str | None = None
    nptv6_scope: str | None = None
    translations: list[Translation] | None = None


class TenantState(BaseModel):
    """The live state of a tenant."""

    id: str
    name: str
    network_instances: list[str]
    connections_up: int
    connections: int


class Status(BaseModel):
    """An overview of the service."""

    mode: str
    tenants: int
    network_instances: int
    connections_up: int
    connections: int


class BgpNeighbor(BaseModel):
    """A BGP session in CORE."""

    neighbor: str
    hostname: str | None
    remote_as: int | None
    address_family: str
    state: str | None
    uptime: str | None
    prefixes_received: int | None
    prefixes_sent: int | None


def tenant_of(network_instance_id: str) -> str:
    """Return the tenant of a network instance (CORE etc. belong to DEFAULT)."""
    if "-" in network_instance_id:
        return network_instance_id.split("-", 1)[0]
    return config.DEFAULT_TENANT


def network_instances() -> dict[str, NetworkInstance]:
    """Return the configured network instances by id."""
    return {
        ni.id: ni
        for tenant_config in list(config.VPNC_CONFIG_TENANT.values())
        for ni in tenant_config.network_instances.values()
    }


def _ipsec_sas() -> dict[str, dict[str, Any]]:
    """Return the IKE SAs by connection name."""
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(VICI_TIMEOUT)
    try:
        sock.connect(VICI_SOCKET)
        session = vici.Session(sock)
        return {name: sa for item in session.list_sas() for name, sa in item.items()}
    except OSError:
        logger.warning("Reading the IPsec SAs failed.", exc_info=True)
        return {}
    finally:
        sock.close()


def _decode(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, dict):
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


def _ipsec(
    name: str,
    connection: Connection,
    sas: dict[str, dict[str, Any]],
) -> tuple[State, str | None, dict[str, Any]]:
    sa = sas.get(name)
    if sa is None:
        return "down", str(connection.config.remote_addrs[0]), {}
    sa = _decode(sa)
    children = [
        {"name": child.get("name"), "state": child.get("state")}
        for child in sa.get("child-sas", {}).values()
    ]
    details: dict[str, Any] = {
        "ike_state": sa.get("state"),
        "established_seconds": int(sa.get("established", 0)) or None,
        "child_sas": children,
    }
    if sa.get("state") == "ESTABLISHED" and any(
        child["state"] == "INSTALLED" for child in children
    ):
        current: State = "up"
    else:
        current = "connecting"
    return current, sa.get("remote-host"), details


def _wireguard(
    ni: NetworkInstance,
    ifname: str,
) -> tuple[State, str | None, dict[str, Any]]:
    try:
        peer = wireguard.peer_status(ni.id, ifname)
    except Exception:  # noqa: BLE001
        return "down", None, {}
    handshake = peer["last_handshake"]
    age = int(time.time()) - handshake if handshake else None
    details = {"last_handshake_seconds_ago": age}
    current: State = "up" if age is not None and age < WIREGUARD_TIMEOUT else "down"
    return current, peer["endpoint"], details


def connection_states(
    selected: list[NetworkInstance] | None = None,
) -> list[ConnectionState]:
    """Return the live state of the connections of the network instances."""
    selected = list(network_instances().values()) if selected is None else selected
    sas = (
        _ipsec_sas()
        if any(
            c.config.type == enums.ConnectionType.IPSEC
            for ni in selected
            for c in ni.connections.values()
        )
        else {}
    )
    output: list[ConnectionState] = []
    for ni in selected:
        try:
            with state.netns(ni.id) as ns:
                snapshot = ns.state
        except FileNotFoundError:
            snapshot = state.NetnsState(name=ni.id)
        for connection in ni.connections.values():
            name = f"{ni.id}-{connection.id}"
            ifname = connection.intf_name(ni)
            link = snapshot.links.get(ifname) if ifname else None
            addresses = sorted(
                str(a) for a in snapshot.addresses.get(ifname or "", set())
            )
            remote_addrs = getattr(connection.config, "remote_addrs", None)
            remote = str(remote_addrs[0]) if remote_addrs else None
            details: dict[str, Any] = {}
            ctype = connection.config.type
            if ctype == enums.ConnectionType.IPSEC:
                current, remote, details = _ipsec(name, connection, sas)
            elif ctype == enums.ConnectionType.WIREGUARD and link is not None:
                current, endpoint, details = _wireguard(ni, ifname)
                remote = endpoint or remote
            else:
                # SSH (tun has carrier while ssh runs) and physical interfaces.
                current = "up" if link is not None and link.passes_traffic else "down"
            output.append(
                ConnectionState(
                    id=name,
                    tenant=tenant_of(ni.id),
                    network_instance=ni.id,
                    type=ctype.value,
                    state=current,
                    interface=ifname if link is not None else None,
                    addresses=addresses,
                    remote=remote,
                    details=details,
                ),
            )
    return output


def _counts(states: list[ConnectionState]) -> tuple[int, int]:
    return sum(s.state == "up" for s in states), len(states)


def network_instance_states(
    selected: list[NetworkInstance],
    *,
    translations: bool = False,
) -> list[NetworkInstanceState]:
    """Return the live state of network instances."""
    by_ni: dict[str, list[ConnectionState]] = {}
    for s in connection_states(selected):
        by_ni.setdefault(s.network_instance, []).append(s)
    hub = tenant.get_default_tenant().mode == enums.ServiceMode.HUB
    output: list[NetworkInstanceState] = []
    for ni in selected:
        up, total = _counts(by_ni.get(ni.id, []))
        item = NetworkInstanceState(
            id=ni.id,
            tenant=tenant_of(ni.id),
            type=ni.type.value,
            connections_up=up,
            connections=total,
        )
        if hub and ni.type == enums.NetworkInstanceType.DOWNLINK:
            nat64 = configuration.get_network_instance_nat64_scope(ni)
            nptv6 = configuration.get_network_instance_nptv6_scope(ni.id)
            item.nat64_scope = str(nat64) if nat64 else None
            item.nptv6_scope = str(nptv6) if nptv6 else None
            if translations:
                item.translations = _translations(ni.id)
        output.append(item)
    return output


def _translations(ni_id: str) -> list[Translation]:
    """Return the NAT64 and NPTv6 translations as applied (Jool and nftables)."""
    output: list[Translation] = []
    if nat64 := configuration.get_network_instance_nat64_mappings_state(ni_id):
        output.append(
            Translation(type="nat64", local=str(nat64[0]), remote=str(nat64[1])),
        )
    output.extend(
        Translation(type="nptv6", local=str(local), remote=str(remote))
        for local, remote in configuration.get_network_instance_nptv6_mappings_state(
            ni_id,
        )
    )
    return output


def tenant_states(selected: list[str] | None = None) -> list[TenantState]:
    """Return the live state of tenants."""
    tenants = {
        t.id: t
        for t in list(config.VPNC_CONFIG_TENANT.values())
        if selected is None or t.id in selected
    }
    nis = [ni for t in tenants.values() for ni in t.network_instances.values()]
    by_tenant: dict[str, list[ConnectionState]] = {}
    for s in connection_states(nis):
        by_tenant.setdefault(s.tenant, []).append(s)
    output: list[TenantState] = []
    for tenant_id, tenant_config in sorted(tenants.items()):
        up, total = _counts(by_tenant.get(tenant_id, []))
        output.append(
            TenantState(
                id=tenant_id,
                name=tenant_config.name,
                network_instances=sorted(
                    ni.id for ni in tenant_config.network_instances.values()
                ),
                connections_up=up,
                connections=total,
            ),
        )
    return output


def status() -> Status:
    """Return an overview of the service."""
    states = connection_states()
    up, total = _counts(states)
    return Status(
        mode=tenant.get_default_tenant().mode.value,
        tenants=len(config.VPNC_CONFIG_TENANT),
        network_instances=len(network_instances()),
        connections_up=up,
        connections=total,
    )


def bgp_neighbors() -> list[BgpNeighbor]:
    """Return the BGP sessions in CORE (hub mode)."""
    result = subprocess.run(  # noqa: S603
        ["/usr/bin/vtysh", "-c", f"show bgp vrf {config.CORE_NI} summary json"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    output: list[BgpNeighbor] = []
    for family, summary in json.loads(result.stdout or "{}").items():
        for peer, info in summary.get("peers", {}).items():
            output.append(
                BgpNeighbor(
                    neighbor=peer,
                    hostname=info.get("hostname"),
                    remote_as=info.get("remoteAs"),
                    address_family=family,
                    state=info.get("state"),
                    uptime=info.get("peerUptime"),
                    prefixes_received=info.get("pfxRcd"),
                    prefixes_sent=info.get("pfxSnt"),
                ),
            )
    return output
