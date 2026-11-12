"""Live state of tenants, network instances and connections, read on request."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import socket
import subprocess
import time
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any, Literal

import vici
from pydantic import BaseModel

import vpnc
from vpnc import config, shared
from vpnc.models import enums, tenant
from vpnc.network import namespace, state
from vpnc.api import config_files
from vpnc.services import configuration, ssh, vpncmangle, wireguard
from vpnc.services.charon import VICI_SOCKET, VICI_TIMEOUT

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# A WireGuard peer without a handshake for this long is down (it renews every
# two minutes while there's traffic, and keepalives cause traffic).
WIREGUARD_TIMEOUT = 180

IPAddress = IPv4Address | IPv6Address

# Stopped: through the API, until vpnc restarts.
State = Literal["up", "down", "connecting", "stopped"]


class Counters(BaseModel):
    """Traffic through a connection's interface since it was created."""

    rx_bytes: int
    rx_packets: int
    rx_errors: int
    rx_dropped: int
    tx_bytes: int
    tx_packets: int
    tx_errors: int
    tx_dropped: int


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
    # Only when asked for.
    counters: Counters | None = None


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


class VpncmangleState(BaseModel):
    """vpncmangle, which rewrites DNS answers (hub mode)."""

    running: bool
    # DNS64 and DNS66 translations over all network instances.
    translations: int


class Status(BaseModel):
    """An overview of the service."""

    mode: str
    tenants: int
    network_instances: int
    connections_up: int
    connections: int
    vpncmangle: VpncmangleState | None
    # Service settings that only apply after vpnc restarts.
    restart_needed: list[str]


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
        # Changes when the IKE SA is set up again.
        "ike_id": int(sa.get("uniqueid", 0)) or None,
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


def _counters(ni_id: str) -> dict[str, Counters]:
    """Return the traffic counters of a network instance's interfaces."""
    try:
        result = namespace.run(ni_id, ["/usr/sbin/ip", "-j", "-s", "link"])
    except FileNotFoundError:
        return {}
    output: dict[str, Counters] = {}
    for link in json.loads(result.stdout or "[]"):
        stats = link.get("stats64") or {}
        rx, tx = stats.get("rx") or {}, stats.get("tx") or {}
        output[link["ifname"]] = Counters(
            **{
                f"{direction}_{key}": counters.get(key, 0)
                for direction, counters in (("rx", rx), ("tx", tx))
                for key in ("bytes", "packets", "errors", "dropped")
            },
        )
    return output


def _snapshot(ni_id: str) -> state.NetnsState:
    """Read the links and addresses of a network instance (not its routes)."""
    try:
        return state.NetnsState.read(ni_id, routes=False)
    except FileNotFoundError:
        return state.NetnsState(name=ni_id)


def connection_states(
    selected: list[NetworkInstance] | None = None,
    *,
    counters: bool = False,
    interfaces: bool = True,
) -> list[ConnectionState]:
    """Return the live state of the connections of the network instances.

    Without interfaces, network instances with only IPsec connections aren't read:
    their state comes from the SAs. Enough to count connections that are up.
    """
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
        if interfaces or any(
            c.config.type != enums.ConnectionType.IPSEC for c in ni.connections.values()
        ):
            snapshot = _snapshot(ni.id)
        else:
            snapshot = state.NetnsState(name=ni.id)
        ni_counters = _counters(ni.id) if counters else {}
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
                if ctype == enums.ConnectionType.SSH:
                    details = _ssh(name)
            if name in shared.STOPPED_CONNECTIONS:
                current = "stopped"
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
                    counters=ni_counters.get(ifname or ""),
                ),
            )
    return output


def _ssh(name: str) -> dict[str, Any]:
    tunnel = ssh.SSH_TUNNELS.get(name)
    started = tunnel.started if tunnel is not None else None
    return {"uptime_seconds": int(time.time() - started) if started else None}


def _counts(states: list[ConnectionState]) -> tuple[int, int]:
    return sum(s.state == "up" for s in states), len(states)


def network_instance_states(
    selected: list[NetworkInstance],
    *,
    translations: bool = False,
) -> list[NetworkInstanceState]:
    """Return the live state of network instances."""
    by_ni: dict[str, list[ConnectionState]] = {}
    for s in connection_states(selected, interfaces=False):
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
    for s in connection_states(nis, interfaces=False):
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
    states = connection_states(interfaces=False)
    up, total = _counts(states)
    return Status(
        mode=tenant.get_default_tenant().mode.value,
        tenants=len(config.VPNC_CONFIG_TENANT),
        network_instances=len(network_instances()),
        connections_up=up,
        connections=total,
        vpncmangle=_vpncmangle(),
        restart_needed=config_files.restart_needed(),
    )


def _vpncmangle() -> VpncmangleState | None:
    if tenant.get_default_tenant().mode != enums.ServiceMode.HUB:
        return None
    process = vpncmangle.PROCESS
    try:
        translations = json.loads(vpncmangle.CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        translations = {}
    return VpncmangleState(
        running=process is not None and process.poll() is None,
        translations=sum(
            len(ni.get("dns64", [])) + len(ni.get("dns66", []))
            for ni in translations.values()
        ),
    )


class BgpAddressFamily(BaseModel):
    """A BGP session's prefixes in an address family."""

    family: str
    accepted: int | None
    sent: int | None


class BgpNeighborDetail(BgpNeighbor):
    """A BGP session in CORE, in detail."""

    local_as: int | None
    connections_established: int | None
    connections_dropped: int | None
    last_reset: str | None
    hold_time_seconds: int | None
    keepalive_seconds: int | None
    bfd: str | None
    address_families: list[BgpAddressFamily]


class BgpRoute(BaseModel):
    """A BGP path to a prefix."""

    prefix: str
    next_hops: list[str]
    as_path: str
    best: bool
    valid: bool
    local_pref: int | None
    metric: int | None
    # The neighbor (hostname if known) it was learned from; None: local.
    learned_from: str | None


def vtysh(command: str) -> Any:  # noqa: ANN401
    """Run a vtysh show command with JSON output and return the decoded output."""
    try:
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/vtysh", "-c", f"{command} json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return json.loads(result.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as err:
        detail = "FRR doesn't answer."
        raise config_files.ConfigError(503, "Service unavailable", detail) from err


def bgp_neighbors() -> list[BgpNeighbor]:
    """Return the BGP sessions in CORE (hub mode)."""
    output: list[BgpNeighbor] = []
    for family, summary in vtysh(f"show bgp vrf {config.CORE_NI} summary").items():
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


def bgp_neighbor(neighbor: IPAddress) -> BgpNeighborDetail | None:
    """Return a BGP session in CORE in detail; None if it doesn't exist."""
    data = vtysh(f"show bgp vrf {config.CORE_NI} neighbors {neighbor}")
    if not (info := data.get(str(neighbor))):
        return None
    families = [
        BgpAddressFamily(
            family=family,
            accepted=af.get("acceptedPrefixCounter"),
            sent=af.get("sentPrefixCounter"),
        )
        for family, af in (info.get("addressFamilyInfo") or {}).items()
    ]
    hold = info.get("bgpTimerHoldTimeMsecs")
    keepalive = info.get("bgpTimerKeepAliveIntervalMsecs")
    return BgpNeighborDetail(
        neighbor=str(neighbor),
        hostname=info.get("hostname"),
        remote_as=info.get("remoteAs"),
        local_as=info.get("localAs"),
        address_family=", ".join(f.family for f in families),
        state=info.get("bgpState"),
        uptime=info.get("bgpTimerUpString"),
        prefixes_received=sum(f.accepted or 0 for f in families),
        prefixes_sent=sum(f.sent or 0 for f in families),
        connections_established=info.get("connectionsEstablished"),
        connections_dropped=info.get("connectionsDropped"),
        last_reset=info.get("lastResetDueTo"),
        hold_time_seconds=hold // 1000 if hold is not None else None,
        keepalive_seconds=keepalive // 1000 if keepalive is not None else None,
        bfd=(info.get("peerBfdInfo") or {}).get("status"),
        address_families=families,
    )


FAMILIES = ("ipv4 unicast", "ipv6 unicast")


def bgp_routes() -> list[BgpRoute]:
    """Return the BGP table of CORE: every path to every prefix."""
    output: list[BgpRoute] = []
    for family in FAMILIES:
        data = vtysh(f"show bgp vrf {config.CORE_NI} {family}")
        for prefix, paths in (data.get("routes") or {}).items():
            for path in paths:
                hops = path.get("nexthops") or []
                peer = path.get("peerId")
                from_peer = peer if peer and peer != "(unspec)" else None
                output.append(
                    BgpRoute(
                        prefix=prefix,
                        next_hops=[h["ip"] for h in hops if h.get("ip")],
                        as_path=path.get("path", ""),
                        best=bool(path.get("bestpath")),
                        valid=bool(path.get("valid")),
                        local_pref=path.get("locPrf"),
                        metric=path.get("metric"),
                        learned_from=(
                            hops[0].get("hostname", from_peer)
                            if from_peer and hops
                            else from_peer
                        ),
                    ),
                )
    return output


def bgp_neighbor_routes(
    neighbor: IPAddress,
    direction: Literal["received", "advertised"],
) -> list[BgpRoute]:
    """Return the routes received from (before policy) or advertised to a neighbor."""
    output: list[BgpRoute] = []
    key = f"{direction}Routes"
    for family in FAMILIES:
        data = vtysh(
            f"show bgp vrf {config.CORE_NI} {family} neighbors {neighbor} "
            f"{direction}-routes",
        )
        for prefix, route in (data.get(key) or {}).items():
            hop = route.get("nextHopGlobal") or route.get("nextHop")
            output.append(
                BgpRoute(
                    prefix=prefix,
                    next_hops=[hop] if hop else [],
                    as_path=route.get("path", ""),
                    best=bool(route.get("best")),
                    valid=bool(route.get("valid")),
                    local_pref=route.get("locPrf"),
                    metric=route.get("metric"),
                    learned_from=str(neighbor) if direction == "received" else None,
                ),
            )
    return output


class Version(BaseModel):
    """The versions of vpnc and the software it runs."""

    vpnc: str
    kernel: str
    strongswan: str | None
    frr: str | None


def version() -> Version:
    """Return the versions of vpnc, the kernel, strongSwan and FRR (hub mode)."""
    strongswan = None
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(VICI_TIMEOUT)
    try:
        sock.connect(VICI_SOCKET)
        strongswan = _decode(vici.Session(sock).version()).get("version")
    except OSError:
        logger.warning("Reading the strongSwan version failed.", exc_info=True)
    finally:
        sock.close()
    frr = None
    if tenant.get_default_tenant().mode == enums.ServiceMode.HUB:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            result = subprocess.run(  # noqa: S603
                ["/usr/bin/vtysh", "-c", "show version"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            if match := re.search(r"FRRouting (\S+)", result.stdout):
                frr = match[1]
    return Version(
        vpnc=vpnc.__version__,
        kernel=os.uname().release,
        strongswan=strongswan,
        frr=frr,
    )
