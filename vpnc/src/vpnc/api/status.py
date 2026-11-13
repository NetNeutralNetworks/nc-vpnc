"""Live state of tenants, network instances and connections, read on request."""

from __future__ import annotations

import contextlib
import dataclasses
import datetime
import json
import logging
import os
import re
import subprocess
import threading
import time
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel

import vpnc
from vpnc import config, helpers
from vpnc.models import enums, tenant
from vpnc.network import state, traffic
from vpnc.api import config_files
from vpnc.services import charon, configuration, vpncmangle, wireguard

if TYPE_CHECKING:
    from vpnc.models.connections import Connection
    from vpnc.models.network_instance import NetworkInstance

logger = logging.getLogger("vpnc")

# A WireGuard peer without a handshake for this long is down (it renews every
# two minutes while there's traffic, and keepalives cause traffic).
WIREGUARD_TIMEOUT = 180

IPAddress = IPv4Address | IPv6Address

# Named and valued as in OpenConfig, like the counters and rates.
AdminStatus = Literal["UP", "DOWN"]
# DORMANT: being set up (an IKE SA that isn't established yet).
OperStatus = Literal["UP", "DOWN", "DORMANT"]


class Counters(BaseModel):
    """Traffic through a connection's interface since it was created."""

    in_octets: int
    in_pkts: int
    in_errors: int
    in_discards: int
    out_octets: int
    out_pkts: int
    out_errors: int
    out_discards: int


class Rates(BaseModel):
    """Traffic through a connection's interface: the average of the last seconds."""

    # Seconds the rates are measured over.
    load_interval: int
    # Bits per second.
    in_bits_rate: int
    out_bits_rate: int


class ConnectionState(BaseModel):
    """The live state of a connection."""

    id: str
    tenant: str
    network_instance: str
    type: enums.ConnectionType
    # DOWN: disabled in the configuration.
    admin_status: AdminStatus
    oper_status: OperStatus
    # When oper_status last changed, or vpnc first saw the connection.
    last_change: str
    # How often oper_status changed since vpnc started.
    interface_transitions: int
    interface: str | None
    mtu: int | None
    addresses: list[str]
    remote: str | None
    # Type specific, e.g. IKE state or the last WireGuard handshake.
    details: dict[str, Any]
    # None without interface.
    counters: Counters | None
    # None until measured.
    rates: Rates | None


class Translation(BaseModel):
    """A NAT64 or NPTv6 translation: local (CORE side) to remote prefix."""

    type: Literal["NAT64", "NPTV6"]
    local: str
    remote: str


class NetworkInstanceState(BaseModel):
    """The live state of a network instance."""

    id: str
    tenant: str
    type: enums.NetworkInstanceType
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

    mode: enums.ServiceMode
    tenants: int
    network_instances: int
    connections_up: int
    connections: int
    vpncmangle: VpncmangleState | None
    # Service settings that only apply after vpnc restarts.
    restart_needed: list[str]


class BgpPrefixes(BaseModel):
    """A BGP session's prefixes in an address family, after policy."""

    received: int | None
    sent: int | None


class BgpAfiSafi(BaseModel):
    """An address family of a BGP session."""

    # E.g. IPV6_UNICAST.
    afi_safi_name: str
    prefixes: BgpPrefixes


class BgpNeighbor(BaseModel):
    """A BGP session in CORE, named as in OpenConfig."""

    neighbor_address: str
    hostname: str | None
    peer_as: int | None
    # IDLE, CONNECT, ACTIVE, OPENSENT, OPENCONFIRM or ESTABLISHED.
    session_state: str | None
    # When the session last became established, or stopped being so.
    last_established: str | None
    afi_safis: list[BgpAfiSafi]


class Ids(BaseModel):
    """The ids of what's configured, e.g. to complete commands."""

    tenants: list[str]
    network_instances: list[str]
    connections: list[str]
    # Tenants with an active or staged configuration.
    config_tenants: list[str]


def ids() -> Ids:
    """Return the ids of the tenants, network instances and connections."""
    configured = helpers.network_instances()
    return Ids(
        tenants=sorted(config.VPNC_CONFIG_TENANT),
        network_instances=sorted(configured),
        connections=sorted(
            connection.name(ni)
            for ni in configured.values()
            for connection in ni.connections.values()
        ),
        config_tenants=config_files.tenant_ids(),
    )


def _ipsec_sas(
    listing: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Return the IKE SAs by connection name; listed, unless a listing is given."""
    if listing is None:
        try:
            with charon.session() as vcs:
                listing = list(vcs.list_sas())
        except OSError:
            logger.warning("Reading the IPsec SAs failed.", exc_info=True)
            return {}
    sas: dict[str, dict[str, Any]] = {}
    for item in listing:
        for name, sa in item.items():
            # A connection can have several (rekeying, duplicates): the one
            # that's up counts.
            if name not in sas or (charon.sa_up(sa) and not charon.sa_up(sas[name])):
                sas[name] = sa
    return sas


def _timestamp(seconds: float | None = None) -> str:
    """Return a time (Unix; default now) as in the rest of the API: ISO 8601."""
    time_ = datetime.datetime.fromtimestamp(seconds or time.time()).astimezone()
    return time_.isoformat(timespec="seconds")


@dataclasses.dataclass
class _Seen:
    """A connection's oper_status as last seen."""

    status: OperStatus
    last_change: str
    transitions: int = 0


# By connection; updated whenever the states are read (every full check at least).
_SEEN: dict[str, _Seen] = {}
_SEEN_LOCK = threading.Lock()


def _track(name: str, current: OperStatus) -> tuple[str, int]:
    """Return when a connection's oper_status last changed, and how often."""
    with _SEEN_LOCK:
        if (seen := _SEEN.get(name)) is None:
            seen = _SEEN[name] = _Seen(current, _timestamp())
        elif seen.status != current:
            seen.status, seen.last_change = current, _timestamp()
            seen.transitions += 1
        return seen.last_change, seen.transitions


def _ipsec(
    name: str,
    connection: Connection,
    sas: dict[str, dict[str, Any]],
) -> tuple[OperStatus, str | None, dict[str, Any]]:
    sa = sas.get(name)
    if sa is None:
        return "DOWN", str(connection.config.remote_addrs[0]), {}
    sa = charon.decode(sa)
    children = [
        {"name": child.get("name"), "state": child.get("state")}
        for child in sa.get("child-sas", {}).values()
    ]
    details: dict[str, Any] = {
        "ike_state": sa.get("state"),
        # Changes when the IKE SA is set up again.
        "ike_id": int(sa.get("uniqueid", 0)) or None,
        "child_sas": children,
    }
    current: OperStatus = "UP" if charon.sa_up(sa) else "DORMANT"
    return current, sa.get("remote-host"), details


def _wireguard(
    ni: NetworkInstance,
    ifname: str,
) -> tuple[OperStatus, str | None, dict[str, Any]]:
    try:
        peer = wireguard.peer_status(ni.id, ifname)
    except Exception:  # noqa: BLE001
        return "DOWN", None, {}
    handshake = peer["last_handshake"]
    details = {"last_handshake": _timestamp(handshake) if handshake else None}
    recent = handshake and time.time() - handshake < WIREGUARD_TIMEOUT
    return ("UP" if recent else "DOWN"), peer["endpoint"], details


def _snapshot(ni_id: str) -> state.NetnsState:
    """Read the links and addresses of a network instance (not its routes)."""
    try:
        return state.NetnsState.read(ni_id, routes=False)
    except FileNotFoundError:
        return state.NetnsState(name=ni_id)


def connection_states(
    selected: list[NetworkInstance] | None = None,
    *,
    interfaces: bool = True,
    sas_listing: list[dict[str, Any]] | None = None,
) -> list[ConnectionState]:
    """Return the live state of the connections of the network instances.

    Without interfaces, network instances with only IPsec connections aren't read:
    their state comes from the SAs. Enough to count connections that are up. The
    SAs are listed, unless a listing (as vici returns it) is given.
    """
    everything = selected is None
    if selected is None:
        selected = list(helpers.network_instances().values())
    sas = (
        _ipsec_sas(sas_listing)
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
        for connection in ni.connections.values():
            name = connection.name(ni)
            ifname = connection.intf_name(ni)
            link = snapshot.links.get(ifname) if ifname else None
            addresses = sorted(
                str(a) for a in snapshot.addresses.get(ifname or "", set())
            )
            remote_addrs = getattr(connection.config, "remote_addrs", None)
            remote = str(remote_addrs[0]) if remote_addrs else None
            details: dict[str, Any] = {}
            ctype = connection.config.type
            current: OperStatus
            if ctype == enums.ConnectionType.IPSEC:
                current, remote, details = _ipsec(name, connection, sas)
            elif ctype == enums.ConnectionType.WIREGUARD and link is not None:
                current, endpoint, details = _wireguard(ni, ifname)
                remote = endpoint or remote
            else:
                # SSH (tun has carrier while ssh runs) and physical interfaces.
                current = "UP" if link is not None and link.passes_traffic else "DOWN"
            if ctype != enums.ConnectionType.PHYSICAL:
                details["auto_resets_24h"] = helpers.auto_resets(name)
            last_change, transitions = _track(name, current)
            counters = snapshot.counters.get(ifname or "")
            rates = traffic.rates(ni.id, ifname) if counters else None
            output.append(
                ConnectionState(
                    id=name,
                    tenant=ni.tenant_id,
                    network_instance=ni.id,
                    type=ctype,
                    admin_status="UP" if connection.enabled else "DOWN",
                    oper_status=current,
                    last_change=last_change,
                    interface_transitions=transitions,
                    interface=ifname if link is not None else None,
                    mtu=link.mtu if link is not None else None,
                    addresses=addresses,
                    remote=remote,
                    details=details,
                    counters=(
                        Counters(**dataclasses.asdict(counters)) if counters else None
                    ),
                    rates=Rates(**dataclasses.asdict(rates)) if rates else None,
                ),
            )
    if everything:
        # Connections that aren't configured anymore.
        with _SEEN_LOCK:
            for name in set(_SEEN) - {s.id for s in output}:
                del _SEEN[name]
    return output


def _counts(states: list[ConnectionState]) -> tuple[int, int]:
    return sum(s.oper_status == "UP" for s in states), len(states)


def network_instance_states(
    selected: list[NetworkInstance],
    *,
    translations: bool = False,
) -> list[NetworkInstanceState]:
    """Return the live state of network instances."""
    by_ni: dict[str, list[ConnectionState]] = {}
    for s in connection_states(selected, interfaces=False):
        by_ni.setdefault(s.network_instance, []).append(s)
    hub = tenant.is_hub()
    output: list[NetworkInstanceState] = []
    for ni in selected:
        up, total = _counts(by_ni.get(ni.id, []))
        item = NetworkInstanceState(
            id=ni.id,
            tenant=ni.tenant_id,
            type=ni.type,
            connections_up=up,
            connections=total,
        )
        if hub and ni.type == enums.NetworkInstanceType.DOWNLINK:
            nat64 = configuration.get_network_instance_nat64_scope(ni)
            nptv6 = configuration.get_network_instance_nptv6_scope(ni)
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
            Translation(type="NAT64", local=str(nat64[0]), remote=str(nat64[1])),
        )
    output.extend(
        Translation(type="NPTV6", local=str(local), remote=str(remote))
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
        mode=tenant.get_default_tenant().mode,
        tenants=len(config.VPNC_CONFIG_TENANT),
        network_instances=len(helpers.network_instances()),
        connections_up=up,
        connections=total,
        vpncmangle=_vpncmangle(),
        restart_needed=config_files.restart_needed(),
    )


def _vpncmangle() -> VpncmangleState | None:
    if not tenant.is_hub():
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


class BgpNeighborDetail(BgpNeighbor):
    """A BGP session in CORE, in detail."""

    local_as: int | None
    # How often the session became established.
    established_transitions: int | None
    connections_dropped: int | None
    last_reset: str | None
    # Seconds, as negotiated.
    hold_time: int | None
    keepalive_interval: int | None
    bfd: str | None


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


def _session_state(state: str | None) -> str | None:
    """Return FRR's session state as in OpenConfig, e.g. Idle (Admin) as IDLE."""
    return state.split()[0].upper() if state else None


def _afi_safi(family: str, received: int | None, sent: int | None) -> BgpAfiSafi:
    """Return an address family with FRR's name as in OpenConfig: IPV6_UNICAST."""
    return BgpAfiSafi(
        afi_safi_name=re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", family).upper(),
        prefixes=BgpPrefixes(received=received, sent=sent),
    )


def bgp_neighbors() -> list[BgpNeighbor]:
    """Return the BGP sessions in CORE (hub mode)."""
    output: dict[str, BgpNeighbor] = {}
    for family, summary in vtysh(f"show bgp vrf {config.CORE_NI} summary").items():
        for peer, info in summary.get("peers", {}).items():
            neighbor = output.setdefault(
                peer,
                BgpNeighbor(
                    neighbor_address=peer,
                    hostname=info.get("hostname"),
                    peer_as=info.get("remoteAs"),
                    session_state=_session_state(info.get("state")),
                    last_established=(
                        _timestamp(epoch)
                        if (epoch := info.get("peerUptimeEstablishedEpoch"))
                        else None
                    ),
                    afi_safis=[],
                ),
            )
            neighbor.afi_safis.append(
                _afi_safi(family, info.get("pfxRcd"), info.get("pfxSnt")),
            )
    return list(output.values())


def bgp_neighbor(neighbor: IPAddress) -> BgpNeighborDetail | None:
    """Return a BGP session in CORE in detail; None if it doesn't exist."""
    data = vtysh(f"show bgp vrf {config.CORE_NI} neighbors {neighbor}")
    if not (info := data.get(str(neighbor))):
        return None
    hold = info.get("bgpTimerHoldTimeMsecs")
    keepalive = info.get("bgpTimerKeepAliveIntervalMsecs")
    bfd = (info.get("peerBfdInfo") or {}).get("status")
    return BgpNeighborDetail(
        neighbor_address=str(neighbor),
        hostname=info.get("hostname"),
        peer_as=info.get("remoteAs"),
        local_as=info.get("localAs"),
        session_state=_session_state(info.get("bgpState")),
        last_established=(
            _timestamp(epoch)
            if (epoch := info.get("bgpTimerUpEstablishedEpoch"))
            else None
        ),
        afi_safis=[
            _afi_safi(
                family,
                af.get("acceptedPrefixCounter"),
                af.get("sentPrefixCounter"),
            )
            for family, af in (info.get("addressFamilyInfo") or {}).items()
        ],
        established_transitions=info.get("connectionsEstablished"),
        connections_dropped=info.get("connectionsDropped"),
        last_reset=info.get("lastResetDueTo"),
        hold_time=hold // 1000 if hold is not None else None,
        keepalive_interval=keepalive // 1000 if keepalive is not None else None,
        bfd=bfd.upper() if bfd else None,
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
    try:
        with charon.session() as vcs:
            strongswan = charon.decode(vcs.version()).get("version")
    except OSError:
        logger.warning("Reading the strongSwan version failed.", exc_info=True)
    frr = None
    if tenant.is_hub():
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
