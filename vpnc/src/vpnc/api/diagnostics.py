"""Troubleshooting: routes, ping, traceroute, TCP, translations, sessions, firewall."""

from __future__ import annotations

import csv
import json
import re
import socket
import subprocess
import time
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field
from pyroute2 import Conntrack

from vpnc.models import enums
from vpnc.network import namespace, nftables
from vpnc.services import jool

if TYPE_CHECKING:
    from collections.abc import Iterator

    from vpnc.models.network_instance import NetworkInstance

IPAddress = IPv4Address | IPv6Address

PING_SUMMARY_RE = re.compile(r"(\d+) packets transmitted, (\d+) received")
PING_RTT_RE = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/")
TRACEROUTE_HOP_RE = re.compile(r"^\s*(\d+)\s+(?:(\S+)\s+([\d.]+) ms|\*)")


class Route(BaseModel):
    """A route in a network instance's routing table."""

    prefix: str
    # UNICAST, BLACKHOLE, UNREACHABLE, LOCAL etc.
    type: str
    next_hops: list[str]
    interfaces: list[str]
    # Who installed it, e.g. KERNEL, BGP, VPNC.
    protocol: str | None
    metric: int | None


class PingRequest(BaseModel):
    """A ping."""

    destination: IPAddress
    count: int = Field(5, ge=1, le=100)
    size: int = Field(56, ge=0, le=65500)
    # Seconds to wait for each reply.
    timeout: float = Field(1, gt=0, le=10)


class PingResult(BaseModel):
    """The result of a ping."""

    destination: str
    transmitted: int
    received: int
    rtt_min_ms: float | None
    rtt_avg_ms: float | None
    rtt_max_ms: float | None
    output: str


class TracerouteRequest(BaseModel):
    """A traceroute."""

    destination: IPAddress
    max_hops: int = Field(20, ge=1, le=64)


class Hop(BaseModel):
    """A traceroute hop; no address if it didn't answer."""

    hop: int
    address: str | None
    rtt_ms: float | None


class TracerouteResult(BaseModel):
    """The result of a traceroute."""

    destination: str
    hops: list[Hop]
    output: str


class TcpRequest(BaseModel):
    """A TCP connection test."""

    address: IPAddress
    port: int = Field(ge=1, le=65535)
    timeout: float = Field(3, gt=0, le=30)


class TcpResult(BaseModel):
    """The result of a TCP connection test."""

    address: str
    port: int
    connected: bool
    time_ms: float | None
    error: str | None


def routes(ni_id: str, family: Literal[4, 6] | None = None) -> list[Route]:
    """Return the routes of a network instance's main table."""
    output: list[Route] = []
    for fam in (family,) if family else (4, 6):
        result = namespace.run(ni_id, ["/usr/sbin/ip", "-j", f"-{fam}", "route"])
        default = "0.0.0.0/0" if fam == 4 else "::/0"  # noqa: PLR2004
        for route in json.loads(result.stdout or "[]"):
            hops = route.get("nexthops") or [route]
            protocol = route.get("protocol")
            output.append(
                Route(
                    prefix=default if route["dst"] == "default" else route["dst"],
                    type=route.get("type", "unicast").upper(),
                    next_hops=[h["gateway"] for h in hops if h.get("gateway")],
                    interfaces=[h["dev"] for h in hops if h.get("dev")],
                    protocol=str(protocol).upper() if protocol else None,
                    metric=route.get("metric"),
                ),
            )
    return output


def _run(ni_id: str, args: list[str], timeout: float) -> str:
    try:
        result = namespace.run(ni_id, args, timeout=timeout)
    except subprocess.TimeoutExpired as err:
        return (err.stdout or b"").decode(errors="replace")
    return result.stdout + result.stderr


def ping(ni_id: str, request: PingRequest) -> PingResult:
    """Ping from a network instance."""
    output = _run(
        ni_id,
        [
            "/usr/bin/ping",
            "-n",
            "-c",
            str(request.count),
            "-s",
            str(request.size),
            "-W",
            str(request.timeout),
            str(request.destination),
        ],
        timeout=request.count * (request.timeout + 1) + 5,
    )
    summary = PING_SUMMARY_RE.search(output)
    rtt = PING_RTT_RE.search(output)
    return PingResult(
        destination=str(request.destination),
        transmitted=int(summary[1]) if summary else 0,
        received=int(summary[2]) if summary else 0,
        rtt_min_ms=float(rtt[1]) if rtt else None,
        rtt_avg_ms=float(rtt[2]) if rtt else None,
        rtt_max_ms=float(rtt[3]) if rtt else None,
        output=output,
    )


def traceroute(ni_id: str, request: TracerouteRequest) -> TracerouteResult:
    """Traceroute from a network instance (one probe per hop)."""
    output = _run(
        ni_id,
        [
            "/usr/bin/traceroute",
            "-n",
            "-q",
            "1",
            "-w",
            "1",
            "-m",
            str(request.max_hops),
            str(request.destination),
        ],
        timeout=request.max_hops * 2 + 5,
    )
    hops = [
        Hop(
            hop=int(match[1]),
            address=match[2],
            rtt_ms=float(match[3]) if match[3] else None,
        )
        for line in output.splitlines()
        if (match := TRACEROUTE_HOP_RE.match(line))
    ]
    return TracerouteResult(
        destination=str(request.destination),
        hops=hops,
        output=output,
    )


def tcp(ni_id: str, request: TcpRequest) -> TcpResult:
    """Open a TCP connection from a network instance."""

    def run() -> tuple[float | None, str | None]:
        started = time.monotonic()
        try:
            with socket.create_connection(
                (str(request.address), request.port),
                timeout=request.timeout,
            ):
                return (time.monotonic() - started) * 1000, None
        except TimeoutError:
            return None, "timed out"
        except OSError as err:
            return None, err.strerror or str(err)

    elapsed, error = namespace.call(ni_id, run)
    return TcpResult(
        address=str(request.address),
        port=request.port,
        connected=error is None,
        time_ms=round(elapsed, 2) if elapsed is not None else None,
        error=error,
    )


class AddressTranslation(BaseModel):
    """An address as admins reach it (local, CORE side) and in the tenant (remote)."""

    tenant: str
    network_instance: str
    # NONE: global unicast, routed as is.
    type: Literal["NAT64", "NPTV6", "NONE"]
    local: str
    remote: str


def _mappings(
    ni: NetworkInstance,
) -> Iterator[tuple[str, IPv6Network, IPv4Network | IPv6Network]]:
    """Return a downlink's translations: type, CORE side and tenant side prefix."""
    if nat64 := ni.nat64_scope():
        yield "NAT64", nat64, IPv4Network("0.0.0.0/0")
    for connection in ni.connections.values():
        for route6 in connection.routes.ipv6:
            if route6.nptv6:
                # None until it's calculated.
                if route6.nptv6_prefix:
                    yield "NPTV6", route6.nptv6_prefix, route6.to
            else:
                yield "NONE", route6.to, route6.to


def _map(
    address: IPv4Address | IPv6Address,
    source: IPv4Network | IPv6Network,
    target: IPv4Network | IPv6Network,
) -> IPv4Address | IPv6Address | None:
    """Return the address in target with the host bits of address in source."""
    if address.version != source.version or address not in source:
        return None
    host = int(address) - int(source.network_address)
    if host >= target.num_addresses:
        return None
    return ip_address(int(target.network_address) + host)


def translate(
    address: IPv4Address | IPv6Address,
    network_instances: list[NetworkInstance],
) -> list[AddressTranslation]:
    """Return the translations of an address, from either side, in the downlinks."""
    output: list[AddressTranslation] = []
    for ni in network_instances:
        if ni.type != enums.NetworkInstanceType.DOWNLINK:
            continue
        for kind, local, remote in _mappings(ni):
            if (tenant_side := _map(address, local, remote)) is not None:
                pair = address, tenant_side
            elif (core_side := _map(address, remote, local)) is not None:
                pair = core_side, address
            else:
                continue
            item = AddressTranslation(
                tenant=ni.tenant_id,
                network_instance=ni.id,
                type=kind,  # type: ignore[arg-type]
                local=str(pair[0]),
                remote=str(pair[1]),
            )
            if item not in output:
                output.append(item)
    return output


class Session(BaseModel):
    """A flow through a network instance, with how it's translated."""

    # NAT64 (Jool), NPTV6 (destination prefix translated) or ROUTED.
    type: Literal["NAT64", "NPTV6", "ROUTED"]
    # TCP, UDP, ICMP, ICMPV6 or the protocol number.
    protocol: str
    # As management sent it.
    source: str
    destination: str
    # As the tenant sees it; None if it isn't translated.
    translated_source: str | None
    translated_destination: str | None
    # TCP only.
    state: str | None
    # Seconds until it expires without traffic.
    expires: int | None


class Sessions(BaseModel):
    """The sessions of a network instance; at most a limit of them listed."""

    total: int
    sessions: list[Session]


PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPV6"}
# conntrack status bits.
IPS_DST_NAT = 0x20
IPS_SRC_NAT = 0x10


def _address(address: str | None, port: int | str | None, protocol: str) -> str:
    """Return address:port, or the address alone for ICMP."""
    if port is None or protocol.startswith("ICMP"):
        return str(address)
    return f"[{address}]:{port}" if ":" in str(address) else f"{address}:{port}"


def _expires(text: str) -> int | None:
    """Return Jool's expiry (H:MM:SS.mmm) in seconds."""
    try:
        hours, minutes, seconds = text.split(":")
        return int(hours) * 3600 + int(minutes) * 60 + int(float(seconds))
    except ValueError:
        return None


def _nat64_sessions(ni_id: str) -> list[Session]:
    """Return the sessions of a network instance's Jool instance."""
    output: list[Session] = []
    for flag in ("--tcp", "--udp", "--icmp"):
        result = namespace.run(
            ni_id,
            [jool.JOOL, "-i", ni_id, "session", "display", "--numeric", "--csv", flag],
        )
        if result.returncode:
            continue
        for row in csv.reader(result.stdout.splitlines()[1:]):
            if len(row) < 10:  # noqa: PLR2004
                continue
            protocol = row[0].upper()
            output.append(
                Session(
                    type="NAT64",
                    protocol=protocol,
                    source=_address(row[1], row[2], protocol),
                    destination=_address(row[3], row[4], protocol),
                    translated_source=_address(row[5], row[6], protocol),
                    translated_destination=_address(row[7], row[8], protocol),
                    state=row[10] if len(row) > 10 and row[10] else None,  # noqa: PLR2004
                    expires=_expires(row[9]),
                ),
            )
    return output


def _conntrack_sessions(ni_id: str, *, ipv4: bool) -> list[Session]:
    """Return the conntrack flows of a network instance; IPv4 ones if ipv4."""

    def read() -> list[Session]:
        with Conntrack(nfgen_family=socket.AF_UNSPEC) as ct:
            entries = list(ct.dump_entries())
        output: list[Session] = []
        for entry in entries:
            orig, reply = entry.tuple_orig, entry.tuple_reply
            if orig.family == socket.AF_INET and not ipv4:
                continue
            protocol = PROTOCOLS.get(orig.proto, str(orig.proto))
            translated = entry.status & (IPS_DST_NAT | IPS_SRC_NAT)
            output.append(
                Session(
                    type="NPTV6" if entry.status & IPS_DST_NAT else "ROUTED",
                    protocol=protocol,
                    source=_address(orig.saddr, orig.sport, protocol),
                    destination=_address(orig.daddr, orig.dport, protocol),
                    translated_source=(
                        _address(reply.daddr, reply.dport, protocol)
                        if translated
                        else None
                    ),
                    translated_destination=(
                        _address(reply.saddr, reply.sport, protocol)
                        if translated
                        else None
                    ),
                    state=(
                        entry.protoinfo.state_name()
                        if entry.protoinfo is not None
                        else None
                    ),
                    expires=entry.timeout,
                ),
            )
        return output

    return namespace.call(ni_id, read)


def session_list(
    ni: NetworkInstance,
    address: IPv4Address | IPv6Address | None = None,
    protocol: str | None = None,
) -> list[Session]:
    """Return the sessions through a network instance, NAT64 ones first.

    With NAT64, IPv4 flows are Jool's translations: they're left out of conntrack's.
    """
    nat64 = ni.nat64_scope() is not None
    found = [
        *(_nat64_sessions(ni.id) if nat64 else []),
        *_conntrack_sessions(ni.id, ipv4=not nat64),
    ]
    if protocol:
        found = [s for s in found if s.protocol == protocol.upper()]
    if address is not None:
        wanted = str(address)
        found = [
            s
            for s in found
            if wanted
            in {
                _host(value)
                for value in (
                    s.source,
                    s.destination,
                    s.translated_source,
                    s.translated_destination,
                )
                if value
            }
        ]
    return found


def sessions(
    ni: NetworkInstance,
    address: IPv4Address | IPv6Address | None = None,
    protocol: str | None = None,
    limit: int = 1000,
) -> Sessions:
    """Return the sessions through a network instance, at most limit of them."""
    found = session_list(ni, address, protocol)
    return Sessions(total=len(found), sessions=found[:limit])


def _host(endpoint: str) -> str:
    """Return the address of address:port, [address]:port or address."""
    if endpoint.startswith("["):
        return endpoint[1:].partition("]")[0]
    if endpoint.count(":") == 1:
        return endpoint.partition(":")[0]
    return endpoint


class FirewallRule(BaseModel):
    """A rule of vpnc's firewall in a network instance, with its counter."""

    chain: str
    rule: str
    packets: int
    bytes: int


CHAIN_RE = re.compile(r"^\s*chain (\S+) \{")
COUNTER_RE = re.compile(r"\s*counter packets (\d+) bytes (\d+)")


def firewall(ni_id: str) -> list[FirewallRule]:
    """Return the counted rules of vpnc's table, in order (since it was replaced)."""
    listing = nftables.run(ni_id, f"list table {nftables.TABLE}")
    output: list[FirewallRule] = []
    chain = ""
    for line in listing.splitlines():
        if match := CHAIN_RE.match(line):
            chain = match[1]
        elif match := COUNTER_RE.search(line):
            rule = COUNTER_RE.sub("", line).strip()
            output.append(
                FirewallRule(
                    chain=chain,
                    rule=rule,
                    packets=int(match[1]),
                    bytes=int(match[2]),
                ),
            )
    return output


def dropped(rules: list[FirewallRule]) -> int:
    """Return the packets the rules dropped or rejected."""
    return sum(
        rule.packets
        for rule in rules
        if rule.rule.endswith("drop") or " reject" in f" {rule.rule}"
    )
