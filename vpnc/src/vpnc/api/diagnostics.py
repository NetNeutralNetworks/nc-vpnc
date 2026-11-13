"""Troubleshooting inside a network instance: routes, ping, traceroute, TCP."""

from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Literal

from pydantic import BaseModel, Field

from vpnc.network import namespace

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
        default = "0.0.0.0/0" if fam == 4 else "::/0"  # noqa: PLR2004, S104
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
