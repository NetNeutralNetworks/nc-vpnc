"""vpnctl: show vpnc's state and edit its configuration through the local API.

Only the standard library is imported up front (PyYAML when needed), so commands
start fast.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import http.client
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode

if TYPE_CHECKING:
    from collections.abc import Iterator

SOCKET = os.environ.get("VPNCTL_SOCKET", "/run/vpnc/api.sock")


class ApiError(Exception):
    """The API returned an error (problem details)."""

    def __init__(self, status: int, problem: dict[str, Any]) -> None:
        """Store the HTTP status and problem details."""
        super().__init__(problem.get("title", f"HTTP {status}"))
        self.status = status
        self.problem = problem


class _UnixConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)


@contextlib.contextmanager
def _call(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    body: Any = None,  # noqa: ANN401
    timeout: float | None = 60,
) -> Iterator[http.client.HTTPResponse]:
    """Call the API and yield the response; exit if vpnc can't be reached."""
    if params := {k: v for k, v in (params or {}).items() if v is not None}:
        path += "?" + urlencode(params)
    conn = _UnixConnection("localhost", timeout=timeout)
    try:
        payload = json.dumps(body) if body is not None else None
        headers = {"Content-Type": "application/json"} if payload else {}
        conn.request(method, path, body=payload, headers=headers)
        yield conn.getresponse()
    except FileNotFoundError:
        fail(f"vpnc isn't running: no API at {SOCKET}.", code=2)
    except PermissionError:
        fail(f"No access to {SOCKET}: run vpnctl as root.", code=2)
    except ConnectionRefusedError:
        fail(f"vpnc isn't running: nothing listens on {SOCKET}.", code=2)
    except TimeoutError:
        fail("vpnc didn't answer in time.", code=2)
    except BrokenPipeError:
        # The output, e.g. piped into head.
        raise
    except (http.client.HTTPException, ConnectionError):
        fail("vpnc closed the connection.", code=2)
    finally:
        conn.close()


def _decode(response: http.client.HTTPResponse) -> Any:  # noqa: ANN401
    """Return the decoded response (text for text/plain); raise its error."""
    data = response.read().decode()
    content_type = response.getheader("Content-Type", "")
    decoded: Any = json.loads(data) if "json" in content_type else data
    if response.status >= 400:  # noqa: PLR2004
        problem = decoded if isinstance(decoded, dict) else {"detail": decoded}
        raise ApiError(response.status, problem)
    return decoded


def request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    body: Any = None,  # noqa: ANN401
) -> Any:  # noqa: ANN401
    """Call the API and return the decoded response (text for text/plain)."""
    with _call(method, path, params=params, body=body) as response:
        return _decode(response)


def stream(path: str, params: dict[str, Any]) -> Iterator[Any]:
    """Yield the JSON lines of a response that continues, until vpnc ends it."""
    with _call("GET", path, params=params, timeout=None) as response:
        if response.status >= 400:  # noqa: PLR2004
            _decode(response)
        for line in response:
            # Empty lines keep the stream alive.
            if line.strip():
                yield json.loads(line)


def fail(message: str, code: int = 1) -> None:
    """Print an error and exit."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(code)


def problem_text(err: ApiError) -> str:
    """Return a readable problem, one line per validation error."""
    detail = err.problem.get("detail")
    if isinstance(detail, list):
        lines = [f"  {d.get('loc', '')}: {d.get('msg', d)}" for d in detail]
        return "\n".join([f"{err}:", *lines])
    return f"{err}: {detail}" if detail else str(err)


# Output.


def duration(seconds: float | None) -> str:
    """Return a short duration, e.g. 2h13m."""
    if seconds is None:
        return "-"
    seconds = int(seconds)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d{hours}h"
    if hours:
        return f"{hours}h{minutes}m"
    if minutes:
        return f"{minutes}m{secs}s"
    return f"{secs}s"


def age(timestamp: str | None) -> str:
    """Return how long ago a time (ISO 8601) was, e.g. 2h13m."""
    if not timestamp:
        return "-"
    then = dt.datetime.fromisoformat(timestamp)
    return duration((dt.datetime.now(then.tzinfo) - then).total_seconds())


def size(count: int | None) -> str:
    """Return a byte count, e.g. 1.2 MB."""
    if count is None:
        return "-"
    value = float(count)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":  # noqa: PLR2004
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return str(count)


def rate(bits: float | None) -> str:
    """Return bits per second, e.g. 1.2 Mbit/s."""
    if bits is None:
        return "-"
    value = float(bits)
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if value < 1000 or unit == "Gbit/s":  # noqa: PLR2004
            return f"{value:.0f} {unit}" if unit == "bit/s" else f"{value:.1f} {unit}"
        value /= 1000
    return str(bits)


def clean(text: str) -> str:
    """Return text without control characters (e.g. a peer's terminal escapes)."""
    return "".join(c if c.isprintable() else "?" for c in text)


def structured(output: str) -> bool:
    """Return whether the output format is JSON or YAML."""
    return output in ("json", "yaml")


def up(row: dict[str, Any]) -> str:
    """Return how many of the connections are up, e.g. 3/4."""
    return f"{row['connections_up']}/{row['connections']}"


def cell(value: Any) -> str:  # noqa: ANN401
    """Return a table cell: lists comma separated, empty as '-'."""
    if value is None or value == []:
        return "-"
    if isinstance(value, list):
        return ", ".join(cell(v) for v in value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return clean(str(value))


def table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> None:
    """Print rows as a table with the given (header, key) columns."""
    if not rows:
        print("No results.")
        return
    cells = [[cell(row.get(key)) for _, key in columns] for row in rows]
    widths = [
        max(len(header), *(len(r[i]) for r in cells))
        for i, (header, _) in enumerate(columns)
    ]
    for line in [[h for h, _ in columns], *cells]:
        print("  ".join(v.ljust(w) for v, w in zip(line, widths, strict=True)).rstrip())


def fields(items: list[tuple[str, Any]]) -> None:
    """Print key-value lines."""
    width = max(len(k) for k, _ in items)
    for key, value in items:
        print(f"{key + ':':<{width + 1}}  {cell(value)}")


def dump(data: Any, output: str) -> bool:  # noqa: ANN401
    """Print data as JSON or YAML; return False for table output."""
    if output == "json":
        print(json.dumps(data, indent=2))
        return True
    if output == "yaml":
        import yaml  # noqa: PLC0415

        print(yaml.safe_dump(data, sort_keys=False), end="")
        return True
    return False


# State commands.


def cmd_status(args: argparse.Namespace) -> None:
    """Show an overview."""
    data = request("GET", "/v1/status")
    if dump(data, args.output):
        return
    fields(
        [
            ("Mode", data["mode"]),
            ("Tenants", data["tenants"]),
            ("Network instances", data["network_instances"]),
            ("Connections", f"{up(data)} up"),
            *(
                [("vpncmangle", vpncmangle_text(data["vpncmangle"]))]
                if data.get("vpncmangle")
                else []
            ),
            *(
                [
                    (
                        "Restart needed",
                        (
                            f"{', '.join(data['restart_needed'])} changed "
                            "(vpnctl service restart)"
                        ),
                    ),
                ]
                if data.get("restart_needed")
                else []
            ),
        ],
    )


def vpncmangle_text(state: dict[str, Any]) -> str:
    """Return vpncmangle's state, e.g. running, 12 translations, 3 answers ..."""
    running = "running" if state["running"] else "not running"
    text = f"{running}, {state['translations']} translations"
    if state.get("answers_translated") is not None:
        text += (
            f"; answers {state['answers_translated']} translated,"
            f" {state['answers_dropped']} dropped"
            f"{reasons_text(state.get('drop_reasons'))}"
        )
    return text


def reasons_text(reasons: dict[str, int] | None) -> str:
    """Return why DNS answers were dropped, e.g. " (RATE_LIMITED 12, ERROR 1)"."""
    if not reasons:
        return ""
    return f" ({', '.join(f'{reason} {count}' for reason, count in reasons.items())})"


def _up(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "up": up(row)}


def cmd_tenants_list(args: argparse.Namespace) -> None:
    """List the tenants."""
    data = request("GET", "/v1/tenants")
    if not dump(data, args.output):
        columns = [("TENANT", "id"), ("NAME", "name"), ("UP", "up")]
        if args.output == "wide":
            columns.append(("NETWORK INSTANCES", "network_instances"))
        table([_up(r) for r in data], columns)


def cmd_tenants_show(args: argparse.Namespace) -> None:
    """Show a tenant."""
    data = request("GET", f"/v1/tenants/{quote(args.id)}")
    if dump(data, args.output):
        return
    fields(
        [
            ("Tenant", data["id"]),
            ("Name", data["name"]),
            ("Connections", f"{up(data)} up"),
            ("Network instances", data["network_instances"]),
        ],
    )


def cmd_ni_list(args: argparse.Namespace) -> None:
    """List the network instances."""
    data = request("GET", "/v1/network-instances", params={"tenant": args.tenant})
    if not dump(data, args.output):
        columns = [("NETWORK INSTANCE", "id"), ("TYPE", "type"), ("UP", "up")]
        if args.output == "wide":
            columns += [("NAT64", "nat64_scope"), ("NPTV6", "nptv6_scope")]
        table([_up(r) for r in data], columns)


def cmd_ni_show(args: argparse.Namespace) -> None:
    """Show a network instance with its translations."""
    data = request("GET", f"/v1/network-instances/{quote(args.id)}")
    if dump(data, args.output):
        return
    fields(
        [
            ("Network instance", data["id"]),
            ("Tenant", data["tenant"]),
            ("Type", data["type"]),
            ("Connections", f"{up(data)} up"),
            ("NAT64 scope", data.get("nat64_scope")),
            ("NPTv6 scope", data.get("nptv6_scope")),
            *(
                [("Sessions", sessions_text(data["sessions"]))]
                if data.get("sessions") is not None
                else []
            ),
            *(
                [("Firewall drops", data["firewall_dropped"])]
                if data.get("firewall_dropped") is not None
                else []
            ),
            *(
                [
                    (
                        "DNS answers",
                        (
                            f"{data['dns_answers_translated']} translated,"
                            f" {data['dns_answers_dropped']} dropped"
                            f"{reasons_text(data.get('dns_drop_reasons'))}"
                        ),
                    ),
                ]
                if data.get("dns_answers_translated") is not None
                else []
            ),
        ],
    )
    if data.get("translations"):
        print()
        table(
            data["translations"],
            [("TRANSLATION", "type"), ("LOCAL", "local"), ("REMOTE", "remote")],
        )


def sessions_text(counts: dict[str, int]) -> str:
    """Return session counts, e.g. 12 (NAT64 9, NPTV6 3)."""
    total = sum(counts.values())
    if not total:
        return "0"
    parts = ", ".join(f"{kind} {count}" for kind, count in sorted(counts.items()))
    return f"{total} ({parts})"


def _filter(prefix: str | None) -> dict[str, str | None]:
    """Return the filter for a tenant (C0001) or network instance (C0001-00)."""
    if prefix is None:
        return {}
    if "-" in prefix or prefix in ("CORE", "EXTERNAL", "ENDPOINT"):
        return {"network_instance": prefix}
    return {"tenant": prefix}


def cmd_connections_list(args: argparse.Namespace) -> None:
    """List the connections."""
    data = request(
        "GET",
        "/v1/connections",
        params={
            **_filter(args.filter),
            "admin_status": args.admin_status,
            "oper_status": args.oper_status,
            "type": args.type,
        },
    )
    if not dump(data, args.output):
        columns = [
            ("CONNECTION", "id"),
            ("TYPE", "type"),
            ("ADMIN", "admin_status"),
            ("OPER", "oper_status"),
            ("LAST CHANGE", "age"),
            ("REMOTE", "remote"),
            ("INTERFACE", "interface"),
        ]
        if args.output == "wide":
            columns += [
                ("MTU", "mtu"),
                ("IN", "in"),
                ("OUT", "out"),
                ("IN RATE", "in_rate"),
                ("OUT RATE", "out_rate"),
                ("PROBES", "probes_ok"),
                ("ADDRESSES", "addresses"),
            ]
        for row in data:
            counters, rates = row.get("counters") or {}, row.get("rates") or {}
            row["age"] = age(row["last_change"])
            row["probes_ok"] = probes_text(row.get("probes") or [])
            for direction in ("in", "out"):
                row[direction] = size(counters.get(f"{direction}_octets"))
                row[f"{direction}_rate"] = rate(rates.get(f"{direction}_bits_rate"))
        table(data, columns)


PROBE_RESULTS = {None: "not tested", False: "OK", True: "FAILED"}


def probe_name(probe: dict[str, Any]) -> str:
    """Return what a probe tests, e.g. 10.0.0.1 TCP 443."""
    name = f"{probe['address']} {probe['test_type']}"
    return name if probe["port"] is None else f"{name} {probe['port']}"


def probe_text(probe: dict[str, Any]) -> str:
    """Return a probe and its last test, e.g. 10.0.0.1 TCP 443 (web server): OK."""
    description = f" ({probe['description']})" if probe.get("description") else ""
    return f"{probe_name(probe)}{description}: {PROBE_RESULTS[probe['failed']]}"


def probes_text(probes: list[dict[str, Any]]) -> str | None:
    """Return how many of the tested probes are answered, e.g. 1/2."""
    tested = [probe for probe in probes if probe["failed"] is not None]
    if not tested:
        return None
    return f"{sum(not probe['failed'] for probe in tested)}/{len(tested)}"


def delay(microseconds: int | None) -> str:
    """Return a response time, e.g. 1.2 ms."""
    return "-" if microseconds is None else f"{microseconds / 1000:.1f} ms"


def cmd_connections_probes(args: argparse.Namespace) -> None:
    """Show a connection's probes and their last tests (3 minutes)."""
    data = request("GET", f"/v1/connections/{quote(args.id)}/probes")
    if dump(data, args.output):
        return
    if not data:
        print("No probes.")
        return
    rows = []
    for probe in data:
        tests = probe["history"]
        rows.append(
            {
                "probe": probe_name(probe),
                "result": PROBE_RESULTS[probe["failed"]],
                "last": age(probe["last_test_timestamp"]),
                "answered": f"{sum(not t['failed'] for t in tests)}/{len(tests)}",
                "delay": delay(tests[-1]["avg_delay"]) if tests else None,
                "description": probe.get("description"),
            },
        )
    table(
        rows,
        [
            ("PROBE", "probe"),
            ("RESULT", "result"),
            ("LAST TEST", "last"),
            ("ANSWERED", "answered"),
            ("DELAY", "delay"),
            ("DESCRIPTION", "description"),
        ],
    )
    for probe in data:
        if not probe["history"]:
            continue
        description = f" ({probe['description']})" if probe.get("description") else ""
        print(f"\n{probe_name(probe)}{clean(description)}")
        table(
            [
                {
                    "time": test["timestamp"],
                    "age": age(test["timestamp"]),
                    "result": PROBE_RESULTS[test["failed"]],
                    "delay": delay(test["avg_delay"]),
                }
                # Newest first.
                for test in reversed(probe["history"])
            ],
            [
                ("TIME", "time"),
                ("AGE", "age"),
                ("RESULT", "result"),
                ("DELAY", "delay"),
            ],
        )


# Events shown with a connection.
RECENT_EVENTS = 5


def cmd_connections_show(args: argparse.Namespace) -> None:
    """Show a connection."""
    data = request("GET", f"/v1/connections/{quote(args.id)}")
    if dump(data, args.output):
        return
    tunnel = data.get("tunnel") or {}
    items: list[tuple[str, Any]] = [
        ("Connection", data["id"]),
        ("Tenant", data["tenant"]),
        ("Network instance", data["network_instance"]),
        ("Type", data["type"]),
        ("Admin status", data["admin_status"]),
        ("Oper status", data["oper_status"]),
        ("Last change", f"{data['last_change']} ({age(data['last_change'])} ago)"),
        ("Interface transitions", data["interface_transitions"]),
        ("Remote", tunnel.get("remote") or data.get("remote")),
        ("Interface", data.get("interface")),
        ("MTU", data.get("mtu")),
        ("Addresses", data.get("addresses")),
        *tunnel_items(data["type"], tunnel),
    ]
    if data.get("probes"):
        items.append(("Probes", [probe_text(probe) for probe in data["probes"]]))
    if data.get("auto_resets_24h") is not None:
        items.append(("Auto resets (24h)", data["auto_resets_24h"]))
    if counters := data.get("counters"):
        items += [
            (
                label,
                (
                    f"{size(counters[f'{direction}_octets'])} "
                    f"({counters[f'{direction}_pkts']} packets, "
                    f"{counters[f'{direction}_errors']} errors, "
                    f"{counters[f'{direction}_discards']} discards)"
                ),
            )
            for label, direction in (("In", "in"), ("Out", "out"))
        ]
    if rates := data.get("rates"):
        over = f"(over {duration(rates['load_interval'])})"
        items += [
            ("In rate", f"{rate(rates['in_bits_rate'])} {over}"),
            ("Out rate", f"{rate(rates['out_bits_rate'])} {over}"),
        ]
    fields(items)
    if tunnel.get("sas"):
        print()
        sa_table(tunnel["sas"])
    _last_events(args.id)


def _last_events(connection: str) -> None:
    """Print a connection's last events."""
    params = {"connection": connection, "limit": RECENT_EVENTS}
    if recent := request("GET", "/v1/events", params=params):
        print("\nLast events (all: vpnctl connections events):")
        for event in recent:
            _print_event(event, subject=False)


def cmd_connections_diagnose(args: argparse.Namespace) -> None:
    """Tell what's wrong with a connection, and what was checked."""
    data = request("GET", f"/v1/connections/{quote(args.id)}/diagnosis")
    if dump(data, args.output):
        return
    problem = data["problem"]
    status = (
        f"admin {data['admin_status']}, oper {data['oper_status']} "
        f"for {age(data['last_change'])}"
    )
    items: list[tuple[str, Any]] = [
        ("Connection", f"{data['id']} ({data['type']})"),
        ("Status", status),
        ("Problem", f"{problem}: {data['summary']}" if problem else data["summary"]),
    ]
    if data["count"]:
        seen = (
            f"{data['count']} times, first {age(data['first_seen'])} ago, "
            f"last {age(data['last_seen'])} ago"
        )
        items.append(("Seen", seen))
    if data["hint"]:
        items.append(("Hint", data["hint"]))
    fields(items)
    if problem and data["details"]:
        print("\nDetails:")
        fields([(f"  {k.replace('_', ' ')}", v) for k, v in data["details"].items()])
    print("\nChecks:")
    for check in data["checks"]:
        print(f"  {check['result']:<6}  {check['name']:<17}  {clean(check['detail'])}")
    if data["evidence"]:
        print("\nReported:")
        for line in data["evidence"]:
            print(f"  {clean(line)}")
    _last_events(args.id)


def until(timestamp: str | None) -> str:
    """Return how long until a time (ISO 8601), e.g. 2h13m."""
    if not timestamp:
        return "-"
    then = dt.datetime.fromisoformat(timestamp)
    return duration(max((then - dt.datetime.now(then.tzinfo)).total_seconds(), 0))


def when(timestamp: str | None, *, future: bool = False) -> str | None:
    """Return a time with how long ago or until, e.g. ... (2h13m ago)."""
    if not timestamp:
        return None
    if future:
        return f"{timestamp} (in {until(timestamp)})"
    return f"{timestamp} ({age(timestamp)} ago)"


def key_exchange_text(tunnel: dict[str, Any]) -> str | None:
    """Return the key exchanges, e.g. ECP_384 + ML_KEM_768 + PPK."""
    methods = [*tunnel.get("key_exchange", []), *(["PPK"] if tunnel.get("ppk") else [])]
    return " + ".join(methods) or None


def tunnel_items(ctype: str, tunnel: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return a VPN connection's session fields, the same for each type."""
    if ctype == "PHYSICAL":
        return []
    if not tunnel:
        return [("Session", "none")]
    # The same for each type, "-" where it lacks one.
    common: list[tuple[str, Any]] = [
        ("Session state", tunnel.get("state")),
        ("Session id", tunnel.get("session_id")),
        ("Local", tunnel.get("local")),
        ("Local identity", tunnel.get("local_identity")),
        ("Remote identity", tunnel.get("remote_identity")),
        ("Encryption", tunnel.get("encryption")),
        ("Integrity", tunnel.get("integrity")),
        ("Key exchange", key_exchange_text(tunnel)),
        ("Established", when(tunnel.get("established"))),
        ("Rekey", when(tunnel.get("rekey"), future=True)),
    ]
    # Only shown for the type that has them.
    specific: list[tuple[str, Any]] = [
        ("PRF", tunnel.get("prf")),
        ("NAT", tunnel.get("nat")),
        ("Last handshake", when(tunnel.get("last_handshake"))),
        ("Allowed IPs", tunnel.get("allowed_ips")),
    ]
    return common + [(key, value) for key, value in specific if value not in (None, [])]


def sa_table(sas: list[dict[str, Any]]) -> None:
    """Print IPsec child SAs."""
    rows = [
        {
            **sa,
            "crypto": "/".join(
                v for v in (sa.get("encryption"), sa.get("integrity")) if v
            ),
            "pfs": " + ".join(sa.get("key_exchange") or []) or None,
            "spis": f"{sa.get('spi_in') or '-'}/{sa.get('spi_out') or '-'}",
            "traffic": f"{size(sa.get('in_octets'))}/{size(sa.get('out_octets'))}",
            "age": age(sa.get("installed")),
            "rekey_in": until(sa.get("rekey")),
        }
        for sa in sas
    ]
    table(
        rows,
        [
            ("SA", "id"),
            ("STATE", "state"),
            ("ENCRYPTION", "crypto"),
            ("PFS", "pfs"),
            ("SPI IN/OUT", "spis"),
            ("LOCAL TS", "local_ts"),
            ("REMOTE TS", "remote_ts"),
            ("IN/OUT", "traffic"),
            ("AGE", "age"),
            ("REKEY IN", "rekey_in"),
        ],
    )


def cmd_connections_ssh_setup(args: argparse.Namespace) -> None:
    """Print a script that sets up an SSH connection's server for an account."""
    script = request(
        "GET",
        f"/v1/connections/{quote(args.id)}/ssh-setup",
        params={"username": args.username, "interface": args.interface},
    )
    print(script, end="")


def _expand(target: str) -> list[str]:
    """Return a network instance's or tenant's VPN connections (not PHYSICAL)."""
    ids = [
        c["id"]
        for c in request("GET", "/v1/connections", params=_filter(target))
        if c["type"] != "PHYSICAL"
    ]
    if not ids:
        fail(f"No connection, network instance or tenant '{target}'.")
    return ids


def _control(args: argparse.Namespace, action: str, done: str) -> None:
    """Act on connections, or the VPN connections of network instances/tenants."""
    results: list[dict[str, Any]] = []
    failed = False
    pending = list(args.ids)
    expanded: set[str] = set()
    while pending:
        target = pending.pop(0)
        try:
            data = request("POST", f"/v1/connections/{quote(target)}/{action}")
        except ApiError as err:
            if err.status == 404 and target not in expanded:  # noqa: PLR2004
                ids = _expand(target)
                expanded.update(ids)
                pending[:0] = ids
                continue
            print(f"{target}: {problem_text(err)}", file=sys.stderr)
            failed = True
            continue
        results.append(data)
        if not structured(args.output):
            print(f"{done} {data['id']}; it's {data['oper_status']}.")
    dump(results, args.output)
    if failed:
        sys.exit(1)


def cmd_connections_stop(args: argparse.Namespace) -> None:
    """Disable connections: enabled is set to false in the configuration."""
    _control(args, "stop", "Stopped")


def cmd_connections_start(args: argparse.Namespace) -> None:
    """Enable connections: enabled is set to true in the configuration."""
    _control(args, "start", "Started")


def cmd_connections_reset(args: argparse.Namespace) -> None:
    """Set VPN connections up again (new IKE SA, WireGuard or SSH session)."""
    _control(args, "reset", "Reset")


def _print_log(line: dict[str, Any], *, source: bool = True) -> None:
    prefix = f"{line['time']}  {line['source']:<6}  " if source else f"{line['time']}  "
    first, *rest = (clean(part) for part in line["message"].split("\n"))
    print(f"{prefix}{line['level']:<7}  {first}")
    for extra in rest:
        print(f"    {extra}")


def show_log(
    args: argparse.Namespace,
    path: str,
    params: dict[str, Any],
    *,
    source: bool = True,
) -> None:
    """Print log lines; with --follow, keep printing new ones."""
    params = {**params, "lines": args.lines}
    if not args.follow:
        data = request("GET", path, params=params)
        if not dump(data, args.output):
            for line in data:
                _print_log(line, source=source)
        return
    for line in stream(path, {**params, "follow": "true"}):
        _print_log(line, source=source)
        sys.stdout.flush()


def cmd_connections_logs(args: argparse.Namespace) -> None:
    """Show a connection's log: vpnc's, SSH's and charon's (IPsec) lines."""
    show_log(args, f"/v1/connections/{quote(args.id)}/logs", {"level": args.level})


def cmd_logs(args: argparse.Namespace) -> None:
    """Show vpnc's log (or vpncmangle's or charon's), or a network instance's."""
    if args.ni:
        if args.source != "vpnc":
            fail("--ni combines vpnc's and charon's lines; leave out --source.")
        path = f"/v1/network-instances/{quote(args.ni)}/logs"
        params: dict[str, Any] = {"level": args.level}
    else:
        path, params = "/v1/logs", {"source": args.source, "level": args.level}
    show_log(args, path, params, source=bool(args.ni))


# The network instances of the service.
SERVICE_NIS = ("CORE", "EXTERNAL", "ENDPOINT")


def event_subject(target: str | None) -> dict[str, str]:
    """Return the events filter for a tenant, network instance or connection."""
    if not target:
        return {}
    if target == "service":
        return {"tenant": "DEFAULT"}
    first, _, rest = target.partition("-")
    if first in SERVICE_NIS:
        return {"connection" if rest else "network_instance": target}
    kinds = ("tenant", "network_instance", "connection")
    return {kinds[min(target.count("-"), 2)]: target}


def _print_event(event: dict[str, Any], *, subject: bool = True) -> None:
    time = dt.datetime.fromisoformat(event["time"]).strftime("%Y-%m-%d %H:%M:%S")
    names = (event[key] for key in ("connection", "network_instance", "tenant"))
    name = f"{next(filter(None, names), '-'):<11}  " if subject else ""
    print(f"{time}  {name}{event['event']:<23}  {clean(event['message'])}")


def cmd_events(args: argparse.Namespace) -> None:
    """Show the event history: all, or of a tenant, network instance or connection."""
    params = {
        **event_subject(args.target),
        "event": args.event,
        "since": args.since,
        "limit": args.lines,
    }
    if not args.follow:
        data = request("GET", "/v1/events", params=params)
        if not dump(data, args.output):
            for event in data:
                _print_event(event)
        return
    for event in stream("/v1/events", {**params, "follow": "true"}):
        _print_event(event)
        sys.stdout.flush()


def _afi_safis(neighbor: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a row per address family of a BGP session, with its prefixes."""
    return [
        {**neighbor, **afi_safi, **afi_safi["prefixes"]}
        for afi_safi in neighbor["afi_safis"]
    ]


def cmd_bgp_neighbor(args: argparse.Namespace) -> None:
    """Show a BGP session in detail."""
    data = request("GET", f"/v1/bgp/neighbors/{quote(args.neighbor)}")
    if dump(data, args.output):
        return
    established = data["last_established"]
    fields(
        [
            ("Neighbor address", data["neighbor_address"]),
            ("Hostname", data["hostname"]),
            ("Peer AS", data["peer_as"]),
            ("Local AS", data["local_as"]),
            ("Session state", data["session_state"]),
            (
                "Last established",
                f"{established} ({age(established)} ago)" if established else None,
            ),
            ("Established transitions", data["established_transitions"]),
            ("Connections dropped", data["connections_dropped"]),
            ("Last reset", data["last_reset"]),
            ("BFD", data["bfd"]),
            ("Hold time", duration(data["hold_time"])),
            ("Keepalive interval", duration(data["keepalive_interval"])),
        ],
    )
    print()
    table(
        _afi_safis(data),
        [("AFI-SAFI", "afi_safi_name"), ("RECEIVED", "received"), ("SENT", "sent")],
    )


def cmd_bgp_routes(args: argparse.Namespace) -> None:
    """Show CORE's BGP table, or the routes received from/advertised to a neighbor."""
    if args.received_from or args.advertised_to:
        neighbor = args.received_from or args.advertised_to
        direction = "received" if args.received_from else "advertised"
        data = request(
            "GET",
            f"/v1/bgp/neighbors/{quote(neighbor)}/routes",
            params={"direction": direction},
        )
    else:
        data = request("GET", "/v1/bgp/routes")
    if not dump(data, args.output):
        columns = [
            ("PREFIX", "prefix"),
            ("NEXT HOP", "next_hops"),
            ("BEST", "best"),
            ("FROM", "learned_from"),
            ("AS PATH", "as_path"),
        ]
        if args.output == "wide":
            columns += [("LOCAL PREF", "local_pref"), ("METRIC", "metric")]
        table(data, columns)


# Troubleshooting inside a network instance.


def cmd_routes(args: argparse.Namespace) -> None:
    """Show a network instance's routes (installed, blackhole etc.)."""
    data = request(
        "GET",
        f"/v1/network-instances/{quote(args.network_instance)}/routes",
        params={"family": args.family},
    )
    if not dump(data, args.output):
        columns = [
            ("PREFIX", "prefix"),
            ("TYPE", "type"),
            ("NEXT HOP", "next_hops"),
            ("INTERFACE", "interfaces"),
            ("PROTOCOL", "protocol"),
        ]
        if args.output == "wide":
            columns.append(("METRIC", "metric"))
        table(data, columns)


def cmd_ping(args: argparse.Namespace) -> None:
    """Ping from a network instance."""
    data = request(
        "POST",
        f"/v1/network-instances/{quote(args.network_instance)}/ping",
        body={
            "destination": args.address,
            "count": args.count,
            "size": args.size,
            "timeout": args.timeout,
        },
    )
    if not dump(data, args.output):
        print(data["output"], end="")
    if not data["received"]:
        sys.exit(1)


def cmd_traceroute(args: argparse.Namespace) -> None:
    """Traceroute from a network instance."""
    data = request(
        "POST",
        f"/v1/network-instances/{quote(args.network_instance)}/traceroute",
        body={"destination": args.address, "max_hops": args.max_hops},
    )
    if not dump(data, args.output):
        print(data["output"], end="")


def cmd_tcp(args: argparse.Namespace) -> None:
    """Test a TCP connection from a network instance."""
    data = request(
        "POST",
        f"/v1/network-instances/{quote(args.network_instance)}/tcp",
        body={"address": args.address, "port": args.port, "timeout": args.timeout},
    )
    if not dump(data, args.output):
        target = f"{data['address']} port {data['port']}"
        if data["connected"]:
            print(f"Connected to {target} in {data['time_ms']} ms.")
        else:
            print(f"Couldn't connect to {target}: {data['error']}.")
    if not data["connected"]:
        sys.exit(1)


def cmd_sessions(args: argparse.Namespace) -> None:
    """Show the sessions through a network instance and how they're translated."""
    data = request(
        "GET",
        f"/v1/network-instances/{quote(args.network_instance)}/sessions",
        params={
            "address": args.address,
            "protocol": args.protocol,
            "limit": args.limit,
        },
    )
    if dump(data, args.output):
        return
    for row in data["sessions"]:
        if row["translated_source"]:
            row["translated"] = (
                f"{row['translated_source']} > {row['translated_destination']}"
            )
        row["expires_in"] = duration(row["expires"])
    table(
        data["sessions"],
        [
            ("TYPE", "type"),
            ("PROTO", "protocol"),
            ("SOURCE", "source"),
            ("DESTINATION", "destination"),
            ("TRANSLATED AS", "translated"),
            ("STATE", "state"),
            ("EXPIRES", "expires_in"),
        ],
    )
    if data["total"] > len(data["sessions"]):
        print(f"{len(data['sessions'])} of {data['total']} shown (--limit).")


def cmd_firewall(args: argparse.Namespace) -> None:
    """Show a network instance's firewall rules with their counters."""
    data = request(
        "GET",
        f"/v1/network-instances/{quote(args.network_instance)}/firewall",
    )
    if dump(data, args.output):
        return
    if args.hits:
        data = [rule for rule in data if rule["packets"]]
    for row in data:
        row["size"] = size(row["bytes"])
    table(
        data,
        [
            ("CHAIN", "chain"),
            ("PACKETS", "packets"),
            ("BYTES", "size"),
            ("RULE", "rule"),
        ],
    )


def cmd_translate(args: argparse.Namespace) -> None:
    """Show an address as admins reach it (LOCAL) and in the tenant (REMOTE)."""
    data = request(
        "GET",
        "/v1/translate",
        params={"address": args.address, "network_instance": args.network_instance},
    )
    if not dump(data, args.output):
        table(
            data,
            [
                ("NETWORK INSTANCE", "network_instance"),
                ("TYPE", "type"),
                ("LOCAL", "local"),
                ("REMOTE", "remote"),
            ],
        )


def cmd_capture(args: argparse.Namespace) -> None:
    """Capture packets with tcpdump on a connection, or in a network instance."""
    if shutil.which("tcpdump") is None:
        fail("tcpdump isn't installed.")
    try:
        connection = request("GET", f"/v1/connections/{quote(args.target)}")
    except ApiError as err:
        if err.status != 404:  # noqa: PLR2004
            raise
        # A network instance: all its interfaces.
        if not pathlib.Path("/run/netns", args.target).exists():
            fail(f"{args.target} isn't a connection or network instance.")
        namespace, interface = args.target, "any"
    else:
        namespace, interface = connection["network_instance"], connection["interface"]
        if interface is None:
            fail(f"{args.target} has no interface.")
    command = ["ip", "netns", "exec", namespace, "tcpdump", "-l", "-n", "-i", interface]
    if args.count:
        command += ["-c", str(args.count)]
    if args.verbose:
        command.append("-" + "v" * args.verbose)
    if args.write:
        # As root: tcpdump otherwise can't write in root's directories.
        command += ["-Z", "root", "-w", args.write]
    sys.stdout.flush()
    # tcpdump takes over: Ctrl-C ends it with its summary.
    os.execvp(command[0], [*command, *args.filter])  # noqa: S606


def cmd_version(args: argparse.Namespace) -> None:
    """Show the versions of vpnctl, vpnc and the software it runs."""
    from vpnc import __version__  # noqa: PLC0415

    try:
        data = request("GET", "/v1/version")
    except ApiError:
        data = {}
    data = {"vpnctl": __version__, **data}
    if not dump(data, args.output):
        fields(
            [
                ("vpnctl", data["vpnctl"]),
                ("vpnc", data.get("vpnc")),
                ("Kernel", data.get("kernel")),
                ("strongSwan", data.get("strongswan")),
                ("FRR", data.get("frr")),
            ],
        )


def cmd_service(args: argparse.Namespace) -> None:
    """Restart or stop vpnc (systemd); start it with systemctl."""
    request("POST", f"/v1/service/{args.service_action}")
    done = "Restarting" if args.service_action == "restart" else "Stopping"
    print(f"{done} vpnc.")


def cmd_bgp_neighbors(args: argparse.Namespace) -> None:
    """List the BGP sessions, per address family."""
    data = request("GET", "/v1/bgp/neighbors")
    if not dump(data, args.output):
        rows = [row for neighbor in data for row in _afi_safis(neighbor)]
        for row in rows:
            row["age"] = age(row["last_established"])
        table(
            rows,
            [
                ("NEIGHBOR ADDRESS", "neighbor_address"),
                ("HOSTNAME", "hostname"),
                ("PEER AS", "peer_as"),
                ("SESSION STATE", "session_state"),
                ("LAST ESTABLISHED", "age"),
                ("AFI-SAFI", "afi_safi_name"),
                ("RECEIVED", "received"),
                ("SENT", "sent"),
            ],
        )


# Configuration commands. Changes are staged in the candidate; commit applies them.


def new_tenant(target: str) -> dict[str, Any]:
    """Return an empty configuration of a tenant, to edit."""
    from vpnc.migration import CURRENT  # noqa: PLC0415

    return {"version": CURRENT, "id": target, "name": "", "network_instances": {}}


def config_path(target: str) -> str:
    """Return the API path of a tenant's or the service's configuration."""
    if target in ("service", "DEFAULT"):
        return "/v1/config/service"
    return f"/v1/config/tenants/{quote(target)}"


def split(path: str | None) -> list[str]:
    """Return the keys of a dotted path, e.g. network_instances.00.type."""
    return [k for k in (path or "").split(".") if k]


def walk(data: Any, keys: list[str], target: str) -> Any:  # noqa: ANN401
    """Return the value at the keys; list items by index."""
    for i, key in enumerate(keys):
        if isinstance(data, list) and key.isdigit() and int(key) < len(data):
            data = data[int(key)]
        elif isinstance(data, dict) and key in data:
            data = data[key]
        else:
            fail(f"{target} has no {'.'.join(keys[: i + 1])}.")
    return data


DELETE = object()


def assign(data: Any, keys: list[str], value: Any, target: str) -> None:  # noqa: ANN401
    """Set (or DELETE) the value at the keys, adding missing mappings."""
    *parents, last = keys
    for i, key in enumerate(parents):
        if isinstance(data, list):
            data = walk(data, [key], target)
        else:
            data = data.setdefault(key, {})
        if not isinstance(data, dict | list):
            fail(f"{'.'.join(keys[: i + 1])} isn't a mapping or list.")
    if isinstance(data, list):
        if not last.isdigit() or int(last) > len(data):
            fail(f"{'.'.join(keys)}: use an index up to {len(data)} (appends).")
        index = int(last)
        if value is DELETE:
            walk(data, [last], target)
            del data[index]
        elif index == len(data):
            data.append(value)
        else:
            data[index] = value
    elif value is DELETE:
        walk(data, [last], target)
        del data[last]
    else:
        data[last] = value


def merge_patch(
    current: dict[str, Any] | None,
    keys: list[str],
    value: Any,  # noqa: ANN401
    target: str,
) -> dict[str, Any]:
    """Return the merge patch that sets (or DELETEs) the value at the keys.

    A merge patch can't address list items: those change the whole list.
    """
    data: Any = current or {}
    for i, key in enumerate(keys):
        if isinstance(data, list):
            changed = json.loads(json.dumps(data))
            assign(changed, keys[i:], value, target)
            keys, value = keys[:i], changed
            break
        data = data.get(key) if isinstance(data, dict) else None
    patch: Any = None if value is DELETE else value
    for key in reversed(keys):
        patch = {key: patch}
    return patch


def staged(target: str, *, reveal: bool = False) -> dict[str, Any] | None:
    """Return the configuration with staged changes; None if there's none."""
    try:
        return request(
            "GET",
            config_path(target),
            params={"revision": "candidate", "reveal_secrets": reveal or None},
        )
    except ApiError as err:
        if err.status != 404:  # noqa: PLR2004
            raise
        return None


def cmd_config_list(args: argparse.Namespace) -> None:
    """List the tenants with configuration and their staged changes."""
    data = request("GET", "/v1/config/tenants")
    if not dump(data, args.output):
        table(
            data,
            [
                ("TENANT", "id"),
                ("NAME", "name"),
                ("STAGED", "status"),
                ("CONFIRM BY", "confirm_by"),
            ],
        )


def cmd_config_show(args: argparse.Namespace) -> None:
    """Show a configuration, or part of it."""
    data = request(
        "GET",
        config_path(args.target),
        params={
            "revision": "candidate" if args.candidate else "active",
            "reveal_secrets": "true" if args.reveal_secrets else None,
        },
    )
    data = walk(data, split(args.path), args.target)
    if structured(args.output):
        dump(data, args.output)
    elif isinstance(data, dict | list):
        dump(data, "yaml")
    else:
        # As it's set: true, not yes.
        print(json.dumps(data) if isinstance(data, bool) else cell(data))


def cmd_config_edit(args: argparse.Namespace) -> None:
    """Edit a configuration, or part of it, in $EDITOR (a new tenant if needed)."""
    import yaml  # noqa: PLC0415

    keys = split(args.path)
    current = staged(args.target, reveal=True) or new_tenant(args.target)
    part = walk(current, keys, args.target) if keys else current
    text = yaml.safe_dump(part, sort_keys=False)
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    with tempfile.TemporaryDirectory() as directory:
        # Read back by path: editors may replace the file instead of writing it.
        path = pathlib.Path(directory, f"{args.target}.yaml")
        path.write_text(text, encoding="utf-8")
        while True:
            subprocess.run([*editor.split(), str(path)], check=False)  # noqa: S603
            edited = path.read_text(encoding="utf-8")
            if edited == text:
                print("No changes.")
                return
            try:
                value = yaml.safe_load(edited)
                if keys:
                    assign(current, keys, value, args.target)
                else:
                    current = value
                request("PUT", config_path(args.target), body=current)
                break
            except yaml.YAMLError as err:
                print(f"Invalid YAML: {err}", file=sys.stderr)
            except ApiError as err:
                print(problem_text(err), file=sys.stderr)
            try:
                again = input("Edit again? [Y/n] ").strip().lower() != "n"
            except EOFError:
                again = False
            if not again:
                fail("aborted; nothing was staged.")
    staged_message(args.target)


def prompt(path: str) -> str:
    """Return a value typed in without echo (twice), or a line from stdin."""
    if not sys.stdin.isatty():
        value = sys.stdin.readline().rstrip("\n")
    else:
        import getpass  # noqa: PLC0415

        value = getpass.getpass(f"{path}: ")
        if getpass.getpass("Again: ") != value:
            fail("The values don't match.")
    if not value:
        fail("No value given.")
    return value


def cmd_generate_psk(_: argparse.Namespace) -> None:
    """Print a new random PSK: 256 bits, as 43 characters."""
    import secrets  # noqa: PLC0415

    print(secrets.token_urlsafe(32))


def cmd_config_set(args: argparse.Namespace) -> None:
    """Set a value at a path, creating missing parts; without one, prompt for it."""
    import yaml  # noqa: PLC0415

    if args.value is None:
        # Taken as is: a secret like 123 or yes stays a string.
        value: Any = prompt(args.path)
    else:
        try:
            value = yaml.safe_load(args.value)
        except yaml.YAMLError as err:
            fail(f"Invalid YAML: {err}")
    keys = split(args.path)
    if not keys:
        fail("Give a path to set.")
    current = staged(args.target, reveal=True)
    patch = merge_patch(current, keys, value, args.target)
    request("PATCH", config_path(args.target), body=patch)
    staged_message(args.target)


def cmd_config_delete(args: argparse.Namespace) -> None:
    """Delete part of a configuration, or (without a path) the tenant."""
    keys = split(args.path)
    if not keys:
        result = request("DELETE", config_path(args.target))
        if not result["changed"]:
            print("No changes.")
            return
    else:
        current = staged(args.target, reveal=True)
        walk(current, keys, args.target)
        patch = merge_patch(current, keys, DELETE, args.target)
        request("PATCH", config_path(args.target), body=patch)
    staged_message(args.target)


def staged_message(target: str) -> None:
    """Print the staged changes and how to apply them."""
    print_diff(target)
    print(f"Staged. Apply with: vpnctl config commit {target}")


def print_diff(target: str) -> None:
    """Print the staged changes."""
    if text := request("GET", f"{config_path(target)}/diff"):
        print(text, end="")
    else:
        print("No changes.")


def cmd_config_diff(args: argparse.Namespace) -> None:
    """Show the staged changes."""
    print_diff(args.target)


def seconds(text: str) -> int:
    """Return the seconds of a duration like 90, 90s, 5m, 1h or 2d."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    try:
        if text[-1:] in units:
            return int(text[:-1]) * units[text[-1]]
        return int(text)
    except ValueError:
        msg = f"invalid duration: {text}"
        raise argparse.ArgumentTypeError(msg) from None


def _all_or_target(args: argparse.Namespace, action: str) -> str | None:
    """Return the API path of the action on the target; None with --all."""
    if args.all == bool(args.target):
        fail("Give a tenant, 'service' or --all.")
    return None if args.all else f"{config_path(args.target)}/{action}"


def cmd_config_commit(args: argparse.Namespace) -> None:
    """Apply the staged changes; with --confirm, roll back unless confirmed."""
    params = {"confirm": args.confirm, "allow_weak": args.allow_weak or None}
    if (path := _all_or_target(args, "commit")) is None:
        results = request("POST", "/v1/config/commit", params=params)
        committed = [r for r in results if r["changed"] or r["confirm_by"]]
        for result in committed:
            confirm = f"; confirm before {result['confirm_by']}"
            print(f"Committed {result['id']}{confirm if result['confirm_by'] else ''}.")
        if not committed:
            print("No changes.")
        elif args.confirm:
            print("Confirm with: vpnctl config confirm --all, or they're rolled back.")
        for result in results:
            commit_notices(result)
        return
    result = request("POST", path, params=params)
    if result.get("confirm_by"):
        print(
            f"Committed. Confirm before {result['confirm_by']} with: "
            f"vpnctl config confirm {args.target}, or it's rolled back.",
        )
    else:
        print("Committed." if result["changed"] else "No changes.")
    commit_notices(result)


def commit_notices(result: dict[str, Any]) -> None:
    """Say what was committed weak, and which service settings need a restart."""
    for warning in result.get("warnings") or []:
        print(f"Weak cryptography: {warning}")
    if fields_ := result.get("restart_needed"):
        print(
            f"Restart vpnc to apply {', '.join(fields_)}: vpnctl service restart",
        )


def cmd_config_confirm(args: argparse.Namespace) -> None:
    """Confirm a commit, so it isn't rolled back."""
    if (path := _all_or_target(args, "confirm")) is None:
        results = request("POST", "/v1/config/confirm")
        print(
            f"Confirmed {', '.join(r['id'] for r in results)}."
            if results
            else "No commits to confirm."
        )
        return
    request("POST", path)
    print("Confirmed.")


def cmd_config_history(args: argparse.Namespace) -> None:
    """List the earlier active configurations, or show one."""
    if args.revision is not None:
        data = request(
            "GET",
            f"{config_path(args.target)}/history/{args.revision}",
            params={"reveal_secrets": "true" if args.reveal_secrets else None},
        )
        dump(data, args.output if structured(args.output) else "yaml")
        return
    data = request("GET", f"{config_path(args.target)}/history")
    if not dump(data, args.output):
        table(
            data,
            [("REVISION", "revision"), ("REPLACED", "replaced"), ("EXISTS", "exists")],
        )


def cmd_config_restore(args: argparse.Namespace) -> None:
    """Stage an earlier active configuration."""
    request("POST", f"{config_path(args.target)}/history/{args.revision}/restore")
    staged_message(args.target)


def cmd_config_discard(args: argparse.Namespace) -> None:
    """Drop the staged changes."""
    if (path := _all_or_target(args, "discard")) is None:
        results = request("POST", "/v1/config/discard")
        print(
            f"Discarded the changes of {', '.join(r['id'] for r in results)}."
            if results
            else "No changes.",
        )
        return
    result = request("POST", path)
    print("Discarded the changes." if result["changed"] else "No changes.")


# Completion.

BASH_COMPLETION = """\
_vpnctl() {
    local IFS=$'\\n'
    local lines
    lines=$(vpnctl __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null)
    # With a description (after a tab): in the order given.
    [[ $lines == *$'\\t'* ]] && compopt -o nosort
    COMPREPLY=($(cut -f1 <<< "$lines"))
    # A path that goes on: no space after it.
    [[ ${#COMPREPLY[@]} -eq 1 && ${COMPREPLY[0]} == *. ]] && compopt -o nospace
}
complete -F _vpnctl vpnctl
"""

ZSH_COMPLETION = """\
#compdef vpnctl
_vpnctl() {
    local -a lines text group
    local line value
    lines=(${(f)"$(vpnctl __complete "${(@)words[2,CURRENT]}" 2>/dev/null)"})
    # With a description (after a tab): one per line, in the order given.
    group=(-J vpnctl)
    [[ "$lines" == *$'\\t'* ]] && group=(-V vpnctl -l)
    for line in $lines; do
        value=${line%%$'\\t'*}
        text=("${line#*$'\\t'}")
        if [[ $value == *. ]]; then
            # A path that goes on: no space after it.
            compadd $group -S '' -d text -- $value
        else
            compadd $group -d text -- $value
        fi
    done
}
if [[ "$funcstack[1]" = "_vpnctl" ]]; then
    _vpnctl "$@"
else
    compdef _vpnctl vpnctl
fi
"""

# Values are upper case, as in the API; lower case is accepted.
ADMIN_STATUSES = ["UP", "DOWN"]
OPER_STATUSES = ["UP", "DOWN", "DORMANT"]
TYPES = ["IPSEC", "WIREGUARD", "SSH", "PHYSICAL"]
OUTPUTS = ["table", "wide", "json", "yaml"]
SOURCES = ["vpnc", "vpncmangle", "charon"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "ICMPV6"]
LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Per command its actions, and per action what its argument completes to.
COMMANDS: dict[str, dict[str, str | None]] = {
    "status": {},
    "tenants": {"list": None, "show": "tenant", "events": "tenant"},
    "ni": {"list": "tenant", "show": "network_instance", "events": "network_instance"},
    "network-instances": {
        "list": "tenant",
        "show": "network_instance",
        "events": "network_instance",
    },
    "connections": {
        "list": "filter",
        "show": "connection",
        "stop": "control",
        "start": "control",
        "reset": "control",
        "restart": "control",
        "logs": "connection",
        "events": "connection",
        "diagnose": "connection",
        "probes": "connection",
        "ssh-setup": "connection",
    },
    "bgp": {"neighbors": None, "neighbor": "neighbor", "routes": None},
    # Commands with an argument instead of actions.
    "routes": {},
    "ping": {},
    "traceroute": {},
    "tcp": {},
    "translate": {},
    "sessions": {},
    "firewall": {},
    "capture": {},
    "logs": {},
    "events": {},
    "version": {},
    "generate": {"psk": None},
    "service": {"restart": None, "stop": None},
    "config": {
        "list": None,
        "show": "target",
        "edit": "target",
        "set": "target",
        "delete": "target",
        "diff": "target",
        "commit": "target",
        "confirm": "target",
        "discard": "target",
        "history": "target",
        "restore": "target",
    },
    "completion": {"bash": None, "zsh": None},
}
# Commands whose first argument is a network instance.
NI_COMMANDS = (
    "routes",
    "ping",
    "traceroute",
    "tcp",
    "translate",
    "sessions",
    "firewall",
)
# Actions taking several ids.
MULTIPLE = ("stop", "start", "reset", "restart")
# Options whose values come from the API.
OPTION_IDS = {
    "--received-from": "neighbor",
    "--advertised-to": "neighbor",
    "--ni": "network_instance",
}
OPTION_VALUES = {
    "-o": OUTPUTS,
    "--output": OUTPUTS,
    "--admin-status": ADMIN_STATUSES,
    "--oper-status": OPER_STATUSES,
    "--type": TYPES,
    "--confirm": ["1m", "5m", "10m"],
    "--source": SOURCES,
    "--level": LEVELS,
    "--event": [],
    "--since": ["10m", "1h", "1d"],
    "--username": [],
    "--interface": [],
    "-c": [],
    "--count": [],
    "-s": [],
    "--size": [],
    "-W": [],
    "-m": [],
    "--max-hops": [],
    "-t": [],
    "--timeout": [],
    "-n": [],
    "--lines": [],
    "-w": [],
    "--write": [],
    "-p": PROTOCOLS,
    "--protocol": PROTOCOLS,
    "-l": [],
    "--limit": [],
}


def _ids(kind: str) -> list[str]:
    """Return the ids an argument completes to, from the API."""
    keys = {
        "tenant": ["tenants"],
        "network_instance": ["network_instances"],
        "connection": ["connections"],
        "filter": ["tenants", "network_instances"],
        "target": ["config_tenants"],
        "control": ["tenants", "network_instances", "connections"],
        "capture": ["network_instances", "connections"],
        "events": ["tenants", "network_instances", "connections"],
    }.get(kind, [])
    if kind == "neighbor":
        return [n["neighbor"] for n in request("GET", "/v1/bgp/neighbors")]
    # Without their state, which takes longer to read.
    data = request("GET", "/v1/ids")
    ids = [item for key in keys for item in data[key]]
    return [*ids, "service"] if kind == "target" else ids


def complete(words: list[str]) -> list[str]:
    """Return the completions of the last word (as far as typed), after the others.

    A completion may have a description, after a tab.
    """
    *before, current = words or [""]
    return [word for word in candidates(before, current) if word.startswith(current)]


def candidates(words: list[str], current: str) -> list[str]:  # noqa: PLR0911
    """Return what the word after words can be; current is typed so far."""
    if words and words[-1] in OPTION_IDS:
        return _ids(OPTION_IDS[words[-1]])
    if words and words[-1] in OPTION_VALUES:
        return OPTION_VALUES[words[-1]]
    takes_value = {*OPTION_VALUES, *OPTION_IDS}
    positional = [
        w
        for i, w in enumerate(words)
        if not w.startswith("-") and (i == 0 or words[i - 1] not in takes_value)
    ]
    if not positional:
        return [c for c in COMMANDS if c != "network-instances"]
    if positional[0] in NI_COMMANDS:
        return _ids("network_instance") if len(positional) == 1 else []
    if positional[0] in ("capture", "events"):
        return _ids(positional[0]) if len(positional) == 1 else []
    actions = COMMANDS.get(positional[0], {})
    if len(positional) == 1:
        return list(actions)
    kind = actions.get(positional[1])
    if kind and (len(positional) == 2 or positional[1] in MULTIPLE):  # noqa: PLR2004
        return _ids(kind)
    if positional[0] == "config" and positional[1] in PATH_ACTIONS:
        return config_candidates(positional[1], positional[2:], current)
    return []


PATH_ACTIONS = ("show", "edit", "set", "delete")

# Completion of configuration paths and values, from the JSON Schema.

# How the formats of values are described.
FORMATS = {
    "ipv4": "IPv4 address",
    "ipv6": "IPv6 address",
    "ipv4network": "IPv4 prefix",
    "ipv6network": "IPv6 prefix",
    "ipv4interface": "IPv4 address/length",
    "ipv6interface": "IPv6 address/length",
    "password": "secret",
}


def scalar(value: Any) -> str | None:  # noqa: ANN401
    """Return a value as it's typed in, e.g. true; None if it isn't a single word."""
    if value is None or isinstance(value, dict | list):
        return None
    text = json.dumps(value) if isinstance(value, bool) else str(value)
    return text if text and not any(c.isspace() for c in text) else None


def choices(schema: dict[str, Any]) -> list[str]:
    """Return the values a schema limits to, as they're typed in."""
    if schema.get("type") == "boolean":
        return ["true", "false"]
    values = schema.get("enum") or ([schema["const"]] if "const" in schema else [])
    return [str(scalar(value)) for value in values]


class Node:
    """A place in a configuration: what the schema allows there, and what's set."""

    def __init__(
        self,
        root: dict[str, Any],
        schema: dict[str, Any],
        data: Any,  # noqa: ANN401
        *,
        required: bool = False,
        added: bool = False,
    ) -> None:
        """Take the schema as the parent has it: with the default.

        An added one isn't there yet: it's set as a whole.
        """
        self.root = root
        self.schema = schema
        self.data = data
        self.required = required
        self.added = added
        self.options = self._variants(schema)
        self.variants = self._selected()

    def _variants(self, schema: dict[str, Any]) -> list[dict[str, Any]]:
        """Return the schemas a value can follow, except null."""
        if ref := schema.get("$ref"):
            return self._variants(self.root["$defs"][ref.rpartition("/")[2]])
        if options := schema.get("anyOf") or schema.get("oneOf"):
            return [v for option in options for v in self._variants(option)]
        return [] if schema.get("type") == "null" else [schema]

    def _selected(self) -> list[dict[str, Any]]:
        """Return the options what's set fits, e.g. the one of a connection's type."""
        if not isinstance(self.data, dict):
            return self.options
        selected = [
            option
            for option in self.options
            if all(
                str(self.data[key]).upper() == str(schema["const"]).upper()
                for key, schema in option.get("properties", {}).items()
                if "const" in schema and self.data.get(key) is not None
            )
        ]
        return selected or self.options

    @property
    def container(self) -> bool:
        """Return whether it has keys or items below it."""
        return not self.added and (
            isinstance(self.data, dict | list)
            or any(v.get("type") in ("object", "array") for v in self.variants)
        )

    @property
    def secret(self) -> bool:
        """Return whether its value is a secret."""
        return any(v.get("format") == "password" for v in self.variants)

    def _set(self, key: str) -> tuple[bool, Any]:
        """Return whether a key or index is set, and to what."""
        data = self.data
        if isinstance(data, dict) and key in data:
            return True, data[key]
        if isinstance(data, list) and key.isdigit() and int(key) < len(data):
            return True, data[int(key)]
        return False, None

    def _property(self, variant: dict[str, Any], key: str) -> dict[str, Any]:
        """Return a key's schema; of a key that selects the option: all its values."""
        values = [
            option["properties"][key]["const"]
            for option in self.options
            if "const" in option.get("properties", {}).get(key, {})
        ]
        return {"enum": values} if len(values) > 1 else variant["properties"][key]

    def children(self, *, new: bool) -> dict[str, Node]:
        """Return what's below it by key; with new, also what can be set or added."""
        if self.added:
            return {}
        # Per key: its schema, whether it's required and whether it's added.
        found: dict[str, tuple[Any, bool, bool]] = {}
        for variant in self.variants:
            required = variant.get("required", [])
            for key in variant.get("properties", {}):
                schema = self._property(variant, key)
                found.setdefault(key, (schema, key in required, False))
            if variant.get("type") == "array":
                count = len(self.data) if isinstance(self.data, list) else 0
                keys, more = [str(index) for index in range(count)], [str(count)]
                schema = variant.get("items")
            else:
                schema = variant.get("additionalProperties")
                mapping = schema and isinstance(self.data, dict)
                keys = [str(key) for key in self.data] if mapping else []
                more = next_key(keys)
            for key in keys:
                found.setdefault(key, (schema, False, False))
            for key in more:
                found.setdefault(key, (schema, False, True))
        return {
            key: Node(
                self.root,
                schema if isinstance(schema, dict) else {},
                self._set(key)[1],
                required=required,
                added=added,
            )
            for key, (schema, required, added) in found.items()
            if new or self._set(key)[0]
        }

    def kind(self) -> str:
        """Return the values it takes, e.g. integer 1280-65535."""
        return " | ".join(dict.fromkeys(filter(None, map(self._kind, self.variants))))

    def _kind(self, schema: dict[str, Any]) -> str:
        if fixed := choices(schema):
            return " | ".join(fixed)
        kind = str(schema.get("type", ""))
        if kind == "array":
            items = Node(self.root, schema.get("items") or {}, None).kind()
            return f"list of {items}" if items else "list"
        if schema.get("format") in FORMATS:
            return FORMATS[schema["format"]]
        if kind == "integer" and "minimum" in schema and "maximum" in schema:
            return f"integer {schema['minimum']}-{schema['maximum']}"
        return "" if kind == "object" else kind

    def _needs(self) -> str:
        """Return the keys a mapping that's added must have, if it's of one kind."""
        required = self.variants[0].get("required") if len(self.variants) == 1 else []
        return f"needs {', '.join(required)}" if self.added and required else ""

    def text(self) -> str:
        """Return its value and what it takes, e.g. 300 (integer, default 86400)."""
        value = None if self.secret else scalar(self.data)
        default = scalar(self.schema.get("default"))
        kind = self.kind()
        notes = [
            "new" if self.added else "",
            kind if kind != value else "",
            self._needs(),
            "required" if self.required and self.data is None else "",
            f"default {default}" if default not in (None, value) else "",
        ]
        details = ", ".join(note for note in notes if note)
        return " ".join(filter(None, [value, f"({details})" if details else ""]))

    def values(self) -> list[tuple[str, str]]:
        """Return the values to offer, each with what it is (current, default)."""
        if self.secret:
            return []
        found: dict[str, list[str]] = {
            choice: [] for variant in self.variants for choice in choices(variant)
        }
        current, default = scalar(self.data), scalar(self.schema.get("default"))
        for value, note in ((current, "current"), (default, "default")):
            if value is not None:
                found.setdefault(value, []).append(note)
        return [(value, ", ".join(notes)) for value, notes in found.items()]


def next_key(keys: list[str]) -> list[str]:
    """Return the key after numbered ones (e.g. 01 after 00), to add an item."""
    if not keys or not all(key.isdigit() for key in keys):
        return []
    return [f"{max(map(int, keys)) + 1:0{len(keys[0])}d}"]


def config_node(target: str, keys: list[str], *, new: bool) -> Node | None:
    """Return the place in a configuration (with staged changes) at the keys."""
    schema = request("GET", f"{config_path(target)}/schema")
    node: Node | None = Node(schema, schema, staged(target) or {})
    for key in keys:
        if node is None:
            break
        node = node.children(new=new).get(key)
    return node


def described(items: list[tuple[str, str, str]]) -> list[str]:
    """Return completions (word, name, text) with name and text as description."""
    width = max((len(name) for _, name, _ in items), default=0)
    return [
        f"{word}\t{f'{name:<{width}}  {text}'.rstrip()}" for word, name, text in items
    ]


def path_candidates(target: str, current: str, *, new: bool) -> list[str]:
    """Return the paths one level below what's typed; new: also what can be set."""
    prefix = current[: current.rfind(".") + 1]
    if (node := config_node(target, split(prefix), new=new)) is None:
        return []
    return described(
        [
            (f"{prefix}{key}{'.' * child.container}", key, child.text())
            for key, child in node.children(new=new).items()
        ],
    )


def value_candidates(target: str, path: str) -> list[str]:
    """Return the values a path can be set to: choices, the current and default."""
    if (node := config_node(target, split(path), new=True)) is None:
        return []
    return described([(value, value, note) for value, note in node.values()])


def config_candidates(action: str, arguments: list[str], current: str) -> list[str]:
    """Return the paths after a target, or the values after a path to set."""
    new = action == "set"
    if len(arguments) == 1:
        return path_candidates(arguments[0], current, new=new)
    if len(arguments) == 2 and new:  # noqa: PLR2004
        return value_candidates(*arguments)
    return []


def cmd_completion(args: argparse.Namespace) -> None:
    """Print the shell completion script."""
    print(ZSH_COMPLETION if args.script == "zsh" else BASH_COMPLETION, end="")


# Arguments.


def log_options(p: argparse.ArgumentParser) -> None:
    """Add the options of the log commands."""
    p.add_argument(
        "--level",
        type=str.upper,
        choices=LEVELS,
        default="INFO",
        help="at least (not for charon's lines)",
    )
    p.add_argument("-n", "--lines", type=int, default=50, help="default: 50")
    p.add_argument("-f", "--follow", action="store_true", help="print new lines")


def event_options(p: argparse.ArgumentParser) -> None:
    """Add the options of the events commands."""
    p.add_argument("--event", type=str.upper, help="only these, e.g. OPER_DOWN")
    p.add_argument("--since", type=seconds, metavar="TIME", help="e.g. 30m, 6h or 2d")
    p.add_argument("-n", "--lines", type=int, default=50, help="default: 50")
    p.add_argument("-f", "--follow", action="store_true", help="print new events")


def parser() -> argparse.ArgumentParser:  # noqa: PLR0915 (one statement per option)
    """Return the argument parser."""
    # Before or after the command; a subcommand's default mustn't override it.
    output = argparse.ArgumentParser(add_help=False)
    output.add_argument(
        "-o",
        "--output",
        choices=OUTPUTS,
        default=argparse.SUPPRESS,
        help="output format (default: table)",
    )
    main = argparse.ArgumentParser(
        prog="vpnctl",
        description="Show vpnc's state and edit its configuration.",
        parents=[output],
    )
    commands = main.add_subparsers(dest="command", metavar="COMMAND", required=True)

    def add(
        sub: Any,  # noqa: ANN401
        name: str,
        func: Any,  # noqa: ANN401
        aliases: list[str] | None = None,
    ) -> argparse.ArgumentParser:
        p = sub.add_parser(
            name,
            help=func.__doc__.splitlines()[0].rstrip("."),
            aliases=aliases or [],
            parents=[output],
        )
        p.set_defaults(func=func)
        return p

    def group(name: str, text: str, aliases: list[str] | None = None) -> Any:  # noqa: ANN401
        p = commands.add_parser(name, help=text, aliases=aliases or [])
        return p.add_subparsers(dest="action", metavar="ACTION", required=True)

    add(commands, "status", cmd_status)

    tenants = group("tenants", "tenants")
    add(tenants, "list", cmd_tenants_list)
    add(tenants, "show", cmd_tenants_show).add_argument("id", help="e.g. C0001")
    p = add(tenants, "events", cmd_events)
    p.add_argument("target", metavar="id", help="e.g. C0001")
    event_options(p)

    ni = group("ni", "network instances", aliases=["network-instances"])
    add(ni, "list", cmd_ni_list).add_argument("tenant", nargs="?", help="e.g. C0001")
    add(ni, "show", cmd_ni_show).add_argument("id", help="e.g. C0001-00")
    p = add(ni, "events", cmd_events)
    p.add_argument("target", metavar="id", help="e.g. C0001-00")
    event_options(p)

    connections = group("connections", "connections")
    p = add(connections, "list", cmd_connections_list)
    p.add_argument(
        "filter", nargs="?", help="a tenant (C0001) or network instance (C0001-00)"
    )
    p.add_argument("--admin-status", type=str.upper, choices=ADMIN_STATUSES)
    p.add_argument("--oper-status", type=str.upper, choices=OPER_STATUSES)
    p.add_argument("--type", type=str.upper, choices=TYPES)
    connection = {"help": "e.g. C0001-00-0 or CORE-0"}
    add(connections, "show", cmd_connections_show).add_argument("id", **connection)
    p = add(connections, "diagnose", cmd_connections_diagnose)
    p.add_argument("id", **connection)
    for name, func, aliases in (
        ("stop", cmd_connections_stop, []),
        ("start", cmd_connections_start, []),
        ("reset", cmd_connections_reset, ["restart"]),
    ):
        add(connections, name, func, aliases=aliases).add_argument(
            "ids",
            nargs="+",
            metavar="ID",
            help="connections, or network instances/tenants: their VPN connections",
        )
    add(connections, "probes", cmd_connections_probes).add_argument("id", **connection)
    p = add(connections, "ssh-setup", cmd_connections_ssh_setup)
    p.add_argument("id", **connection)
    p.add_argument("--username", help="the account (default: the connection's)")
    p.add_argument(
        "--interface",
        help="masquerade out of it (default: remote_config_interface)",
    )
    p = add(connections, "logs", cmd_connections_logs)
    p.add_argument("id", **connection)
    log_options(p)
    p = add(connections, "events", cmd_events)
    p.add_argument("target", metavar="id", **connection)
    event_options(p)

    bgp = group("bgp", "BGP (hub mode)")
    add(bgp, "neighbors", cmd_bgp_neighbors)
    add(bgp, "neighbor", cmd_bgp_neighbor).add_argument("neighbor", help="address")
    p = add(bgp, "routes", cmd_bgp_routes)
    direction = p.add_mutually_exclusive_group()
    direction.add_argument("--received-from", metavar="NEIGHBOR", help="before policy")
    direction.add_argument("--advertised-to", metavar="NEIGHBOR")

    ni_help = {"help": "e.g. C0001-00 or CORE"}
    p = add(commands, "routes", cmd_routes)
    p.add_argument("network_instance", **ni_help)
    family = p.add_mutually_exclusive_group()
    family.add_argument("-4", dest="family", action="store_const", const=4)
    family.add_argument("-6", dest="family", action="store_const", const=6)
    p = add(commands, "ping", cmd_ping)
    p.add_argument("network_instance", **ni_help)
    p.add_argument("address")
    p.add_argument("-c", "--count", type=int, default=5, help="default: 5")
    p.add_argument("-s", "--size", type=int, default=56, help="default: 56")
    p.add_argument("-W", "--timeout", type=float, default=1, help="per reply (s)")
    p = add(commands, "traceroute", cmd_traceroute)
    p.add_argument("network_instance", **ni_help)
    p.add_argument("address")
    p.add_argument("-m", "--max-hops", type=int, default=20, help="default: 20")
    p = add(commands, "tcp", cmd_tcp)
    p.add_argument("network_instance", **ni_help)
    p.add_argument("address")
    p.add_argument("port", type=int)
    p.add_argument("-t", "--timeout", type=float, default=3, help="default: 3s")
    p = add(commands, "sessions", cmd_sessions)
    p.add_argument("network_instance", **ni_help)
    p.add_argument("address", nargs="?", help="only sessions with this address")
    p.add_argument("-p", "--protocol", type=str.upper, choices=PROTOCOLS)
    p.add_argument("-l", "--limit", type=int, default=1000, help="default: 1000")
    p = add(commands, "firewall", cmd_firewall)
    p.add_argument("network_instance", **ni_help)
    p.add_argument("--hits", action="store_true", help="only rules that matched")
    p = add(commands, "translate", cmd_translate)
    p.add_argument(
        "network_instance",
        nargs="?",
        help="e.g. C0001-00; required for a tenant's IPv4 address",
    )
    p.add_argument("address", help="as admins reach it, or in the tenant")

    p = add(commands, "capture", cmd_capture)
    p.add_argument("target", help="a connection (C0001-00-0) or network instance")
    p.add_argument(
        "filter",
        nargs="*",
        metavar="TCPDUMP",
        help="tcpdump's options and filter, e.g. -e port 443",
    )
    p.add_argument("-c", "--count", type=int, help="stop after this many packets")
    p.add_argument("-v", "--verbose", action="count", default=0, help="up to -vvv")
    p.add_argument("-w", "--write", metavar="FILE", help="a pcap file ('-': stdout)")

    p = add(commands, "logs", cmd_logs)
    p.add_argument("--source", choices=SOURCES, default="vpnc")
    p.add_argument(
        "--ni",
        metavar="NETWORK_INSTANCE",
        help="its lines and its connections' (vpnc's, ssh's and charon's)",
    )
    log_options(p)
    p = add(commands, "events", cmd_events)
    p.add_argument(
        "target",
        nargs="?",
        help="a tenant (C0001), network instance (C0001-00), connection "
        "(C0001-00-0) or 'service'; default: all",
    )
    event_options(p)

    add(commands, "version", cmd_version)
    generate = group("generate", "make a secret")
    add(generate, "psk", cmd_generate_psk)
    p = add(commands, "service", cmd_service)
    p.add_argument("service_action", choices=["restart", "stop"])

    shell = group("completion", "shell completion")
    add(shell, "bash", cmd_completion).set_defaults(script="bash")
    add(shell, "zsh", cmd_completion).set_defaults(script="zsh")

    cfg = group("config", "configuration: stage changes, then commit them")
    add(cfg, "list", cmd_config_list)
    target = {"help": "a tenant (e.g. C0001) or 'service'"}
    path = {"help": "dotted, e.g. network_instances.00.connections.0"}
    p = add(cfg, "show", cmd_config_show)
    p.add_argument("target", **target)
    p.add_argument("path", nargs="?", **path)
    p.add_argument("--candidate", action="store_true", help="with staged changes")
    p.add_argument("--reveal-secrets", action="store_true")
    p = add(cfg, "edit", cmd_config_edit)
    p.add_argument("target", **target)
    p.add_argument("path", nargs="?", **path)
    p = add(cfg, "set", cmd_config_set)
    p.add_argument("target", **target)
    p.add_argument("path", **path)
    p.add_argument(
        "value",
        nargs="?",
        help="YAML, e.g. 10.0.0.1, '[a, b]' or '{to: ::/0}'; "
        "without it, prompted for as text (e.g. a secret)",
    )
    p = add(cfg, "delete", cmd_config_delete)
    p.add_argument("target", **target)
    p.add_argument("path", nargs="?", **path)
    add(cfg, "diff", cmd_config_diff).add_argument("target", **target)
    for name, func in (
        ("commit", cmd_config_commit),
        ("confirm", cmd_config_confirm),
        ("discard", cmd_config_discard),
    ):
        p = add(cfg, name, func)
        p.add_argument("target", nargs="?", **target)
        p.add_argument("--all", action="store_true", help="all tenants and service")
    p = cfg.choices["commit"]
    p.add_argument(
        "--confirm",
        type=seconds,
        metavar="TIME",
        help="roll back unless confirmed within TIME, e.g. 5m",
    )
    p.add_argument(
        "--allow-weak",
        action="store_true",
        help="accept a short PSK, IKEv1 or weak algorithms in what's committed",
    )
    p = add(cfg, "history", cmd_config_history)
    p.add_argument("target", **target)
    p.add_argument("revision", nargs="?", type=int, help="show this revision")
    p.add_argument("--reveal-secrets", action="store_true")
    p = add(cfg, "restore", cmd_config_restore)
    p.add_argument("target", **target)
    p.add_argument("revision", type=int, help="see: vpnctl config history")
    return main


# vpnctl capture's own options; the ones in the first take a value.
CAPTURE_OPTIONS = ("-c", "--count", "-w", "--write", "-o", "--output")
CAPTURE_FLAGS = ("-h", "--help")


def capture_arguments(words: list[str]) -> list[str]:
    """Return capture's arguments with tcpdump's (options and filter) after '--'.

    So tcpdump's own options can be given as they are, e.g. -e or -s 96.
    """
    own: list[str] = []
    rest: list[str] = []
    target = False
    words = list(words)
    while words:
        word = words.pop(0)
        if word == "--":
            rest += words
            break
        if word in CAPTURE_OPTIONS and words:
            own += [word, words.pop(0)]
        elif (
            word in CAPTURE_FLAGS
            or word.strip("v") == "-"
            or word.startswith(("--count=", "--write=", "--output="))
        ):
            own.append(word)
        elif not target and not word.startswith("-"):
            own.append(word)
            target = True
        else:
            rest.append(word)
    return [*own, "--", *rest]


def main() -> None:
    """Run vpnctl."""
    if sys.argv[1:2] == ["__complete"]:
        with contextlib.suppress(ApiError, SystemExit):
            print("\n".join(complete(sys.argv[2:])))
        return
    words = sys.argv[1:]
    if words[:1] == ["capture"]:
        words = ["capture", *capture_arguments(words[1:])]
    args = parser().parse_args(words)
    args.output = getattr(args, "output", "table")
    try:
        args.func(args)
    except ApiError as err:
        fail(problem_text(err))
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # Output piped into e.g. head.
        sys.stdout = None  # type: ignore[assignment]


if __name__ == "__main__":
    main()
