"""vpnctl: show vpnc's state and edit its configuration through the local API.

Only the standard library is imported up front (PyYAML when needed), so commands
start fast.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import pathlib
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


def clean(text: str) -> str:
    """Return text without control characters (e.g. a peer's terminal escapes)."""
    return "".join(c if c.isprintable() else "?" for c in text)


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
            ("Connections", f"{data['connections_up']}/{data['connections']} up"),
            *(
                [("vpncmangle", vpncmangle_text(data["vpncmangle"]))]
                if data.get("vpncmangle")
                else []
            ),
            *(
                [
                    (
                        "Restart needed",
                        f"{', '.join(data['restart_needed'])} changed "
                        "(vpnctl service restart)",
                    ),
                ]
                if data.get("restart_needed")
                else []
            ),
        ],
    )


def vpncmangle_text(state: dict[str, Any]) -> str:
    """Return vpncmangle's state, e.g. running, 12 translations."""
    running = "running" if state["running"] else "not running"
    return f"{running}, {state['translations']} translations"


def _up(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "up": f"{row['connections_up']}/{row['connections']}"}


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
            ("Connections", f"{data['connections_up']}/{data['connections']} up"),
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
            ("Connections", f"{data['connections_up']}/{data['connections']} up"),
            ("NAT64 scope", data.get("nat64_scope")),
            ("NPTv6 scope", data.get("nptv6_scope")),
        ],
    )
    if data.get("translations"):
        print()
        table(
            data["translations"],
            [("TRANSLATION", "type"), ("LOCAL", "local"), ("REMOTE", "remote")],
        )


def _filter(prefix: str | None) -> dict[str, str | None]:
    """Return the filter for a tenant (C0001) or network instance (C0001-00)."""
    if prefix is None:
        return {}
    if "-" in prefix or prefix in ("CORE", "EXTERNAL", "ENDPOINT"):
        return {"network_instance": prefix}
    return {"tenant": prefix}


def cmd_connections_list(args: argparse.Namespace) -> None:
    """List the connections."""
    wide = args.output == "wide"
    data = request(
        "GET",
        "/v1/connections",
        params={
            **_filter(args.filter),
            "state": args.state,
            "type": args.type,
            "counters": "true" if wide or args.output in ("json", "yaml") else None,
        },
    )
    if not dump(data, args.output):
        columns = [
            ("CONNECTION", "id"),
            ("TYPE", "type"),
            ("STATE", "state"),
            ("REMOTE", "remote"),
            ("INTERFACE", "interface"),
        ]
        if wide:
            columns += [("RX", "rx"), ("TX", "tx"), ("ADDRESSES", "addresses")]
            for row in data:
                counters = row.get("counters") or {}
                row["rx"] = size(counters.get("rx_bytes"))
                row["tx"] = size(counters.get("tx_bytes"))
        table(data, columns)


def cmd_connections_show(args: argparse.Namespace) -> None:
    """Show a connection."""
    data = request("GET", f"/v1/connections/{quote(args.id)}")
    if dump(data, args.output):
        return
    details = data.get("details") or {}
    items: list[tuple[str, Any]] = [
        ("Connection", data["id"]),
        ("Tenant", data["tenant"]),
        ("Network instance", data["network_instance"]),
        ("Type", data["type"]),
        ("State", data["state"]),
        ("Remote", data.get("remote")),
        ("Interface", data.get("interface")),
        ("Addresses", data.get("addresses")),
    ]
    if "ike_state" in details:
        items += [
            ("IKE state", details["ike_state"]),
            ("Established", duration(details.get("established_seconds"))),
            (
                "Child SAs",
                [f"{c['name']} {c['state']}" for c in details.get("child_sas", [])],
            ),
        ]
    if "last_handshake_seconds_ago" in details:
        ago = details["last_handshake_seconds_ago"]
        items.append(("Last handshake", f"{duration(ago)} ago" if ago else "never"))
    if "uptime_seconds" in details:
        items.append(("Uptime", duration(details["uptime_seconds"])))
    if "auto_resets_24h" in details:
        items.append(("Auto resets (24h)", details["auto_resets_24h"]))
    if counters := data.get("counters"):
        for label, direction in (("Received", "rx"), ("Sent", "tx")):
            items.append(
                (
                    label,
                    f"{size(counters[f'{direction}_bytes'])} "
                    f"({counters[f'{direction}_packets']} packets, "
                    f"{counters[f'{direction}_errors']} errors, "
                    f"{counters[f'{direction}_dropped']} dropped)",
                ),
            )
    fields(items)


def _expand(target: str) -> list[str]:
    """Return a network instance's or tenant's VPN connections (not physical)."""
    ids = [
        c["id"]
        for c in request("GET", "/v1/connections", params=_filter(target))
        if c["type"] != "physical"
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
        if args.output not in ("json", "yaml"):
            print(f"{done} {data['id']}; it's {data['state']}.")
    dump(results, args.output)
    if failed:
        sys.exit(1)


def cmd_connections_stop(args: argparse.Namespace) -> None:
    """Stop VPN connections until they're started again, or vpnc restarts."""
    _control(args, "stop", "Stopped")


def cmd_connections_start(args: argparse.Namespace) -> None:
    """Start stopped VPN connections."""
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


def cmd_bgp_neighbor(args: argparse.Namespace) -> None:
    """Show a BGP session in detail."""
    data = request("GET", f"/v1/bgp/neighbors/{quote(args.neighbor)}")
    if dump(data, args.output):
        return
    fields(
        [
            ("Neighbor", data["neighbor"]),
            ("Hostname", data["hostname"]),
            ("Remote AS", data["remote_as"]),
            ("Local AS", data["local_as"]),
            ("State", data["state"]),
            ("Uptime", data["uptime"]),
            ("BFD", data["bfd"]),
            ("Hold time", duration(data["hold_time_seconds"])),
            ("Keepalive", duration(data["keepalive_seconds"])),
            ("Established", data["connections_established"]),
            ("Dropped", data["connections_dropped"]),
            ("Last reset", data["last_reset"]),
        ],
    )
    print()
    table(
        data["address_families"],
        [("FAMILY", "family"), ("ACCEPTED", "accepted"), ("SENT", "sent")],
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
            ("DESTINATION", "destination"),
            ("TYPE", "type"),
            ("GATEWAY", "gateways"),
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
    """List the BGP sessions."""
    data = request("GET", "/v1/bgp/neighbors")
    if not dump(data, args.output):
        table(
            data,
            [
                ("NEIGHBOR", "neighbor"),
                ("HOSTNAME", "hostname"),
                ("AS", "remote_as"),
                ("FAMILY", "address_family"),
                ("STATE", "state"),
                ("UPTIME", "uptime"),
                ("RECEIVED", "prefixes_received"),
                ("SENT", "prefixes_sent"),
            ],
        )


# Configuration commands. Changes are staged in the candidate; commit applies them.

NEW_TENANT = {"version": "0.1.4", "name": "", "network_instances": {}}


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
    if not isinstance(data, dict | list) and args.output not in ("json", "yaml"):
        print(cell(data))
        return
    if args.output not in ("json", "yaml"):
        args.output = "yaml"
    dump(data, args.output)


def cmd_config_edit(args: argparse.Namespace) -> None:
    """Edit a configuration, or part of it, in $EDITOR (a new tenant if needed)."""
    import yaml  # noqa: PLC0415

    keys = split(args.path)
    current = staged(args.target, reveal=True) or {**NEW_TENANT, "id": args.target}
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
    """Return the seconds of a duration like 90, 90s, 5m or 1h."""
    units = {"s": 1, "m": 60, "h": 3600}
    try:
        if text[-1:] in units:
            return int(text[:-1]) * units[text[-1]]
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid duration: {text}") from None


def _all_or_target(args: argparse.Namespace, action: str) -> str | None:
    """Return the API path of the action on the target; None with --all."""
    if args.all == bool(args.target):
        fail("Give a tenant, 'service' or --all.")
    return None if args.all else f"{config_path(args.target)}/{action}"


def cmd_config_commit(args: argparse.Namespace) -> None:
    """Apply the staged changes; with --confirm, roll back unless confirmed."""
    if (path := _all_or_target(args, "commit")) is None:
        results = request("POST", "/v1/config/commit", params={"confirm": args.confirm})
        committed = [r for r in results if r["changed"] or r["confirm_by"]]
        for result in committed:
            confirm = f"; confirm before {result['confirm_by']}"
            print(f"Committed {result['id']}{confirm if result['confirm_by'] else ''}.")
        if not committed:
            print("No changes.")
        elif args.confirm:
            print("Confirm with: vpnctl config confirm --all, or they're rolled back.")
        for result in results:
            restart_notice(result)
        return
    result = request("POST", path, params={"confirm": args.confirm})
    if result.get("confirm_by"):
        print(
            f"Committed. Confirm before {result['confirm_by']} with: "
            f"vpnctl config confirm {args.target}, or it's rolled back.",
        )
    else:
        print("Committed." if result["changed"] else "No changes.")
    restart_notice(result)


def restart_notice(result: dict[str, Any]) -> None:
    """Say which service settings need a restart to apply."""
    if fields_ := result.get("restart_needed"):
        print(
            f"Restart vpnc to apply {', '.join(fields_)}: vpnctl service restart",
        )


def cmd_config_confirm(args: argparse.Namespace) -> None:
    """Confirm a commit, so it isn't rolled back."""
    if (path := _all_or_target(args, "confirm")) is None:
        results = request("POST", "/v1/config/confirm")
        print(f"Confirmed {', '.join(r['id'] for r in results)}." if results else "No commits to confirm.")
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
        dump(data, args.output if args.output in ("json", "yaml") else "yaml")
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
    local words
    words=$(vpnctl __complete "${COMP_WORDS[@]:1:COMP_CWORD-1}" 2>/dev/null)
    COMPREPLY=($(compgen -W "$words" -- "${COMP_WORDS[COMP_CWORD]}"))
}
complete -F _vpnctl vpnctl
"""

ZSH_COMPLETION = """\
#compdef vpnctl
_vpnctl() {
    local -a completions
    completions=(${(f)"$(vpnctl __complete "${(@)words[2,CURRENT-1]}" 2>/dev/null)"})
    compadd -a completions
}
if [[ "$funcstack[1]" = "_vpnctl" ]]; then
    _vpnctl "$@"
else
    compdef _vpnctl vpnctl
fi
"""

STATES = ["up", "down", "connecting", "stopped"]
TYPES = ["ipsec", "wireguard", "ssh", "physical"]

# Per command its actions, and per action what its argument completes to.
COMMANDS: dict[str, dict[str, str | None]] = {
    "status": {},
    "tenants": {"list": None, "show": "tenant"},
    "ni": {"list": "tenant", "show": "network_instance"},
    "network-instances": {"list": "tenant", "show": "network_instance"},
    "connections": {
        "list": "filter",
        "show": "connection",
        "stop": "control",
        "start": "control",
        "reset": "control",
        "restart": "control",
        "logs": "connection",
    },
    "bgp": {"neighbors": None, "neighbor": "neighbor", "routes": None},
    # Commands with an argument instead of actions.
    "routes": {},
    "ping": {},
    "traceroute": {},
    "tcp": {},
    "logs": {},
    "version": {},
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
NI_COMMANDS = ("routes", "ping", "traceroute", "tcp")
# Actions taking several ids.
MULTIPLE = ("stop", "start", "reset", "restart")
# Options whose values come from the API.
OPTION_IDS = {
    "--received-from": "neighbor",
    "--advertised-to": "neighbor",
    "--ni": "network_instance",
}
OPTION_VALUES = {
    "-o": ["table", "wide", "json", "yaml"],
    "--output": ["table", "wide", "json", "yaml"],
    "--state": STATES,
    "--type": TYPES,
    "--confirm": ["1m", "5m", "10m"],
    "--source": ["vpnc", "vpncmangle", "charon"],
    "--level": ["debug", "info", "warning", "error", "critical"],
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
    }.get(kind, [])
    if kind == "neighbor":
        return [n["neighbor"] for n in request("GET", "/v1/bgp/neighbors")]
    # Without their state, which takes longer to read.
    data = request("GET", "/v1/ids")
    ids = [item for key in keys for item in data[key]]
    return [*ids, "service"] if kind == "target" else ids


def complete(words: list[str]) -> list[str]:
    """Return the completions for the word after words (the typed ones)."""
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
    actions = COMMANDS.get(positional[0], {})
    if len(positional) == 1:
        return list(actions)
    kind = actions.get(positional[1])
    if kind and (len(positional) == 2 or positional[1] in MULTIPLE):  # noqa: PLR2004
        return _ids(kind)
    if len(positional) == 3 and positional[1] in PATH_ACTIONS:  # noqa: PLR2004
        return paths(staged(positional[2]))
    return []


PATH_ACTIONS = ("show", "edit", "set", "delete")


def paths(data: Any, prefix: str = "") -> list[str]:  # noqa: ANN401
    """Return the dotted paths in the configuration."""
    if isinstance(data, dict):
        items = [(str(k), v) for k, v in data.items()]
    elif isinstance(data, list):
        items = [(str(i), v) for i, v in enumerate(data)]
    else:
        return []
    output: list[str] = []
    for key, value in items:
        output += [prefix + key, *paths(value, f"{prefix}{key}.")]
    return output


def cmd_completion(args: argparse.Namespace) -> None:
    """Print the shell completion script."""
    print(ZSH_COMPLETION if args.script == "zsh" else BASH_COMPLETION, end="")


# Arguments.


def log_options(p: argparse.ArgumentParser) -> None:
    """Add the options of the log commands."""
    p.add_argument(
        "--level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="at least (not for charon's lines)",
    )
    p.add_argument("-n", "--lines", type=int, default=50, help="default: 50")
    p.add_argument("-f", "--follow", action="store_true", help="print new lines")


def parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    # Before or after the command; a subcommand's default mustn't override it.
    output = argparse.ArgumentParser(add_help=False)
    output.add_argument(
        "-o",
        "--output",
        choices=["table", "wide", "json", "yaml"],
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

    ni = group("ni", "network instances", aliases=["network-instances"])
    add(ni, "list", cmd_ni_list).add_argument("tenant", nargs="?", help="e.g. C0001")
    add(ni, "show", cmd_ni_show).add_argument("id", help="e.g. C0001-00")

    connections = group("connections", "connections")
    p = add(connections, "list", cmd_connections_list)
    p.add_argument(
        "filter", nargs="?", help="a tenant (C0001) or network instance (C0001-00)"
    )
    p.add_argument("--state", choices=STATES)
    p.add_argument("--type", choices=TYPES)
    connection = {"help": "e.g. C0001-00-0 or CORE-0"}
    add(connections, "show", cmd_connections_show).add_argument("id", **connection)
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
    p = add(connections, "logs", cmd_connections_logs)
    p.add_argument("id", **connection)
    log_options(p)

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

    p = add(commands, "logs", cmd_logs)
    p.add_argument("--source", choices=["vpnc", "vpncmangle", "charon"], default="vpnc")
    p.add_argument(
        "--ni",
        metavar="NETWORK_INSTANCE",
        help="its lines and its connections' (vpnc's, ssh's and charon's)",
    )
    log_options(p)

    add(commands, "version", cmd_version)
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
    p = add(cfg, "history", cmd_config_history)
    p.add_argument("target", **target)
    p.add_argument("revision", nargs="?", type=int, help="show this revision")
    p.add_argument("--reveal-secrets", action="store_true")
    p = add(cfg, "restore", cmd_config_restore)
    p.add_argument("target", **target)
    p.add_argument("revision", type=int, help="see: vpnctl config history")
    return main


def main() -> None:
    """Run vpnctl."""
    if sys.argv[1:2] == ["__complete"]:
        with contextlib.suppress(ApiError, SystemExit):
            print("\n".join(complete(sys.argv[2:])))
        return
    args = parser().parse_args()
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
