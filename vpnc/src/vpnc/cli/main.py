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
import time
from typing import Any
from urllib.parse import quote, urlencode

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


def request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    body: Any = None,  # noqa: ANN401
) -> Any:  # noqa: ANN401
    """Call the API and return the decoded response (text for text/plain)."""
    if params := {k: v for k, v in (params or {}).items() if v is not None}:
        path += "?" + urlencode(params)
    conn = _UnixConnection("localhost", timeout=60)
    try:
        payload = json.dumps(body) if body is not None else None
        headers = {"Content-Type": "application/json"} if payload else {}
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        data = response.read().decode()
        content_type = response.getheader("Content-Type", "")
    except FileNotFoundError:
        fail(f"vpnc isn't running: no API at {SOCKET}.", code=2)
    except PermissionError:
        fail(f"No access to {SOCKET}: run vpnctl as root.", code=2)
    finally:
        conn.close()
    decoded: Any = json.loads(data) if "json" in content_type else data
    if response.status >= 400:  # noqa: PLR2004
        problem = decoded if isinstance(decoded, dict) else {"detail": decoded}
        raise ApiError(response.status, problem)
    return decoded


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


def cell(value: Any) -> str:  # noqa: ANN401
    """Return a table cell: lists comma separated, empty as '-'."""
    if value is None or value == []:
        return "-"
    if isinstance(value, list):
        return ", ".join(cell(v) for v in value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


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
        ],
    )


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
    data = request(
        "GET",
        "/v1/connections",
        params={**_filter(args.filter), "state": args.state, "type": args.type},
    )
    if not dump(data, args.output):
        columns = [
            ("CONNECTION", "id"),
            ("TYPE", "type"),
            ("STATE", "state"),
            ("REMOTE", "remote"),
            ("INTERFACE", "interface"),
        ]
        if args.output == "wide":
            columns.append(("ADDRESSES", "addresses"))
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
    fields(items)


def _control(args: argparse.Namespace, action: str, done: str) -> None:
    data = request("POST", f"/v1/connections/{quote(args.id)}/{action}")
    if not dump(data, args.output):
        print(f"{done} {data['id']}; it's {data['state']}.")


def cmd_connections_stop(args: argparse.Namespace) -> None:
    """Stop a VPN connection until it's started again, or vpnc restarts."""
    _control(args, "stop", "Stopped")


def cmd_connections_start(args: argparse.Namespace) -> None:
    """Start a stopped VPN connection."""
    _control(args, "start", "Started")


def cmd_connections_reset(args: argparse.Namespace) -> None:
    """Set a VPN connection up again (new IKE SA, WireGuard or SSH session)."""
    _control(args, "reset", "Reset")


def _log_lines(connection_id: str, count: int) -> list[dict[str, Any]]:
    return request(
        "GET",
        f"/v1/connections/{quote(connection_id)}/logs",
        params={"lines": count},
    )


def _print_log(line: dict[str, Any]) -> None:
    print(f"{line['time']}  {line['source']:<6}  {line['level']:<7}  {line['message']}")


def cmd_connections_logs(args: argparse.Namespace) -> None:
    """Show a connection's log: vpnc's, SSH's and charon's (IPsec) lines."""
    data = _log_lines(args.id, args.lines)
    if not args.follow:
        if not dump(data, args.output):
            for line in data:
                _print_log(line)
        return
    seen: set[tuple[str, ...]] = set()
    while True:
        for line in data:
            key = tuple(line.values())
            if key not in seen:
                seen.add(key)
                _print_log(line)
        sys.stdout.flush()
        time.sleep(1)
        data = _log_lines(args.id, 100)


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

NEW_TENANT = {"version": "0.1.3", "name": "", "network_instances": {}}


def config_path(target: str) -> str:
    """Return the API path of a tenant's or the service's configuration."""
    if target in ("service", "DEFAULT"):
        return "/v1/config/service"
    return f"/v1/config/tenants/{quote(target)}"


def split(path: str | None) -> list[str]:
    """Return the keys of a dotted path, e.g. network_instances.C0001-00.type."""
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
        table(data, [("TENANT", "id"), ("NAME", "name"), ("STAGED", "status")])


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


def cmd_config_set(args: argparse.Namespace) -> None:
    """Set a value (YAML) at a path, creating missing parts."""
    import yaml  # noqa: PLC0415

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


def cmd_config_commit(args: argparse.Namespace) -> None:
    """Apply the staged changes."""
    result = request("POST", f"{config_path(args.target)}/commit")
    print("Committed." if result["changed"] else "No changes.")


def cmd_config_discard(args: argparse.Namespace) -> None:
    """Drop the staged changes."""
    result = request("POST", f"{config_path(args.target)}/discard")
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
        "stop": "connection",
        "start": "connection",
        "reset": "connection",
        "logs": "connection",
    },
    "bgp": {"neighbors": None},
    "config": {
        "list": None,
        "show": "target",
        "edit": "target",
        "set": "target",
        "delete": "target",
        "diff": "target",
        "commit": "target",
        "discard": "target",
    },
    "completion": {"bash": None},
}
OPTION_VALUES = {
    "-o": ["table", "wide", "json", "yaml"],
    "--output": ["table", "wide", "json", "yaml"],
    "--state": STATES,
    "--type": TYPES,
    "-n": [],
    "--lines": [],
}


def _ids(kind: str) -> list[str]:
    """Return the ids an argument completes to, from the API."""
    paths = {
        "tenant": ["/v1/tenants"],
        "network_instance": ["/v1/network-instances"],
        "connection": ["/v1/connections"],
        "filter": ["/v1/tenants", "/v1/network-instances"],
        "target": ["/v1/config/tenants"],
    }[kind]
    ids = [item["id"] for path in paths for item in request("GET", path)]
    return [*ids, "service"] if kind == "target" else ids


def complete(words: list[str]) -> list[str]:
    """Return the completions for the word after words (the typed ones)."""
    if words and words[-1] in OPTION_VALUES:
        return OPTION_VALUES[words[-1]]
    positional = [
        w
        for i, w in enumerate(words)
        if not w.startswith("-") and (i == 0 or words[i - 1] not in OPTION_VALUES)
    ]
    if not positional:
        return [c for c in COMMANDS if c != "network-instances"]
    actions = COMMANDS.get(positional[0], {})
    if len(positional) == 1:
        return list(actions)
    kind = actions.get(positional[1])
    if len(positional) == 2 and kind:  # noqa: PLR2004
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
    _ = args
    print(BASH_COMPLETION, end="")


# Arguments.


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
    for name, func in (
        ("show", cmd_connections_show),
        ("stop", cmd_connections_stop),
        ("start", cmd_connections_start),
        ("reset", cmd_connections_reset),
    ):
        add(connections, name, func).add_argument("id", **connection)
    p = add(connections, "logs", cmd_connections_logs)
    p.add_argument("id", **connection)
    p.add_argument("-n", "--lines", type=int, default=50, help="default: 50")
    p.add_argument("-f", "--follow", action="store_true", help="print new lines")

    bgp = group("bgp", "BGP (hub mode)")
    add(bgp, "neighbors", cmd_bgp_neighbors)

    shell = group("completion", "shell completion")
    add(shell, "bash", cmd_completion)

    cfg = group("config", "configuration: stage changes, then commit them")
    add(cfg, "list", cmd_config_list)
    target = {"help": "a tenant (e.g. C0001) or 'service'"}
    path = {"help": "dotted, e.g. network_instances.C0001-00.connections.0"}
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
    p.add_argument("value", help="YAML, e.g. 10.0.0.1, '[a, b]' or '{to: ::/0}'")
    p = add(cfg, "delete", cmd_config_delete)
    p.add_argument("target", **target)
    p.add_argument("path", nargs="?", **path)
    for name, func in (
        ("diff", cmd_config_diff),
        ("commit", cmd_config_commit),
        ("discard", cmd_config_discard),
    ):
        add(cfg, name, func).add_argument("target", **target)
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
