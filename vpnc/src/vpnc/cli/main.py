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
        params={**_filter(args.filter), "state": args.state},
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


# Configuration commands.


def config_path(target: str) -> str:
    """Return the API path of a tenant's or the service's configuration."""
    if target in ("service", "DEFAULT"):
        return "/v1/config/service"
    return f"/v1/config/tenants/{quote(target)}"


def cmd_config_list(args: argparse.Namespace) -> None:
    """List the tenants with configuration."""
    data = request("GET", "/v1/config/tenants")
    if not dump(data, args.output):
        table(
            data,
            [
                ("TENANT", "id"),
                ("NAME", "name"),
                ("ACTIVE", "active"),
                ("CANDIDATE", "candidate"),
                ("CHANGED", "changed"),
            ],
        )


def cmd_config_show(args: argparse.Namespace) -> None:
    """Show a configuration."""
    data = request(
        "GET",
        config_path(args.target),
        params={
            "revision": "candidate" if args.candidate else "active",
            "reveal_secrets": "true" if args.reveal_secrets else None,
        },
    )
    if args.output not in ("json", "yaml"):
        args.output = "yaml"
    dump(data, args.output)


def _current(target: str) -> dict[str, Any] | None:
    """Return the candidate, else the active configuration, with secrets."""
    for revision in ("candidate", "active"):
        try:
            return request(
                "GET",
                config_path(target),
                params={"revision": revision, "reveal_secrets": "true"},
            )
        except ApiError as err:
            if err.status != 404:  # noqa: PLR2004
                raise
    return None


def cmd_config_edit(args: argparse.Namespace) -> None:
    """Edit a candidate configuration in $EDITOR (a new tenant if it has none)."""
    import yaml  # noqa: PLC0415

    current = _current(args.target)
    if current is None:
        current = {
            "version": "0.1.3",
            "id": args.target,
            "name": "",
            "network_instances": {},
        }
    text = yaml.safe_dump(current, sort_keys=False)
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
                request(
                    "PUT",
                    f"{config_path(args.target)}/candidate",
                    body=yaml.safe_load(edited),
                )
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
                fail("aborted; the candidate is unchanged.")
    print_diff(args.target)
    print(f"Stored the candidate. Apply it with: vpnctl config commit {args.target}")


def print_diff(target: str) -> None:
    """Print the changes from the active to the candidate configuration."""
    if text := request("GET", f"{config_path(target)}/diff"):
        print(text, end="")
    else:
        print("No changes.")


def cmd_config_diff(args: argparse.Namespace) -> None:
    """Show the changes from the active to the candidate configuration."""
    print_diff(args.target)


def cmd_config_commit(args: argparse.Namespace) -> None:
    """Apply a candidate configuration."""
    result = request("POST", f"{config_path(args.target)}/commit")
    print("Committed." if result["changed"] else "No changes.")


def cmd_config_discard(args: argparse.Namespace) -> None:
    """Discard a candidate configuration."""
    result = request("DELETE", f"{config_path(args.target)}/candidate")
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

# Per command its actions, and per action what its argument completes to.
COMMANDS: dict[str, dict[str, str | None]] = {
    "status": {},
    "tenants": {"list": None, "show": "tenant"},
    "ni": {"list": "tenant", "show": "network_instance"},
    "network-instances": {"list": "tenant", "show": "network_instance"},
    "connections": {"list": "filter", "show": "connection"},
    "bgp": {"neighbors": None},
    "config": {
        "list": None,
        "show": "target",
        "edit": "target",
        "diff": "target",
        "commit": "target",
        "discard": "target",
    },
    "completion": {"bash": None},
}
OPTION_VALUES = {
    "-o": ["table", "wide", "json", "yaml"],
    "--output": ["table", "wide", "json", "yaml"],
    "--state": ["up", "down", "connecting"],
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
    return []


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
    p.add_argument("--state", choices=["up", "down", "connecting"])
    add(connections, "show", cmd_connections_show).add_argument(
        "id",
        help="e.g. C0001-00-0 or CORE-0",
    )

    bgp = group("bgp", "BGP (hub mode)")
    add(bgp, "neighbors", cmd_bgp_neighbors)

    shell = group("completion", "shell completion")
    add(shell, "bash", cmd_completion)

    cfg = group("config", "configuration (candidate and active)")
    add(cfg, "list", cmd_config_list)
    target = {"help": "a tenant (e.g. C0001) or 'service'"}
    p = add(cfg, "show", cmd_config_show)
    p.add_argument("target", **target)
    p.add_argument("--candidate", action="store_true", help="the candidate revision")
    p.add_argument("--reveal-secrets", action="store_true")
    for name, func in (
        ("edit", cmd_config_edit),
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
