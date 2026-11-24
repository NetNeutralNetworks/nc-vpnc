"""Helpers of the fuzz tests; see also test/lab_helpers.py.

The tests run many examples, so what each one does must be cheap. Commands and
API calls go through an agent in the node (a process that stays), several at a
time, and waits poll fast at first.
"""

from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

import pytest
from hypothesis.database import DirectoryBasedExampleDatabase

# test/ holds lab_helpers.py. Add it explicitly so the suite also works when
# pytest is started from inside the suite directory.
TEST_DIR = str(Path(__file__).resolve().parents[2])
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)

# Always the fuzz lab. Unless another suite imported lab_helpers first: then
# the tests are skipped (see FUZZ_LAB).
os.environ["VPNC_LAB"] = "vpnc-fuzz"

from fuzz_common.dns_wire import addresses  # noqa: E402
from lab_helpers import CONTAINER_PREFIX  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Callable

T = TypeVar("T")

FUZZ_LAB = CONTAINER_PREFIX == "clab-vpnc-fuzz-"
# Every suite's examples, failing ones first next time; Hypothesis keeps each
# test's apart.
DATABASE = DirectoryBasedExampleDatabase(
    Path(__file__).resolve().parents[1] / ".hypothesis"
)

HOST = "hub00"
API_SOCKET = "/run/vpnc/api.sock"
ACTIVE_DIR = "/opt/ncubed/config/vpnc/active"
CANDIDATE_DIR = "/opt/ncubed/config/vpnc/candidate"
HISTORY_DIR = "/opt/ncubed/config/vpnc/history"
# An answer slower than this is a hang.
API_TIMEOUT = 60
COMMAND_TIMEOUT = 60

# Runs in a node: a request (JSON) per line, its answer on a line. A batch runs
# its requests at the same time.
AGENT = r"""
import concurrent.futures, http.client, json, os, socket, subprocess, sys


class Api(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def api(request):
    connection = Api(request["socket"], request["timeout"])
    try:
        body = request.get("body")
        connection.request(
            request["method"],
            request["path"],
            body=None if body is None else body.encode(),
            headers={} if body is None else {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        text = response.read().decode(errors="replace")
        return {"status": response.status, "text": text}
    finally:
        connection.close()


def sh(request):
    command = request["command"]
    done = subprocess.run(
        command,
        shell=isinstance(command, str),
        executable="/bin/bash" if isinstance(command, str) else None,
        input=request.get("input"),
        capture_output=True,
        text=True,
        timeout=request.get("timeout"),
    )
    return {"rc": done.returncode, "out": done.stdout, "err": done.stderr}


def write(request):
    path = request["path"]
    if not request.get("via"):
        with open(path, "w") as f:
            f.write(request["content"])
        return {}
    # Written elsewhere and moved into place, as most editors and tools save.
    with open(request["via"], "w") as f:
        f.write(request["content"])
    os.replace(request["via"], path)
    return {}


SCOPE = {}


def py(request):
    SCOPE["args"] = request.get("args")
    exec(request["code"], SCOPE)
    return {"value": SCOPE.pop("result", None)}


OPS = {"api": api, "sh": sh, "write": write, "py": py}
POOL = concurrent.futures.ThreadPoolExecutor(16)


def run(request):
    try:
        if request["op"] == "batch":
            return {"answers": list(POOL.map(run, request["requests"]))}
        return OPS[request["op"]](request)
    except Exception as error:
        return {"error": f"{type(error).__name__}: {error}"}


for line in sys.stdin:
    sys.stdout.write(json.dumps(run(json.loads(line))) + "\n")
    sys.stdout.flush()
"""


class ApiError(AssertionError):
    """The API failed: no answer, or a server error."""


class AgentError(RuntimeError):
    """A node's agent didn't answer: the node restarted, or a command hangs."""


class CommandError(RuntimeError):
    """A command in a node failed."""


class Agent:
    """A process in a node that runs the tests' commands and API calls.

    A podman exec costs about 100 ms; a request to the agent under one. With
    setup (Python code) it keeps state between requests, e.g. open sockets.
    """

    agents: list[Agent] = []  # noqa: RUF012

    def __init__(self, host: str, netns: str | None = None, setup: str = "") -> None:
        """Start nothing yet: the first request does."""
        self.host = host
        self.setup = setup
        self.command = [
            "podman", "exec", "-i", f"{CONTAINER_PREFIX}{host}",
            *(["ip", "netns", "exec", netns] if netns else []),
            "python3", "-u", "-c", AGENT,
        ]  # fmt: skip
        self.process: subprocess.Popen[str] | None = None
        self.lock = threading.Lock()
        Agent.agents.append(self)

    def _start(self) -> None:
        self.process = subprocess.Popen(  # noqa: S603
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if self.setup:
            answer = self._exchange({"op": "py", "code": self.setup}, COMMAND_TIMEOUT)
            if "error" in answer:
                raise AgentError(answer["error"])

    def _exchange(self, request: dict[str, Any], timeout: float) -> dict[str, Any]:
        process = self.process
        assert process is not None
        assert process.stdin is not None
        assert process.stdout is not None
        timer = threading.Timer(timeout, process.kill)
        timer.start()
        try:
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            line = process.stdout.readline()
        except OSError:
            line = ""
        finally:
            timer.cancel()
        if not line:
            process.kill()
            self.process = None
            msg = f"no answer from {self.host}"
            raise AgentError(msg)
        return json.loads(line)

    def call(self, request: dict[str, Any], timeout: float) -> dict[str, Any]:
        """Return the answer to a request; a new process if the node restarted."""
        with self.lock:
            if self.process is None or self.process.poll() is not None:
                self._start()
            return self._exchange(request, timeout)

    def run(self, code: str, args: Any = None, timeout: float = COMMAND_TIMEOUT) -> Any:  # noqa: ANN401
        """Run Python code in the agent; return what it sets as result."""
        answer = self.call({"op": "py", "code": code, "args": args}, timeout)
        if "error" in answer:
            raise CommandError(answer["error"])
        return answer["value"]

    def stop(self) -> None:
        """Stop the process."""
        with self.lock:
            if self.process is not None:
                self.process.kill()
                self.process = None


@atexit.register
def _stop_agents() -> None:
    for agent in Agent.agents:
        agent.stop()


# Agents without state, per node: one per request at the same time.
_IDLE: dict[str, list[Agent]] = {}
_IDLE_LOCK = threading.Lock()


def call(host: str, request: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Return a node's answer to a request."""
    with _IDLE_LOCK:
        idle = _IDLE.setdefault(host, [])
        agent = idle.pop() if idle else Agent(host)
    try:
        return agent.call(request, timeout)
    finally:
        with _IDLE_LOCK:
            idle.append(agent)


def batch(host: str, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a node's answers to requests it runs at the same time."""
    timeout = max(r.get("timeout") or COMMAND_TIMEOUT for r in requests) + 10
    answer = call(host, {"op": "batch", "requests": requests}, timeout)
    return answer["answers"]


def command(command: list[str] | str, *, timeout: float = COMMAND_TIMEOUT) -> dict:
    """Return the request that runs a command (a string: by bash)."""
    return {"op": "sh", "command": command, "timeout": timeout}


def sh(host: str, command_: list[str] | str, *, check: bool = True) -> str:
    """Run a command in a node (a string: by bash); return its output."""
    answer = call(host, command(command_), COMMAND_TIMEOUT + 10)
    if "error" in answer or (check and answer["rc"]):
        msg = f"{host}: {command_}: {answer.get('error') or answer['err'].strip()}"
        raise CommandError(msg)
    return answer["out"]


def run_cmd(host: str, command_: str) -> str:
    """Run a command, split on whitespace, in a node; return its output."""
    return sh(host, command_.split())


def run_cmd_shell(host: str, command_: str) -> str:
    """Run a shell command line in a node; return its output."""
    return sh(host, command_)


def write_file(host: str, path: str, content: str, via: str | None = None) -> None:
    """Write a file in a node: in place, or (via) elsewhere and moved into place."""
    request = {"op": "write", "path": path, "content": content, "via": via}
    answer = call(host, request, COMMAND_TIMEOUT)
    if "error" in answer:
        msg = f"{host}: writing {path}: {answer['error']}"
        raise CommandError(msg)


def wait_until(
    func: Callable[[], T],
    timeout: float,
    interval: float = 0.5,
    message: str = "condition",
) -> T:
    """Poll func until it returns a truthy value and return that value.

    As lab_helpers.wait_until, but it polls after 20 ms first and then less
    often, up to every interval: most of what the tests wait for takes a moment.
    """
    deadline = time.monotonic() + timeout
    pause = 0.02
    last: object = None
    while True:
        try:
            if result := func():
                return result
            last = result
        except Exception as exc:  # noqa: BLE001
            last = exc
        if time.monotonic() >= deadline:
            msg = f"Timed out after {timeout}s waiting for {message}. Last: {last!r}"
            raise TimeoutError(msg)
        time.sleep(pause)
        pause = min(pause * 1.5, interval)


def _request(method: str, path: str, body: Any) -> dict[str, Any]:  # noqa: ANN401
    request = {
        "op": "api",
        "socket": API_SOCKET,
        "method": method,
        "path": path,
        "timeout": API_TIMEOUT,
    }
    if body is not None:
        request["body"] = body if isinstance(body, str) else json.dumps(body)
    return request


def _response(method: str, path: str, answer: dict[str, Any]) -> tuple[int, Any]:
    if "error" in answer:
        msg = f"{method} {path}: no answer ({answer['error']})"
        raise ApiError(msg)
    try:
        content = json.loads(answer["text"])
    except json.JSONDecodeError:
        content = answer["text"]
    if answer["status"] >= 500:  # noqa: PLR2004
        msg = f"{method} {path}: {answer['status']} {content}"
        raise ApiError(msg)
    return answer["status"], content


def api(
    method: str,
    path: str,
    body: Any = None,  # noqa: ANN401
    host: str = HOST,
) -> tuple[int, Any]:
    """Call vpnc's API on a node; return the status and the (JSON) answer."""
    try:
        answer = call(host, _request(method, path, body), API_TIMEOUT + 10)
    except AgentError as err:
        msg = f"{method} {path}: no answer ({err})"
        raise ApiError(msg) from err
    return _response(method, path, answer)


def gets(paths: list[str], host: str = HOST) -> list[tuple[int, Any]]:
    """GET paths of vpnc's API on a node, at the same time."""
    try:
        answers = batch(host, [_request("GET", path, None) for path in paths])
    except AgentError as err:
        msg = f"GET {', '.join(paths)}: no answer ({err})"
        raise ApiError(msg) from err
    return [
        _response("GET", path, answer)
        for path, answer in zip(paths, answers, strict=True)
    ]


# The fuzz lab's bridge (fuzz.clab.yaml): a node's uplink is fuzz-<node> on it.
BRIDGE = "br-vpnc-fuzz"


def restarted_node(host: str = HOST) -> None:
    """Restart a node and link it again.

    A container's links go with it: containerlab only adds them at a deploy.
    The node's script waits for them before it starts systemd.
    """
    container = f"{CONTAINER_PREFIX}{host}"
    subprocess.run(  # noqa: S603
        ["podman", "restart", container],  # noqa: S607
        capture_output=True,
        check=True,
    )
    # A new systemd counts from 0.
    EXPECTED_RESTARTS[host] = 0
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "containerlab", "--runtime", "podman", "tools", "veth", "create",
            "-a", f"{container}:eth1", "-b", f"bridge:{BRIDGE}:fuzz-{host}",
        ],
        capture_output=True,
        check=True,
    )  # fmt: skip
    _api_answers(host)


def restarted_vpnc(host: str = HOST, *, before: str) -> None:
    """Wait until systemd started vpnc again, after its main PID before."""
    wait_until(
        lambda: sh(host, MAIN_PID).strip() not in {before, "0"},
        timeout=RESET_TIMEOUT,
        message=f"vpnc on {host} to restart",
    )
    _api_answers(host)


def _api_answers(host: str) -> None:
    wait_until(
        lambda: api("GET", "/v1/status", host=host)[0] == 200,  # noqa: PLR2004
        timeout=RESET_TIMEOUT,
        message=f"vpnc's API on {host}",
    )


# Restarts the tests caused on purpose (killing vpnc), by node.
EXPECTED_RESTARTS: dict[str, int] = {}
# How often systemd restarted vpnc since the node started.
RESTARTS = command("systemctl show -P NRestarts ncubed-vpnc.service")
MAIN_PID = "systemctl show -P MainPID ncubed-vpnc.service"


def _restarts(host: str, count: str) -> int:
    return int(count or 0) - EXPECTED_RESTARTS.get(host, 0)


def restarts(host: str = HOST) -> int:
    """Return how often vpnc exited and systemd restarted it, but on purpose."""
    return _restarts(host, sh(host, RESTARTS["command"]))


def expect_restart(host: str = HOST) -> None:
    """Note that a node restarts on purpose."""
    EXPECTED_RESTARTS[host] = EXPECTED_RESTARTS.get(host, 0) + 1


# Per network instance: links, addresses, routes, nftables rules (without
# counters) and WireGuard's settings.
PER_NETNS = (
    "ip -n {ns} -j link",
    "ip -n {ns} -j addr",
    "ip -n {ns} -j -4 route show table all",
    "ip -n {ns} -j -6 route show table all",
    "ip netns exec {ns} nft -s -j list ruleset",
    "ip netns exec {ns} wg show all dump",
)
# The daemons next to vpnc: a new process id means one exited (vpnc restarts
# vpncmangle, and watchfrr FRR's, only when they did).
DAEMONS = "charon|vpncmangle|watchfrr|mgmtd|zebra|bfdd|bgpd|staticd"
PGREP = command(["pgrep", "-l", "-x", DAEMONS])
BGP = command(["vtysh", "-c", "show bgp vrf CORE ipv6 unicast summary json"])
# What charon has loaded per connection: peers, version, ids, lifetimes,
# traffic selectors (not the proposals or keys).
CHARON = command(["swanctl", "--list-conns", "--raw"])
CONNECTIONS = "/v1/connections"


def _routes(routes: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
    return {
        (r.get("table"), r.get("type"), r["dst"], r.get("dev"), r.get("gateway"))
        for r in routes
        # The kernel's own: per address and link, and multicast.
        if r.get("table") != "local" and not r["dst"].startswith(("ff00::", "fe80::"))
    }


def _wireguard(dump: str) -> set[tuple[str, ...]]:
    """Return the interfaces' public keys and ports, and the peers' allowed IPs."""
    items = set()
    for line in dump.splitlines():
        fields = line.split("\t")
        if len(fields) == 5:  # noqa: PLR2004
            name, _, public, port, _ = fields
            items.add((name, "interface", public, port))
        elif len(fields) == 9:  # noqa: PLR2004
            name, public, _, _, allowed, *_ = fields
            items.add((name, "peer", public, ",".join(sorted(allowed.split(",")))))
    return items


def snapshot(host: str = HOST) -> dict[str, Any]:
    """Return what a node has per network instance, and what its daemons run."""
    names = sorted(
        line.split()[0] for line in sh(host, "ip netns list").splitlines() if line
    )
    requests = [command(c.format(ns=ns).split()) for ns in names for c in PER_NETNS]
    requests += [_request("GET", CONNECTIONS, None), PGREP, BGP, CHARON]
    answers = batch(host, requests)
    # A network instance removed meanwhile has nothing.
    outputs = [answer.get("out", "") for answer in answers]
    state = {}
    for index, ns in enumerate(names):
        links, addrs, routes_4, routes_6, rules, wireguard = outputs[
            index * len(PER_NETNS) : (index + 1) * len(PER_NETNS)
        ]
        state[ns] = {
            "links": {
                (link["ifname"], "UP" in link["flags"])
                for link in json.loads(links or "[]")
            },
            "addresses": {
                (link["ifname"], a["local"], a["prefixlen"])
                for link in json.loads(addrs or "[]")
                for a in link.get("addr_info", [])
                if a.get("scope") != "link"
            },
            "routes": _routes(
                json.loads(routes_4 or "[]") + json.loads(routes_6 or "[]")
            ),
            "nftables": _nftables(json.loads(rules or "{}")),
            "wireguard": _wireguard(wireguard),
        }
    connections, processes, bgp, charon = answers[-4:]
    # Not network instances: what vpnc says of its connections, the daemons'
    # processes, FRR's BGP sessions and charon's connections.
    state["(vpnc)"] = {
        "admin_status": {
            (c["id"], c["admin_status"])
            for c in _response("GET", CONNECTIONS, connections)[1]
        },
    }
    state["(daemons)"] = {"processes": _processes(processes.get("out", ""))}
    state["(frr)"] = {"bgp": _sessions(bgp.get("out", ""))}
    state["(charon)"] = {
        "connections": {
            line.removeprefix("list-conn event ")
            for line in charon.get("out", "").splitlines()
            if line.startswith("list-conn event ")
        },
    }
    return state


def _nftables(ruleset: dict[str, Any]) -> set[str]:
    """Return the tables, chains, sets and rules, without their handles.

    Leaves out the rules of Docker's DNS: their ports are new with every start.
    """
    items = set()
    for item in ruleset.get("nftables", []):
        for kind, value in item.items():
            if kind != "metainfo" and not (
                kind == "rule" and value.get("chain", "").startswith("DOCKER_")
            ):
                fields = {k: v for k, v in value.items() if k != "handle"}
                items.add(f"{kind} {json.dumps(fields, sort_keys=True)}")
    return items


def _processes(output: str) -> set[tuple[str, int]]:
    lines = output.split("\n")
    return {(name, int(pid)) for pid, name in (line.split() for line in lines if line)}


def daemons(host: str = HOST) -> set[tuple[str, int]]:
    """Return the daemons' names and process ids."""
    return _processes(sh(host, PGREP["command"], check=False))


def _sessions(output: str) -> set[tuple[str, str, int]]:
    try:
        peers = json.loads(output).get("peers", {})
    except json.JSONDecodeError:
        return {("(vtysh)", "no answer", 0)}
    return {
        (peer, info.get("state"), info.get("pfxSnt")) for peer, info in peers.items()
    }


def _bgp(host: str) -> set[tuple[str, str, int]]:
    """Return CORE's BGP sessions as FRR has them: peer, state, prefixes sent."""
    return _sessions(sh(host, BGP["command"], check=False))


def diff(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Return what differs between two snapshots, readable."""
    lines = []
    for ns in sorted(before.keys() | after.keys()):
        if ns not in after:
            lines.append(f"- netns {ns}")
            continue
        if ns not in before:
            lines.append(f"+ netns {ns}")
            continue
        for what in before[ns]:
            lines += [f"- {ns} {what} {x}" for x in before[ns][what] - after[ns][what]]
            lines += [f"+ {ns} {what} {x}" for x in after[ns][what] - before[ns][what]]
    return lines


# What frr-reload.py finds different between vpnc's FRR configuration and FRR's
# as deployed (e.g. the hostname): set by Deployed.
FRR_DEPLOYED_DIFFERENCES: set[str] = set()
FRR_RELOAD = command(["/usr/lib/frr/frr-reload.py", "--test", "/etc/frr/frr.conf"])
# Per network instance (netns) its nftables tables, on a line.
TABLES = command(
    'for ns in $(ip netns list | cut -d" " -f1); do'
    ' echo "$ns $(ip netns exec "$ns" nft list tables | tr "\\n" " ")"; done',
)


def _frr_differences(output: str) -> set[str]:
    return {
        line
        for line in output.splitlines()
        if line.strip() and not line.startswith(("Lines To", "==="))
    }


def frr_differences(host: str = HOST) -> set[str]:
    """Return the lines frr-reload.py would change for FRR to run vpnc's config."""
    return _frr_differences(sh(host, FRR_RELOAD["command"], check=False))


def not_loaded(host: str = HOST) -> list[str]:
    """Return what vpnc applied only partly: charon, nftables, FRR or vpncmangle.

    Each enabled IPsec connection is loaded in charon, each network instance but
    DEFAULT has vpnc's nftables table, FRR runs vpnc's configuration (but what
    differed as deployed), and vpncmangle loaded the translations vpnc wrote.
    """
    conns, tables, frr, connections, instances, status = batch(
        host,
        [
            command(["swanctl", "--list-conns"]),
            TABLES,
            FRR_RELOAD,
            _request("GET", CONNECTIONS, None),
            _request("GET", "/v1/network-instances", None),
            _request("GET", "/v1/status", None),
        ],
    )
    if "error" in conns or conns["rc"]:
        return [f"charon doesn't list its connections: {conns}"]
    loaded = {
        line.split(":")[0] for line in conns["out"].splitlines() if line[:1].strip()
    }
    problems = [
        f"IPsec connection {c['id']} isn't loaded in charon"
        for c in _response("GET", CONNECTIONS, connections)[1]
        if c["type"] == "IPSEC" and c["admin_status"] == "UP" and c["id"] not in loaded
    ]
    with_table = {
        line.split()[0]
        for line in tables.get("out", "").splitlines()
        if "table inet vpnc" in line
    }
    problems += [
        f"network instance {ni['id']} has no nftables table"
        for ni in _response("GET", "/v1/network-instances", instances)[1]
        if ni["id"] != "DEFAULT" and ni["id"] not in with_table
    ]
    problems += [
        f"FRR doesn't run: {line}"
        for line in sorted(
            _frr_differences(frr.get("out", "")) - FRR_DEPLOYED_DIFFERENCES,
        )
    ]
    mangle = _response("GET", "/v1/status", status)[1]["vpncmangle"]
    if not mangle["translations_loaded"]:
        problems.append(
            f"vpncmangle didn't load the translations: {mangle['translations_error']}",
        )
    return problems


def check_loaded(host: str = HOST) -> None:
    """Check that what vpnc applied, charon and nftables took."""
    problems = not_loaded(host)
    assert not problems, "\n".join(["applied only partly:", *problems])


# DNS queries from mgt00: sockets that stay, one per server. hub00's NAT64 has
# some 4500 ports per address, and a new socket's session keeps one for minutes.
# A server that sends a sentinel after its answer (see test_dns_answers.py)
# spares the wait for an answer that vpncmangle dropped.
DNS_CLIENT = r"""
import os, select, socket, struct, time

SOCKETS = {}


def drain(server):
    # Returns what came on a server's socket since it was last read (hex).
    late = []
    s = SOCKETS.get(server)
    while s and select.select([s], [], [], 0)[0]:
        try:
            late.append(s.recvfrom(65535)[0].hex())
        except OSError:
            pass
    return late


def ask(server, name, qtype, sentinel=None, timeout=1.5, grace=0.03):
    # Returns the answers (hex), whether the sentinel came after them, and what
    # came before the query (late). An empty sentinel: any, returned as answer.
    if server not in SOCKETS:
        SOCKETS[server] = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s = SOCKETS[server]
    late = drain(server)
    query = os.urandom(2) + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)
    query += b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    query += b"\0" + struct.pack(">HH", qtype, 1)
    s.sendto(query, (server, 53))
    last = bytes(b ^ 0xFF for b in query[:2])
    answers, seen, end = [], False, time.monotonic() + timeout
    while (left := end - time.monotonic()) > 0 and select.select([s], [], [], left)[0]:
        try:
            data = s.recvfrom(65535)[0]
        except OSError:
            continue
        if sentinel is None:
            if data[:2] == query[:2]:
                return [data.hex()], False, late
        elif not sentinel:
            if data[:2] == last:
                return [data.hex()], True, late
        elif data == last + bytes.fromhex(sentinel) and not seen:
            # What was sent before it and comes later is close behind.
            seen, end = True, time.monotonic() + grace
        else:
            answers.append(data.hex())
    return answers, seen, late
"""
DNS_CLIENT_HOST = "mgt00"
_DNS_CLIENT: list[Agent] = []


def _dns_client() -> Agent:
    if not _DNS_CLIENT:
        _DNS_CLIENT.append(Agent(DNS_CLIENT_HOST, setup=DNS_CLIENT))
    return _DNS_CLIENT[0]


def dns_observe(
    server: str,
    name: str,
    qtype: int,
    sentinel: str | None = None,
    grace: float = 0.03,
) -> tuple[list[bytes], bool, list[bytes]]:
    """Return mgt00's answers to a query, whether the sentinel came after, and late.

    grace: how long after the sentinel an answer sent before it may still come.
    late: what came on the socket since the last query, i.e. of earlier ones.
    """
    answers, seen, late = _dns_client().run(
        "result = ask(*args)",
        [server, name, qtype, sentinel, 1.5, grace],
    )
    return [bytes.fromhex(a) for a in answers], seen, [bytes.fromhex(a) for a in late]


def dns_ask(
    server: str,
    name: str,
    qtype: int,
    sentinel: str | None = None,
    grace: float = 0.03,
) -> tuple[list[bytes], bool]:
    """Return mgt00's answers to a query, and whether the sentinel came after."""
    answers, seen, _ = dns_observe(server, name, qtype, sentinel, grace)
    return answers, seen


def dns_drain(server: str) -> list[bytes]:
    """Return what came on mgt00's socket of a server since it was last read."""
    return [
        bytes.fromhex(a) for a in _dns_client().run("result = drain(*args)", [server])
    ]


DNS_A = 1


# A tenant's DNS server through hub00 (C0001-00's NAT64), from mgt00: vpncmangle
# translates the A record of an IPv4-only name.
DNS_SERVER = "fdcc:0:c:1::172.16.31.1"
DNS_NAME = "v4lonly.example.com"
DNS_ANSWER = [("AAAA", "fdcc:0:c:1::ac10:1f04")]
# mgt00's tunnel to hub00. hub01 has the same tenants and prefixes: through it
# the answer would say nothing of hub00.
UPLINK = "xfrm0"
SERVICES = [
    command(["swanctl", "--stats"], timeout=10),
    command(["vtysh", "-c", "show bgp vrf CORE summary"], timeout=10),
]


def not_answering(host: str = HOST, *, dns: bool = True) -> list[str]:
    """Return the daemons next to vpnc that don't answer: charon, FRR, vpncmangle.

    dns: vpncmangle too, with a query through a tenant's tunnel, which is up.
    """
    problems = [
        f"{name} doesn't answer: {answer.get('error') or answer['err'].strip()}"
        for name, answer in zip(("charon", "FRR"), batch(host, SERVICES), strict=True)
        if "error" in answer or answer["rc"]
    ]
    if not dns:
        return problems
    route = sh(DNS_CLIENT_HOST, ["ip", "-6", "route", "get", DNS_SERVER], check=False)
    if f"dev {UPLINK} " not in route:
        problems.append(f"mgt00 reaches {DNS_SERVER} not through {host}: {route!r}")
        return problems
    answers, _ = dns_ask(DNS_SERVER, DNS_NAME, DNS_A)
    found = [
        [(a.source, str(a.address)) for a in addresses(answer, answers_only=True)]
        for answer in answers
    ]
    if found != [DNS_ANSWER]:
        problems.append(f"vpncmangle answered {DNS_NAME} with {found}")
    return problems


def up_connections(host: str = HOST) -> set[str]:
    """Return the connections that are up."""
    return {
        c["id"]
        for c in api("GET", CONNECTIONS, host=host)[1]
        if c["oper_status"] == "UP"
    }


# Connections that were up are up again within this time after a fault or crash.
RECOVER_TIMEOUT = 360


# Right after a recovery a query may be lost, e.g. while mgt00's routes through
# hub00 come back: the daemons answer within this time.
ANSWER_TIMEOUT = 30


def check_answering(host: str = HOST) -> None:
    """Check that charon, FRR and vpncmangle answer."""
    if not not_answering(host):
        return
    try:
        wait_until(
            lambda: not not_answering(host),
            timeout=ANSWER_TIMEOUT,
            message="the daemons to answer",
        )
    except TimeoutError:
        problems = not_answering(host)
        assert not problems, "\n".join(problems)


# After a restart or an outage BGP is up again within this time: FRR tries to
# connect every 30 s.
BGP_TIMEOUT = 180


def _down(sessions: set[tuple[str, str, int]]) -> list[str]:
    return sorted(
        f"{peer} {state}" for peer, state, _ in sessions if state != "Established"
    )


def bgp_down(host: str = HOST) -> list[str]:
    """Return CORE's BGP sessions that aren't established."""
    return _down(_bgp(host))


def down(host: str = HOST) -> list[str]:
    """Return the enabled connections and BGP sessions that aren't up."""
    connections = api("GET", CONNECTIONS, host=host)[1]
    return [
        c["id"]
        for c in connections
        if c["admin_status"] == "UP" and c["oper_status"] != "UP"
    ] + bgp_down(host)


def check_bgp(host: str = HOST, timeout: float = BGP_TIMEOUT) -> None:
    """Check that CORE's BGP sessions are established, or get so in time."""
    try:
        wait_until(lambda: not bgp_down(host), timeout=timeout, message="BGP")
    except TimeoutError:
        msg = f"BGP sessions down: {', '.join(bgp_down(host))}"
        raise AssertionError(msg) from None


def unsound(host: str = HOST, *, dns: bool = True) -> list[str]:
    """Return what's wrong with a node: BGP, what the daemons took, their answers.

    dns: see not_answering.
    """
    return [
        *(f"BGP session down: {session}" for session in bgp_down(host)),
        *not_loaded(host),
        *not_answering(host, dns=dns),
    ]


@dataclass(frozen=True)
class Vitals:
    """What must stay as it is while a node gets generated packets."""

    daemons: frozenset[tuple[str, int]]
    up: frozenset[str]
    bgp_down: tuple[str, ...] = ()
    restarts: int = 0

    def check(self, host: str = HOST) -> None:
        """Check that the daemons run on, and what was up is still up."""
        now = vitals(host)
        assert now.restarts == 0, "vpnc exited"
        assert now.daemons == self.daemons, "a daemon exited"
        down = self.up - now.up
        assert not down, f"went down: {', '.join(sorted(down))}"
        assert not now.bgp_down, f"BGP went down: {', '.join(now.bgp_down)}"


def vitals(host: str = HOST) -> Vitals:
    """Return a node's daemons, connections that are up, BGP and restarts, at once."""
    try:
        processes, bgp, connections, restarts_ = batch(
            host,
            [PGREP, BGP, _request("GET", CONNECTIONS, None), RESTARTS],
        )
    except AgentError as err:
        msg = f"no answer from {host} ({err})"
        raise ApiError(msg) from err
    return Vitals(
        frozenset(_processes(processes.get("out", ""))),
        frozenset(
            c["id"]
            for c in _response("GET", CONNECTIONS, connections)[1]
            if c["oper_status"] == "UP"
        ),
        tuple(_down(_sessions(bgp.get("out", "")))),
        _restarts(host, restarts_.get("out", "")),
    )


def stable(host: str = HOST, interval: float = 1) -> dict[str, Any]:
    """Return a node's snapshot once two in a row, interval apart, are the same."""
    previous: dict[str, Any] = {}

    def same() -> dict[str, Any] | None:
        nonlocal previous
        time.sleep(interval)
        current = snapshot(host)
        if current == previous:
            return current
        previous = current
        return None

    previous = snapshot(host)
    return wait_until(same, timeout=120, interval=0.02, message="a stable state")


CONFIG_DIR = "/opt/ncubed/config/vpnc"


class Canary:
    """A tenant without configuration, whose active file tells what vpnc handled.

    vpnc handles changed files in turn, each after 0.1 s. The canary's file gets
    one of two texts that aren't YAML, each with its own error: once vpnc
    reports that error, it handled the files written before (but see settled).
    Moved into place, which is one change to handle.
    """

    TEXTS = ("a: [", "\n\na: [")

    def __init__(self, tenant: str = "C0004", host: str = HOST) -> None:
        """Learn the errors of both texts."""
        self.tenant = tenant
        self.host = host
        self.file = f"{ACTIVE_DIR}/{tenant}.yaml"
        self.turn = 0
        self.errors: list[str] = []
        self.errors = [self.handled(), self.handled()]

    def error(self) -> str | None:
        """Return why vpnc doesn't load the canary's file."""
        tenants = api("GET", "/v1/config/tenants", host=self.host)[1]
        return next((t["error"] for t in tenants if t["id"] == self.tenant), None)

    def handled(self, timeout: float = 120) -> str:
        """Wait until vpnc handled the files written so far; return the error."""
        self.turn = 1 - self.turn
        before = self.error()
        write_file(
            self.host,
            self.file,
            self.TEXTS[self.turn],
            via=f"{CONFIG_DIR}/.fuzz-canary",
        )

        def reported() -> str | None:
            found = self.error()
            if self.errors:
                return found if found == self.errors[1 - self.turn] else None
            return found if found != before else None

        return wait_until(reported, timeout, message="vpnc to handle the files")

    def settled(self, timeout: float = 120) -> None:
        """Wait until vpnc handled the files written so far, for certain.

        vpnc's own check also loads files that changed, not in turn: it may load
        the canary's before a file written earlier. Not twice in a row.
        """
        self.handled(timeout)
        self.handled(timeout)

    def remove(self) -> None:
        """Remove the canary's file."""
        sh(self.host, ["rm", "-f", self.file])


# Restoring the deployed configuration: back to the same state within this time.
RESET_TIMEOUT = 300
# What a reset puts back: configuration, history (and pending confirms), and the
# SSH connections' keys and servers' host keys.
DEPLOYED_DIRS = [
    f"{CONFIG_DIR}/active",
    f"{CONFIG_DIR}/candidate",
    f"{CONFIG_DIR}/history",
    f"{CONFIG_DIR}/known_hosts",
    "/var/lib/vpnc-ssh/.ssh",
]
# Unpacks the saved directories over the node's, and removes what wasn't saved;
# a tenant that's in both isn't removed in between.
RESET_SCRIPT = """
set -e
saved=$(mktemp -d)
tar -C "$saved" -xpf -
for dir in "$@"; do
    mkdir -p "$dir"
    for path in "$dir"/* "$dir"/.[!.]*; do
        [ -e "$path" ] && [ ! -e "$saved$path" ] && rm -rf "$path"
    done
    cp -a "$saved$dir"/. "$dir"/
done
rm -rf "$saved"
"""


class Deployed:
    """A node's configuration files and state as deployed."""

    def __init__(self, host: str = HOST) -> None:
        """Read them once the lab is up and its state stable; it must be sound."""
        self.host = host

        def settled() -> dict[str, Any] | None:
            # Just deployed, CORE's tunnels come up, drop and come up again.
            state = stable(host, interval=5)
            return None if down(host) else state

        try:
            self.state = wait_until(settled, RECOVER_TIMEOUT, message="the lab")
        except TimeoutError:
            msg = f"the fuzz lab isn't up: {', '.join(down(host))}"
            raise AssertionError(msg) from None
        FRR_DEPLOYED_DIFFERENCES.update(frr_differences(host))
        disabled = sorted(
            c for c, admin in self.state["(vpnc)"]["admin_status"] if admin != "UP"
        )
        assert not disabled, f"redeploy the fuzz lab: {', '.join(disabled)} disabled"
        check_loaded(host)
        check_answering(host)
        self.up = up_connections(host)
        self.files = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "podman", "exec", f"{CONTAINER_PREFIX}{host}",
                "tar", "-C", "/", "-cpf", "-",
                *(directory.lstrip("/") for directory in DEPLOYED_DIRS),
            ],
            capture_output=True,
            check=True,
        ).stdout  # fmt: skip

    def restarted(self) -> None:
        """Take the daemons' new processes, once all run, after a restart."""
        names = set(DAEMONS.split("|"))

        def processes() -> set[tuple[str, int]] | None:
            found = daemons(self.host)
            return found if {name for name, _ in found} == names else None

        self.state["(daemons)"] = {
            "processes": wait_until(
                processes, timeout=RESET_TIMEOUT, message="daemons"
            ),
        }

    def healthy(self, also: set[str] = frozenset(), after: str = "") -> None:
        """Wait until what was up as deployed (and also) is up again, BGP too."""
        expected = self.up | also
        try:
            wait_until(
                lambda: up_connections(self.host) >= expected,
                timeout=RECOVER_TIMEOUT,
                message="the connections to be up again",
            )
        except TimeoutError:
            down = sorted(expected - up_connections(self.host))
            msg = f"{after or 'now'}: still down: {', '.join(down)}"
            raise AssertionError(msg) from None
        check_bgp(self.host)

    def reset(self) -> None:
        """Put the deployed files back; the state must follow."""
        container = f"{CONTAINER_PREFIX}{self.host}"
        subprocess.run(  # noqa: S603
            [  # noqa: S607
                "podman", "exec", "-i", container,
                "bash", "-c", RESET_SCRIPT, "reset", *DEPLOYED_DIRS,
            ],
            input=self.files,
            check=True,
        )  # fmt: skip
        try:
            wait_until(
                lambda: snapshot(self.host) == self.state,
                timeout=RESET_TIMEOUT,
                message="the deployed state",
            )
        except TimeoutError:
            changes = diff(self.state, snapshot(self.host))
            msg = "\n".join(["not as deployed after restoring the files:", *changes])
            raise AssertionError(msg) from None
        check_loaded(self.host)
        check_answering(self.host)


@pytest.fixture(scope="session")
def deployed() -> Deployed:
    """Return hub00 as deployed, to reset it to."""
    return Deployed()


__all__ = [
    "ACTIVE_DIR",
    "CANDIDATE_DIR",
    "CONFIG_DIR",
    "CONTAINER_PREFIX",
    "FUZZ_LAB",
    "HISTORY_DIR",
    "HOST",
    "MAIN_PID",
    "RECOVER_TIMEOUT",
    "Agent",
    "AgentError",
    "ApiError",
    "Canary",
    "CommandError",
    "Deployed",
    "Vitals",
    "api",
    "batch",
    "bgp_down",
    "check_answering",
    "check_bgp",
    "check_loaded",
    "command",
    "daemons",
    "diff",
    "dns_ask",
    "dns_drain",
    "dns_observe",
    "expect_restart",
    "gets",
    "not_answering",
    "not_loaded",
    "restarted_node",
    "restarted_vpnc",
    "restarts",
    "run_cmd",
    "run_cmd_shell",
    "sh",
    "snapshot",
    "stable",
    "unsound",
    "up_connections",
    "vitals",
    "wait_until",
    "write_file",
]
