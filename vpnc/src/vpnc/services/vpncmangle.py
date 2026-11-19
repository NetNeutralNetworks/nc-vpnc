"""Manages vpncmangle startup and shutdown as well as the configuration."""

import atexit
import json
import logging
import os
import pathlib
import subprocess
from ipaddress import IPv4Network
from typing import Any

from vpnc import accounts, config, files, helpers, shared
from vpnc.network import namespace

logger = logging.getLogger("vpnc")

CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpncmangle/translations.json")
# The service's dns settings.
LIMITS_PATH = CONFIG_PATH.with_name("limits.json")
# vpncmangle writes its counters there.
STATS_PATH = pathlib.Path("/run/vpncmangle/stats.json")
# The kernel's netfilter queues of the reading thread's namespace (root only).
QUEUES_PATH = "/proc/thread-self/net/netfilter/nfnetlink_queue"


def generate_config() -> None:
    """Generate vpncmangle configuration."""
    output: dict[str, dict[str, Any]] = {}

    with shared.VPNCMANGLE_LOCK:
        for net_ni in helpers.network_instances().values():
            if net_ni.id in (config.CORE_NI, config.EXTERNAL_NI):
                continue
            output[net_ni.id] = {"dns64": [], "dns66": []}
            if nat64_scope := net_ni.nat64_scope():
                output[net_ni.id]["dns64"] = [
                    (str(nat64_scope), str(IPv4Network("0.0.0.0/0"))),
                ]
            for connection in net_ni.connections.values():
                for route6 in connection.routes.ipv6:
                    nptv6_prefix = route6.nptv6_prefix
                    if not nptv6_prefix:
                        nptv6_prefix = route6.to
                    output[net_ni.id]["dns66"].append(
                        (str(nptv6_prefix), str(route6.to)),
                    )

        files.ensure_file(CONFIG_PATH, json.dumps(output))
        limits = helpers.get_default_tenant().dns
        files.ensure_file(LIMITS_PATH, limits.model_dump_json())


# The running vpncmangle process.
PROCESS: subprocess.Popen[bytes] | None = None


def stop() -> None:
    """Shut down the vpncmangle service when terminating the program."""
    if PROCESS is None:
        return
    logger.info("Stopping vpncmangle process in network instance %s.", config.CORE_NI)
    PROCESS.terminate()
    PROCESS.wait()


atexit.register(stop)


def start() -> None:
    """Start the the vpncmangle service in the CORE network instance."""
    # VPNC in hub mode doctors DNS responses so requests are sent via the tunnel.
    # Start the VPNC mangle process in the CORE network instance.
    # This process mangles DNS responses to translate A responses to AAAA responses.
    logger.info("Starting vpncmangle process in network instance %s.", config.CORE_NI)
    user = accounts.user(accounts.VPNCMANGLE)
    STATS_PATH.parent.mkdir(mode=0o755, exist_ok=True)
    os.chown(STATS_PATH.parent, user.pw_uid, user.pw_gid)
    # It reads the tenants' DNS responses: not as root, and with only the
    # capability for the netfilter queue and its nftables table.
    proc = namespace.popen(
        config.CORE_NI,
        [
            *accounts.command(accounts.VPNCMANGLE, ("net_admin",)),
            f"{config.VPNC_INSTALL_DIR}/bin/vpncmangle",
        ],
    )

    global PROCESS  # noqa: PLW0603
    PROCESS = proc


def _queue_dropped() -> int:
    """Return the responses the kernel dropped: the queue was full or unread."""

    def read() -> int:
        # queue, peer, waiting, copy mode, copy range, dropped, user dropped, ...
        lines = pathlib.Path(QUEUES_PATH).read_text(encoding="utf-8").splitlines()
        return sum(int(n) for line in lines for n in line.split()[5:7])

    try:
        return namespace.call(config.CORE_NI, read)
    except (OSError, ValueError):
        return 0


def stats() -> dict[str, Any]:
    """Return vpncmangle's counters since it started; empty if there are none."""
    try:
        counters = json.loads(STATS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if dropped := _queue_dropped():
        counters.setdefault("dropped", {})["QUEUE_FULL"] = dropped
    return counters


def ensure_running() -> None:
    """Restart vpncmangle if it isn't running."""
    if PROCESS is not None and PROCESS.poll() is None:
        return
    logger.warning("vpncmangle isn't running. Starting it.")
    start()
