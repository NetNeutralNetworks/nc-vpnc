"""Events: what happened to a connection, network instance, tenant or the service.

An event is a journal entry with fields of its own (VPNC_*), so the history
survives a restart and is read back per subject (see vpnc.api.events). It also
shows as a line in vpnc's log. Without a journal, events are only logged.
"""

from __future__ import annotations

import json
import logging
import socket
import struct

from vpnc import config

logger = logging.getLogger("vpnc")

JOURNAL_SOCKET = "/run/systemd/journal/socket"
# The journal's MESSAGE_ID of every event.
MESSAGE_ID = "6d5c0f1e9b7a4c3e8a2f4b1d7e9c0a35"
# Python's levels as syslog priorities.
PRIORITIES = {logging.INFO: 6, logging.WARNING: 4, logging.ERROR: 3}


def subject(
    connection: str | None,
    network_instance: str | None,
    tenant: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Return a subject with what it's part of: C0001-00-0 is in C0001-00 of C0001."""
    if connection and not network_instance:
        network_instance = connection.rpartition("-")[0]
    if network_instance and not tenant:
        downlink = config.DOWNLINK_NI_RE.match(network_instance)
        tenant = network_instance[:-3] if downlink else config.DEFAULT_TENANT
    return connection, network_instance, tenant


def _field(name: str, value: str) -> bytes:
    """Return a field in the journal's native protocol."""
    data = value.encode()
    if b"\n" in data:
        return name.encode() + b"\n" + struct.pack("<Q", len(data)) + data + b"\n"
    return name.encode() + b"=" + data + b"\n"


def record(  # noqa: PLR0913
    event: str,
    message: str,
    *,
    connection: str | None = None,
    network_instance: str | None = None,
    tenant: str | None = None,
    level: int = logging.INFO,
    **details: object,
) -> None:
    """Record an event (e.g. OPER_DOWN) of a connection, network instance or tenant.

    The service's own are the DEFAULT tenant's. Details are kept with it.
    """
    connection, network_instance, tenant = subject(connection, network_instance, tenant)
    name = connection or network_instance or tenant or "vpnc"
    fields = {
        "MESSAGE": f"{name}: {message}",
        "MESSAGE_ID": MESSAGE_ID,
        "PRIORITY": str(PRIORITIES.get(level, 6)),
        "SYSLOG_IDENTIFIER": "vpnc",
        "VPNC_EVENT": event,
        "VPNC_TENANT": tenant,
        "VPNC_NETWORK_INSTANCE": network_instance,
        "VPNC_CONNECTION": connection,
        "VPNC_DETAILS": json.dumps(details, default=str) if details else None,
    }
    data = b"".join(_field(key, value) for key, value in fields.items() if value)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, JOURNAL_SOCKET)
    except OSError:
        logger.log(level, "%s: %s (%s)", name, message, event)


def duration(seconds: float) -> str:
    """Return seconds as e.g. 45s, 3m12s, 2h5m or 4d3h."""
    seconds = int(seconds)
    for unit, size, sub, sub_size in (
        ("d", 86400, "h", 3600),
        ("h", 3600, "m", 60),
        ("m", 60, "s", 1),
    ):
        if seconds >= size:
            rest = seconds % size // sub_size
            return (
                f"{seconds // size}{unit}{rest}{sub}"
                if rest
                else f"{seconds // size}{unit}"
            )
    return f"{seconds}s"
