"""A minimal AgentX subagent (RFC 2741): add objects to snmpd over its socket.

Read-only. snmpd waits about a second for an answer and drops the subagent
after a few misses, so a view must answer from memory.
"""

from __future__ import annotations

import select
import socket
import struct
import time
from typing import Protocol

Oid = tuple[int, ...]
# The type of a value (below) and the value.
Value = tuple[int, int | bytes]

INTEGER = 2
OCTET_STRING = 4
COUNTER32 = 65
GAUGE32 = 66
TIMETICKS = 67
COUNTER64 = 70
_NO_SUCH_INSTANCE = 129
_END_OF_MIB_VIEW = 130

_OPEN = 1
_CLOSE = 2
_REGISTER = 3
_UNREGISTER = 4
_GET = 5
_GETNEXT = 6
_GETBULK = 7
_TESTSET = 8
_COMMITSET = 9
_UNDOSET = 10
_PING = 13
_RESPONSE = 18

_INSTANCE_REGISTRATION = 0x01
_NETWORK_BYTE_ORDER = 0x10
_NOT_WRITABLE = 17
_HEADER = 20
# Seconds to wait for snmpd's answer.
_TIMEOUT = 30

DEFAULT_PRIORITY = 127


class Error(Exception):
    """snmpd refused a request or closed the session."""


class View(Protocol):
    """The objects a session serves."""

    def get(self, oid: Oid) -> Value | None:
        """Return the value of an object."""

    def next(self, oid: Oid, *, include: bool) -> tuple[Oid, Value] | None:
        """Return the first object after oid; or at it, with include."""


def _oid(oid: Oid) -> bytes:
    prefix = 0
    if len(oid) > 4 and oid[:4] == (1, 3, 6, 1) and oid[4] < 256:  # noqa: PLR2004
        prefix, oid = oid[4], oid[5:]
    return struct.pack(f"!BBxx{len(oid)}I", len(oid), prefix, *oid)


def _octets(data: bytes) -> bytes:
    return struct.pack("!I", len(data)) + data + bytes(-len(data) % 4)


def _varbind(oid: Oid, kind: int, value: int | bytes = 0) -> bytes:
    data = struct.pack("!Hxx", kind) + _oid(oid)
    if kind == INTEGER:
        data += struct.pack("!i", value)
    elif kind in (COUNTER32, GAUGE32, TIMETICKS):
        data += struct.pack("!I", int(value) & 0xFFFFFFFF)
    elif kind == COUNTER64:
        data += struct.pack("!Q", int(value) & 0xFFFFFFFFFFFFFFFF)
    elif kind == OCTET_STRING:
        data += _octets(bytes(value))  # type: ignore[arg-type]
    return data


class _Reader:
    """Read the fields of a PDU's payload."""

    def __init__(self, data: bytes, order: str) -> None:
        self.data = data
        self.order = order
        self.position = 0

    def unpack(self, fields: str) -> tuple[int, ...]:
        values = struct.unpack_from(self.order + fields, self.data, self.position)
        self.position += struct.calcsize(self.order + fields)
        return values

    def oid(self) -> tuple[Oid, bool]:
        """Return an object identifier and its include flag."""
        count, prefix, include = self.unpack("BBBx")
        subids = self.unpack(f"{count}I")
        return ((1, 3, 6, 1, prefix, *subids) if prefix else subids), bool(include)

    def ranges(self) -> list[tuple[Oid, bool, Oid]]:
        """Return the remaining search ranges: start, include and end."""
        ranges = []
        while self.position < len(self.data):
            start, include = self.oid()
            ranges.append((start, include, self.oid()[0]))
        return ranges


class Session:
    """A session with snmpd (the AgentX master)."""

    def __init__(self, path: str, description: str, view: View) -> None:
        """Connect to snmpd's AgentX socket and open a session."""
        self._view = view
        self._session_id = 0
        self._packet_id = 0
        self._uptime = (0, time.monotonic())
        self._socket = socket.socket(socket.AF_UNIX)
        self._socket.settimeout(_TIMEOUT)
        try:
            self._socket.connect(path)
            # No timeout of our own, no id.
            self._call(_OPEN, bytes(4) + _oid(()) + _octets(description.encode()))
        except BaseException:
            self._socket.close()
            raise

    def close(self) -> None:
        """Close the connection; snmpd drops the registrations."""
        self._socket.close()

    def uptime(self) -> int:
        """Return snmpd's sysUpTime now, in hundredths of a second."""
        ticks, at = self._uptime
        return ticks + int((time.monotonic() - at) * 100)

    def register(
        self,
        oid: Oid,
        priority: int = DEFAULT_PRIORITY,
        *,
        instance: bool = False,
    ) -> None:
        """Register a subtree, or one object (instance).

        The most specific registration gets a request; of equal ones, the lowest
        priority.
        """
        flags = _INSTANCE_REGISTRATION if instance else 0
        self._call(_REGISTER, struct.pack("!xBxx", priority) + _oid(oid), flags)

    def unregister(self, oid: Oid, priority: int = DEFAULT_PRIORITY) -> None:
        """Remove a registration."""
        self._call(_UNREGISTER, struct.pack("!xBxx", priority) + _oid(oid))

    def ping(self) -> None:
        """Check that snmpd still answers."""
        self._call(_PING, b"")

    def serve(self, seconds: float) -> None:
        """Answer snmpd's requests for some time."""
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            if select.select([self._socket], [], [], left)[0]:
                self._answer(*self._receive())

    def _send(
        self,
        kind: int,
        payload: bytes,
        flags: int,
        ids: tuple[int, ...],
    ) -> None:
        header = struct.pack(
            "!BBBxIIII",
            1,
            kind,
            flags | _NETWORK_BYTE_ORDER,
            *ids,
            len(payload),
        )
        self._socket.sendall(header + payload)

    def _read(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            if not (chunk := self._socket.recv(count - len(data))):
                msg = "snmpd closed the connection"
                raise Error(msg)
            data += chunk
        return data

    def _receive(self) -> tuple[int, tuple[int, ...], _Reader]:
        """Return the type, ids (session, transaction, packet) and payload of a PDU."""
        header = self._read(_HEADER)
        order = "!" if header[2] & _NETWORK_BYTE_ORDER else "<"
        kind, *ids, length = struct.unpack(order + "xBxxIIII", header)
        return kind, tuple(ids), _Reader(self._read(length), order)

    def _call(self, kind: int, payload: bytes, flags: int = 0) -> None:
        """Send a request to snmpd and wait for its answer."""
        self._packet_id += 1
        self._send(kind, payload, flags, (self._session_id, 0, self._packet_id))
        while True:
            received, ids, reader = self._receive()
            if received != _RESPONSE or ids[2] != self._packet_id:
                # snmpd doesn't wait with its own requests.
                self._answer(received, ids, reader)
                continue
            uptime, error, _ = reader.unpack("IHH")
            if error:
                msg = f"snmpd answered request {kind} with error {error}"
                raise Error(msg)
            self._session_id = ids[0]
            self._uptime = (uptime, time.monotonic())
            return

    def _next(self, start: Oid, end: Oid, *, include: bool) -> bytes:
        found = self._view.next(start, include=include)
        if found is None or (end and found[0] >= end):
            return _varbind(start, _END_OF_MIB_VIEW)
        return _varbind(found[0], *found[1])

    def _bulk(self, reader: _Reader) -> bytes:
        """Return the next objects: one for the first ranges, several for the rest."""
        non_repeaters, repetitions = reader.unpack("HH")
        ranges = reader.ranges()
        varbinds = b""
        for start, include, end in ranges[:non_repeaters]:
            varbinds += self._next(start, end, include=include)
        repeated = ranges[non_repeaters:]
        for _ in range(repetitions):
            for position, (start, include, end) in enumerate(repeated):
                found = self._view.next(start, include=include)
                if found is None or (end and found[0] >= end):
                    varbinds += _varbind(start, _END_OF_MIB_VIEW)
                else:
                    varbinds += _varbind(found[0], *found[1])
                    repeated[position] = (found[0], False, end)
        return varbinds

    def _answer(self, kind: int, ids: tuple[int, ...], reader: _Reader) -> None:
        """Answer a request of snmpd."""
        error = 0
        varbinds = b""
        if kind == _GET:
            for oid, _, _ in reader.ranges():
                value = self._view.get(oid)
                varbinds += _varbind(oid, *(value or (_NO_SUCH_INSTANCE, 0)))
        elif kind == _GETNEXT:
            for start, include, end in reader.ranges():
                varbinds += self._next(start, end, include=include)
        elif kind == _GETBULK:
            varbinds = self._bulk(reader)
        elif kind in (_TESTSET, _COMMITSET, _UNDOSET):
            error = _NOT_WRITABLE
        elif kind == _CLOSE:
            msg = "snmpd closed the session"
            raise Error(msg)
        else:
            return
        payload = struct.pack("!IHH", 0, error, 0) + varbinds
        self._send(_RESPONSE, payload, 0, ids)
