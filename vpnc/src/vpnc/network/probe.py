"""Test whether hosts answer through an interface: an ICMP echo or a TCP connect.

All tests run at once and take TIMEOUT seconds at most together. A test leaves
through its interface, from the given address, and only an answer of the host
itself that comes back through that interface counts.
"""

from __future__ import annotations

import errno
import logging
import os
import random
import selectors
import socket
import struct
import time
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from itertools import islice
from typing import TYPE_CHECKING

from vpnc.network import namespace

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

logger = logging.getLogger("vpnc")

IPAddress = IPv4Address | IPv6Address

# Seconds to wait for an answer.
TIMEOUT = 2.0
# Seconds until an echo request is sent again. TCP resends by itself.
RESEND_AFTER = 1.0
# Tests (sockets) open at once.
BATCH = 256

ECHO_REQUEST = {4: 8, 6: 128}
ECHO_REPLY = {4: 0, 6: 129}
# Jool (NAT64) may use higher ICMP ids for its translations.
MAX_ICMP_ID = 60999
# An echo's type, code, checksum, id and sequence number.
ECHO_HEADER = struct.Struct("!BBHHH")
PAYLOAD = b"vpnc"


@dataclass(frozen=True)
class Test:
    """A test of a host, through an interface of a namespace."""

    netns: str
    ifname: str
    source: IPAddress
    address: IPAddress
    # None: an ICMP echo.
    port: int | None = None


def _checksum(data: bytes) -> int:
    """Return the Internet checksum (RFC 1071) of data."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _echo_request(version: int, ident: int, sequence: int) -> bytes:
    header = ECHO_HEADER.pack(ECHO_REQUEST[version], 0, 0, ident, sequence)
    # The kernel calculates ICMPv6's checksum.
    checksum = _checksum(header + PAYLOAD) if version == 4 else 0  # noqa: PLR2004
    return (
        ECHO_HEADER.pack(ECHO_REQUEST[version], 0, checksum, ident, sequence) + PAYLOAD
    )


def _is_echo_reply(version: int, data: bytes, ident: int) -> bool:
    """Return whether a received packet answers one of our echo requests."""
    if version == 4:  # noqa: PLR2004
        # A raw IPv4 socket also gets the IP header.
        data = data[(data[0] & 0x0F) * 4 :] if data else data
    if len(data) < ECHO_HEADER.size:
        return False
    kind, code, _, reply_ident, _ = ECHO_HEADER.unpack_from(data)
    return (kind, code, reply_ident) == (ECHO_REPLY[version], 0, ident)


class _Running:
    """A test that was started and waits for its answer."""

    def __init__(self, test: Test) -> None:
        """Open the test's socket, in the calling thread's namespace, and start."""
        self.test = test
        self.version = test.address.version
        self.ident = random.randint(1, MAX_ICMP_ID)  # noqa: S311
        self.sequence = 0
        family = socket.AF_INET if self.version == 4 else socket.AF_INET6  # noqa: PLR2004
        if test.port is None:
            protocol = (
                socket.IPPROTO_ICMP if self.version == 4 else socket.IPPROTO_ICMPV6  # noqa: PLR2004
            )
            self.sock = socket.socket(family, socket.SOCK_RAW, protocol)
        else:
            self.sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            self.sock.setblocking(False)  # noqa: FBT003
            # Out of the interface, and only answers that come in through it.
            self.sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                test.ifname.encode(),
            )
            self.sock.bind((str(test.source), 0))
            self.started = time.monotonic()
            # ICMP: only packets of the host are received.
            error = self.sock.connect_ex((str(test.address), test.port or 0))
            if error not in (0, errno.EINPROGRESS):
                raise OSError(error, os.strerror(error))  # noqa: TRY301
            if test.port is None:
                self.send()
        except OSError:
            self.sock.close()
            raise

    @property
    def events(self) -> int:
        """Return what to wait for: a packet, or the end of connecting."""
        return selectors.EVENT_READ if self.test.port is None else selectors.EVENT_WRITE

    def send(self) -> None:
        """Send an echo request."""
        self.sequence += 1
        self.sock.send(_echo_request(self.version, self.ident, self.sequence))

    def answered(self) -> bool | None:
        """Return whether the host answered; None if that isn't known yet."""
        if self.test.port is not None:
            error = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            # A refused connection is an answer of the host too.
            return error in (0, errno.ECONNREFUSED)
        try:
            data = self.sock.recv(1500)
        except BlockingIOError:
            return None
        except OSError:
            # E.g. an ICMP error.
            return False
        return True if _is_echo_reply(self.version, data, self.ident) else None


def _start(tests: list[Test]) -> tuple[list[_Running], dict[Test, str]]:
    """Start tests in the calling thread's namespace; return the failures too."""
    running: list[_Running] = []
    failed: dict[Test, str] = {}
    for test in tests:
        try:
            running.append(_Running(test))
        except OSError as err:  # noqa: PERF203
            failed[test] = err.strerror or str(err)
    return running, failed


def _resend(selector: selectors.BaseSelector) -> None:
    """Send the echo requests without an answer again."""
    for key in list(selector.get_map().values()):
        if key.data.test.port is not None:
            continue
        try:
            key.data.send()
        except OSError:
            selector.unregister(key.fileobj)


def _wait(running: list[_Running], timeout: float) -> dict[Test, float]:
    """Return the tests that are answered within the timeout, with after how long."""
    answered: dict[Test, float] = {}
    start = time.monotonic()
    resent = False
    with selectors.DefaultSelector() as selector:
        for item in running:
            selector.register(item.sock, item.events, item)
        while selector.get_map():
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                break
            if not resent and elapsed >= RESEND_AFTER:
                resent = True
                _resend(selector)
            limit = timeout if resent else min(timeout, RESEND_AFTER)
            for key, _ in selector.select(max(0.0, limit - elapsed)):
                item = key.data
                try:
                    result = item.answered()
                except OSError:
                    result = False
                if result is None:
                    continue
                selector.unregister(key.fileobj)
                if result:
                    answered[item.test] = time.monotonic() - item.started
    return answered


def _batches(tests: Iterable[Test]) -> Iterator[list[Test]]:
    iterator = iter(tests)
    while batch := list(islice(iterator, BATCH)):
        yield batch


def run(tests: Iterable[Test], timeout: float = TIMEOUT) -> dict[Test, float | None]:
    """Return per test after how many seconds its host answered; None if it didn't."""
    results: dict[Test, float | None] = {}
    for batch in _batches(tests):
        by_netns: dict[str, list[Test]] = {}
        for test in batch:
            by_netns.setdefault(test.netns, []).append(test)
        running: list[_Running] = []
        try:
            for netns, group in by_netns.items():
                try:
                    started, failed = namespace.call(
                        netns,
                        lambda group=group: _start(group),  # type: ignore[misc]
                    )
                except OSError as err:
                    # E.g. the namespace is gone.
                    failed = dict.fromkeys(group, err.strerror or str(err))
                    started = []
                running += started
                for test, error in failed.items():
                    logger.debug(
                        "Probe of %s through %s in %s failed: %s.",
                        test.address,
                        test.ifname,
                        test.netns,
                        error,
                    )
            answered = _wait(running, timeout)
        finally:
            for item in running:
                item.sock.close()
        results.update({test: answered.get(test) for test in batch})
    return results
