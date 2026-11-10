"""Netlink link and address events of network instances, in one thread."""

from __future__ import annotations

import errno
import logging
import selectors
import socket
import struct
import threading
from typing import TYPE_CHECKING, Any

from vpnc.network import namespace

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("vpnc")

# Multicast groups.
RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV6_IFADDR = 0x100
GROUPS = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
EVENTS = {
    16: "RTM_NEWLINK",
    17: "RTM_DELLINK",
    20: "RTM_NEWADDR",
    21: "RTM_DELADDR",
}
ADDRESS_EVENTS = ("RTM_NEWADDR", "RTM_DELADDR")
# Passed when events may have been lost: the namespace must be checked fully.
RESYNC = "RESYNC"
RECEIVE_BUFFER = 4 << 20
# Not in the socket module; sets the buffer above rmem_max (needs CAP_NET_ADMIN).
SO_RCVBUFFORCE = 33
# Seconds between checks for stopping and reopening failed sockets.
POLL_INTERVAL = 1.0


def _open(netns: str) -> socket.socket:
    """Return a non-blocking rtnetlink socket in netns, subscribed to the events."""
    sock = socket.socket(
        socket.AF_NETLINK,
        socket.SOCK_RAW,
        socket.NETLINK_ROUTE,
        fileno=namespace.netlink_socket(netns),
    )
    try:
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, RECEIVE_BUFFER)
        except PermissionError:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER)
        sock.bind((0, GROUPS))
        sock.setblocking(False)  # noqa: FBT003
    except BaseException:
        sock.close()
        raise
    return sock


def _parse(data: bytes) -> list[dict[str, Any]]:
    """Return the link and address events in a netlink datagram."""
    events: list[dict[str, Any]] = []
    offset = 0
    while offset + 16 <= len(data):
        length, msg_type = struct.unpack_from("IH", data, offset)
        if length < 16:  # noqa: PLR2004
            break
        if (name := EVENTS.get(msg_type)) is not None:
            event: dict[str, Any] = {"event": name}
            if name in ADDRESS_EVENTS:
                # struct ifaddrmsg: family, prefixlen, flags, scope, index.
                event["scope"] = data[offset + 16 + 3]
            events.append(event)
        offset += (length + 3) & ~3
    return events


class LinkMonitor(threading.Thread):
    """Call a function per network namespace for its link and address events.

    One thread waits on the sockets of all namespaces. Callbacks run in it, so
    they must be quick (e.g. set a trigger).
    """

    def __init__(self) -> None:
        """Create the monitor; it starts with the first watch()."""
        super().__init__(name="links", daemon=True)
        self.selector = selectors.DefaultSelector()
        self.lock = threading.Lock()
        self.callbacks: dict[str, Callable[[dict[str, Any]], None]] = {}
        self.sockets: dict[str, socket.socket] = {}
        # Namespaces whose socket failed, to reopen.
        self.failed: set[str] = set()
        self.stopped = threading.Event()

    def watch(self, netns: str, callback: Callable[[dict[str, Any]], None]) -> None:
        """Call callback for the events in netns from now on."""
        sock = _open(netns)
        with self.lock:
            self.callbacks[netns] = callback
            self.sockets[netns] = sock
            self.selector.register(sock, selectors.EVENT_READ, netns)
            if not self.is_alive():
                self.start()

    def unwatch(self, netns: str) -> None:
        """Stop calling the callback of netns."""
        with self.lock:
            self.callbacks.pop(netns, None)
            self.failed.discard(netns)
            self._close(netns)

    def stop(self) -> None:
        """Stop the monitor."""
        self.stopped.set()
        if self.is_alive():
            self.join(timeout=5)

    def _close(self, netns: str) -> None:
        if (sock := self.sockets.pop(netns, None)) is not None:
            self.selector.unregister(sock)
            sock.close()

    def run(self) -> None:
        """Receive events until stopped."""
        while not self.stopped.is_set():
            ready = self.selector.select(POLL_INTERVAL)
            with self.lock:
                for key, _ in ready:
                    self._receive(key.data, key.fileobj)
                self._reopen()

    def _receive(self, netns: str, sock: Any) -> None:  # noqa: ANN401
        if self.sockets.get(netns) is not sock:
            # Closed meanwhile.
            return
        while True:
            try:
                data = sock.recv(1 << 16)
            except BlockingIOError:
                return
            except OSError as e:
                if e.errno == errno.ENOBUFS:
                    logger.warning("Missed link events in %s.", netns)
                    self._call(netns, {"event": RESYNC})
                    continue
                logger.warning("Link monitor for %s failed: %s", netns, e)
                self._close(netns)
                self.failed.add(netns)
                return
            for event in _parse(data):
                self._call(netns, event)

    def _reopen(self) -> None:
        for netns in list(self.failed):
            try:
                sock = _open(netns)
            except OSError:
                continue
            self.failed.discard(netns)
            self.sockets[netns] = sock
            self.selector.register(sock, selectors.EVENT_READ, netns)
            self._call(netns, {"event": RESYNC})

    def _call(self, netns: str, event: dict[str, Any]) -> None:
        if (callback := self.callbacks.get(netns)) is None:
            return
        try:
            callback(event)
        except Exception:
            logger.exception("Handling a link event in %s failed.", netns)


MONITOR = LinkMonitor()
