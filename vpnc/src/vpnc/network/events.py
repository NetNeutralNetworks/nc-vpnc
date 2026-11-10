"""Netlink event monitors for network instances."""

from __future__ import annotations

import asyncio
import logging
import queue
import threading
from typing import TYPE_CHECKING, Any

from pyroute2 import AsyncIPRoute
from pyroute2.netlink.rtnl import RTMGRP_LINK

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("vpnc")

# Seconds before reopening the socket after a failure.
RETRY_DELAY = 1
# Seconds start() waits for the socket to be bound.
START_TIMEOUT = 5


class LinkMonitor(threading.Thread):
    """Call a function for every link event in a network namespace.

    Events are received in an asyncio loop and handled in a separate thread, so
    the callback can use the synchronous IPRoute (which runs its own loop).
    """

    def __init__(self, netns: str, callback: Callable[[Any], None]) -> None:
        """Create the monitor; call start() to run it."""
        super().__init__(name=f"links-{netns}", daemon=True)
        self.netns = netns
        self.callback = callback
        self.loop = asyncio.new_event_loop()
        self.task: asyncio.Task[None] | None = None
        self.events: queue.Queue[Any] = queue.Queue()
        self.ready = threading.Event()
        self.worker = threading.Thread(
            target=self.work,
            name=f"links-{netns}-handler",
            daemon=True,
        )

    def start(self) -> None:
        """Start the monitor and wait until it receives events."""
        super().start()
        if not self.ready.wait(START_TIMEOUT):
            logger.warning("Link monitor for %s isn't listening yet.", self.netns)

    def run(self) -> None:
        """Run the event loop until stopped."""
        self.worker.start()
        asyncio.set_event_loop(self.loop)
        self.task = self.loop.create_task(self.listen())
        try:
            self.loop.run_until_complete(self.task)
        except asyncio.CancelledError:
            pass
        finally:
            self.loop.close()

    async def listen(self) -> None:
        """Receive link events, reopening the socket after failures."""
        while True:
            try:
                async with AsyncIPRoute(netns=self.netns, flags=0) as ipr:
                    await ipr.bind(groups=RTMGRP_LINK)
                    self.ready.set()
                    while True:
                        async for msg in ipr.get():
                            self.events.put(msg)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Link monitor for %s failed.", self.netns)
                await asyncio.sleep(RETRY_DELAY)

    def work(self) -> None:
        """Pass events to the callback in order, logging its failures."""
        while (msg := self.events.get()) is not None:
            try:
                self.callback(msg)
            except Exception:
                logger.exception("Handling a link event in %s failed.", self.netns)

    def stop(self) -> None:
        """Stop the monitor."""
        if self.task is not None and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.task.cancel)
        self.events.put(None)
        self.join(timeout=5)
