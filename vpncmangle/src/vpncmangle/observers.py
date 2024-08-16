"""
vpncmangle observers to load ACLs
"""

import logging
import pathlib
import time

from watchdog.events import (
    FileSystemEvent,
    FileSystemEventHandler,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from . import config, helpers

logger = logging.getLogger("vpncmangle")


def observe() -> BaseObserver:
    """
    Create the observer for swanctl configuration
    """

    # Define what should happen when downlink files are created, modified or deleted.
    class VpnmanglerHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileSystemEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            helpers.load_config()

        def on_modified(self, event: FileSystemEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            helpers.load_config()

        def on_deleted(self, event: FileSystemEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            time.sleep(0.1)
            helpers.load_config()

    # Create the observer object. This doesn't start the handler.
    observer: BaseObserver = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=VpnmanglerHandler(patterns=["*.json"], ignore_directories=True),
        path=config.CONFIG_PATH.parent,
        recursive=False,
    )
    # The handler should exit on main thread close
    observer.daemon = True

    return observer
