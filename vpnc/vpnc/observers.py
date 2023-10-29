"""
Observers used to monitor file changes
"""

import logging
import pathlib
import time

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer

from . import config, helpers, vpnc_endpoint, vpnc_hub

logger = logging.getLogger("vpnc")


def uplink_observer() -> Observer:
    """
    Create the observer for uplink connections configuration
    """

    # Define what should happen when the config file with uplink data is modified.
    class UplinkHandler(FileSystemEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            helpers.load_config(config.VPNC_A_SERVICE_CONFIG_PATH)
            time.sleep(0.1)
            vpnc_hub.update_uplink_connection()

    # Create the observer object. This doesn't start the handler.
    observer = Observer()
    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=UplinkHandler(),
        path=config.VPNC_A_SERVICE_CONFIG_PATH,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer


def downlink_observer() -> Observer:
    """
    Create the observer for downlink connections configuration
    """
    if config.VPNC_SERVICE_CONFIG.mode.name == "HUB":
        module = vpnc_hub
    else:
        module = vpnc_endpoint

    # Define what should happen when downlink files are created, modified or deleted.
    class DownlinkHandler(PatternMatchingEventHandler):
        """
        Handler for the event monitoring.
        """

        def on_created(self, event: FileCreatedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            module.add_downlink_connection(downlink_config)

        def on_modified(self, event: FileModifiedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path)
            time.sleep(0.1)
            module.add_downlink_connection(downlink_config)

        def on_deleted(self, event: FileDeletedEvent):
            logger.info("File %s: %s", event.event_type, event.src_path)
            downlink_config = pathlib.Path(event.src_path).stem
            module.delete_downlink_connection(downlink_config)

    # Create the observer object. This doesn't start the handler.
    observer = Observer()

    # Configure the event handler that watches directories. This doesn't start the handler.
    observer.schedule(
        event_handler=DownlinkHandler(
            patterns=["[aAbBcCdDeEfF]*.yaml"], ignore_directories=True
        ),
        path=config.VPNC_A_REMOTE_CONFIG_DIR,
        recursive=False,
    )
    # The handler will not be running as a thread.
    observer.daemon = False

    return observer
