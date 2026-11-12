#!/usr/bin/env python3
"""Starts the service and runs it in either endpoint or hub mode."""

import logging
import os
import resource
import signal
import sys
from logging.handlers import RotatingFileHandler

from vpnc import config, core, files, helpers, migration
from vpnc.models import tenant

# LOGGER
# Get logger
logger = logging.getLogger()


def main() -> None:
    """Run the VPNC service."""
    # The logs name tenants and peers: not readable for all.
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(config.LOG_DIR, 0, config.IPSEC_GROUP)
    config.LOG_DIR.chmod(0o750)

    # Configure logging
    logger.setLevel(level=logging.INFO)
    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s(File:%(name)s,Line:%(lineno)d,"
            "%(funcName)s) - %(levelname)s - %(message)s"
        ),
        datefmt="%m/%d/%Y %H:%M:%S %p",
    )
    rothandler = RotatingFileHandler(
        config.LOG_DIR / "vpnc.log",
        maxBytes=100000,
        backupCount=5,
    )
    rothandler.setFormatter(formatter)
    logger.addHandler(rothandler)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    # Load the configuration
    logger.info("Loading configuration from '%s'.", config.VPNC_A_CONFIG_PATH_SERVICE)
    if not config.VPNC_A_CONFIG_PATH_SERVICE.exists():
        logger.critical(
            "Configuration not found at '%s'.",
            config.VPNC_A_CONFIG_PATH_SERVICE,
        )
        sys.exit(1)

    # Also repairs what earlier versions left readable for all, or owned by
    # charon's user, who could then replace what vpnc writes there as root.
    config.VPNC_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    if config.IPSEC_CONFIG_DIR.parent.is_dir():
        os.chown(config.IPSEC_CONFIG_DIR.parent, 0, 0, follow_symlinks=False)
        if config.IPSEC_CONFIG_DIR.is_symlink():
            config.IPSEC_CONFIG_DIR.unlink()
            config.IPSEC_CONFIG_DIR.mkdir()
    for directory in config.SECRET_DIRS:
        files.secure_tree(directory)
    migration.migrate_all()

    # check for required kernel modules.
    helpers.check_system_requirements()
    # Every network instance keeps sockets open; systemd's soft limit is 1024.
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))

    # Used to gracefully shutdown, allows the atexit commands to run when a
    # signal is received.
    signal.signal(signal.SIGINT, helpers.signal_handler)
    signal.signal(signal.SIGTERM, helpers.signal_handler)

    # Start the concentrator
    try:
        core.concentrator()
    except tenant.ConfigurationError:
        sys.exit(1)


if __name__ == "__main__":
    main()
