#!/usr/bin/env python3
"""Starts the service and runs it in either endpoint or hub mode."""

import logging
import os
import resource
import signal
import subprocess
import sys
from logging.handlers import SysLogHandler

from vpnc import accounts, config, core, files, migration, shared
from vpnc.models import enums, tenant

# LOGGER
# Get logger
logger = logging.getLogger()


def _signal_handler(*_: object) -> None:
    """Shut down the program gracefully."""
    logger.info("SIGTERM received. Stopping all threads.")
    shared.STOP_EVENT.set()


def _journal_handler() -> logging.Handler:
    """Return a handler to the journal (syslog), or stderr where it isn't running."""
    try:
        handler = SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_DAEMON)
    except OSError:
        return logging.StreamHandler()
    # The journal's SYSLOG_IDENTIFIER, which vpnctl reads.
    handler.ident = "vpnc: "
    handler.append_nul = False
    return handler


def _check_modules(modules: list[str]) -> None:
    """Exit unless the kernel modules are installed."""
    for module in modules:
        logger.debug("Verifying kernel module %s is installed", module)
        try:
            subprocess.run(  # noqa: S603
                ["/usr/sbin/modinfo", module],
                check=True,
                stdout=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            logger.critical("The '%s' kernel module isn't installed. Exiting.", module)
            sys.exit(1)


def _check_accounts(names: list[str]) -> None:
    """Exit unless the accounts exist."""
    for name in names:
        if not accounts.exists(name):
            logger.critical(
                "The '%s' account is missing; 'make update' adds it. Exiting.",
                name,
            )
            sys.exit(1)


def _check_system_requirements() -> None:
    """Check if the required kernel modules and accounts are there."""
    _check_modules(
        [
            "xfrm_interface",
            # nftables NAT and masquerading.
            "nft_chain_nat",
            "nft_masq",
            "veth",
            "wireguard",
        ],
    )

    tenant_config, _ = tenant.load_tenant_config(config.VPNC_A_CONFIG_PATH_SERVICE)
    if not isinstance(tenant_config, (tenant.ServiceHub, tenant.ServiceEndpoint)):
        logger.critical("Service configuration is invalid")
        sys.exit(1)

    if tenant_config.mode == enums.ServiceMode.HUB:
        # vpncmangle queues DNS responses with nftables.
        _check_modules(["nft_queue"])
        _check_accounts([accounts.VPNCMANGLE])


def main() -> None:
    """Run the VPNC service."""
    logger.setLevel(level=logging.INFO)
    logger.addHandler(_journal_handler())

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
    _check_system_requirements()
    # Every network instance keeps sockets open; systemd's soft limit is 1024.
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))

    # Used to gracefully shutdown, allows the atexit commands to run when a
    # signal is received.
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Start the concentrator
    try:
        core.concentrator()
    except tenant.ConfigurationError:
        sys.exit(1)


if __name__ == "__main__":
    main()
