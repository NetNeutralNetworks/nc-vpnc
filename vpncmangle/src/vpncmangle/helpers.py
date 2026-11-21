"""Helper functions providing functions used throughout the application."""

import hashlib
import json
import logging

import pydantic_core

from . import config, nftables, stats

logger = logging.getLogger("vpncmangle")


def _load_limits() -> config.Limits | None:
    """Return the limits as configured; the defaults without a file; None: invalid."""
    try:
        text = config.LIMITS_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return config.Limits()
    try:
        return config.Limits.model_validate_json(text)
    except pydantic_core.ValidationError:
        logger.exception(
            "The limits in '%s' aren't valid. Skipping",
            config.LIMITS_PATH,
        )
        return None


def load_config() -> None:
    """Load the global configuration."""
    try:
        text = config.CONFIG_PATH.read_bytes()
    except FileNotFoundError:
        logger.warning(
            "Configuration file could not be found at '%s'. Skipping",
            config.CONFIG_PATH,
        )
        stats.config(error="the file doesn't exist")
        return
    try:
        new_cfg_dict = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.critical(
            "Configuration is not valid '%s'.",
            config.CONFIG_PATH,
            exc_info=True,
        )
        stats.config(error="it isn't valid JSON")
        return

    try:
        new_cfg = config.Config(config=new_cfg_dict).config
    except pydantic_core.ValidationError:
        logger.exception(
            "Configuration '%s' doesn't adhere to the schema. Skipping",
            config.CONFIG_PATH,
        )
        stats.config(error="it doesn't adhere to the schema")
        return

    acl_match = [
        (translation[0], net_in_name, net_in_translations)
        for net_in_name, net_in_translations in new_cfg.items()
        for translation in net_in_translations.dns64 + net_in_translations.dns66
    ]
    # Replaced in one go: the packet thread reads it meanwhile.
    config.CONFIG = new_cfg
    config.ACL_MATCH = acl_match
    if (limits := _load_limits()) is not None:
        config.LIMITS = limits

    logger.info("Loaded new configuration.")
    digest = hashlib.sha256(text).hexdigest()
    # The rate limits are per network instance.
    try:
        nftables.apply()
    except (nftables.NftablesError, OSError):
        logger.exception("Updating the nftables table failed.")
        stats.config(loaded=digest, error="its nftables table isn't updated")
        return
    stats.config(loaded=digest)
