"""Helper functions providing functions used throughout the application."""

import json
import logging

import pydantic_core

from . import config

logger = logging.getLogger("vpncmangle")


def load_config() -> None:
    """Load the global configuration."""
    try:
        with config.CONFIG_PATH.open(encoding="utf-8") as f:
            try:
                new_cfg_dict = json.load(f)
            except (json.JSONDecodeError, TypeError):
                logger.critical(
                    "Configuration is not valid '%s'.",
                    config.CONFIG_PATH,
                    exc_info=True,
                )
                return
    except FileNotFoundError:
        logger.warning(
            "Configuration file could not be found at '%s'. Skipping",
            config.CONFIG_PATH,
        )
        return

    try:
        config.CONFIG = config.Config(config=new_cfg_dict).config
    except pydantic_core.ValidationError:
        logger.exception(
            "Configuration '%s' doesn't adhere to the schema. Skipping",
            config.CONFIG_PATH,
        )
        return

    config.ACL_MATCH.clear()

    for net_in_name, net_in_translations in config.CONFIG.items():
        translation_list_64 = [(x[0], net_in_name) for x in net_in_translations.dns64]
        translation_list_66 = [(x[0], net_in_name) for x in net_in_translations.dns66]
        translation_list = translation_list_64 + translation_list_66

        config.ACL_MATCH.extend(translation_list)

    logger.info("Loaded new configuration.")
