import json
import logging
from ipaddress import IPv6Network

import pydantic_core

from . import config

logger = logging.getLogger("vpncmangle")


def load_config():
    """
    Load the global configuration.
    """

    try:
        with open(config.CONFIG_PATH, "r", encoding="utf-8") as f:
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
        logger.error(
            "Configuration file could not be found at '%s'.",
            config.CONFIG_PATH,
            exc_info=True,
        )
        return

    try:
        config.CONFIG = config.Config(**{"config": new_cfg_dict}).config
    except pydantic_core.ValidationError:
        logger.error(
            "Configuration '%s' doesn't adhere to the schema",
            config.CONFIG_PATH,
            exc_info=True,
        )
        return

    config.ACL_MATCH: list[tuple[IPv6Network, str]] = []

    for net_in_name, net_in_translations in config.CONFIG.items():
        translation_list_64 = [(x[0], net_in_name) for x in net_in_translations.dns64]
        translation_list_66 = [(x[0], net_in_name) for x in net_in_translations.dns66]
        translation_list = translation_list_64 + translation_list_66

        config.ACL_MATCH.extend(translation_list)

    logger.info("Loaded new configuration.")
