"""Miscellaneous functions used throughout the service."""

from __future__ import annotations

import logging
import subprocess
import sys
from typing import TYPE_CHECKING, Any

import pydantic_core
import yaml

from vpnc import config
from vpnc.models import models

if TYPE_CHECKING:
    import pathlib


logger = logging.getLogger("vpnc")


def kill_handler(*_: object) -> None:
    """Shut down the program gracefully."""
    sys.exit(0)


def check_system_requirements() -> None:
    """Check if required kernel modules are installed."""
    module_list: list[str] = ["xfrm_interface", "xt_MASQUERADE", "xt_nat", "veth"]
    module: str = ""
    try:
        for module in module_list:
            subprocess.run(  # noqa: S603
                ["/usr/sbin/modinfo", module],
                check=True,
            )
    except subprocess.CalledProcessError:
        logger.critical("The '%s' kernel module isn't installed. Exiting.", module)
        sys.exit(1)

    if config.VPNC_CONFIG_SERVICE.mode.value != "hub":
        return

    hub_module_list: list[str] = []
    try:
        for module in hub_module_list:
            subprocess.run(  # noqa: S603
                ["/usr/sbin/modinfo", module],
                check=True,
            )
    except subprocess.CalledProcessError:
        logger.critical("The '%s' kernel module isn't installed. Exiting.", module)
        sys.exit(1)


def load_service_config(
    config_path: pathlib.Path,
) -> tuple[
    models.ServiceHub | models.ServiceEndpoint,
    models.ServiceEndpoint | models.ServiceHub | None,
]:
    """Load the global configuration."""
    try:
        with config_path.open(encoding="utf-8") as f:
            try:
                new_cfg_dict = yaml.safe_load(f)
            except (yaml.YAMLError, TypeError):
                logger.critical(
                    "Configuration is not valid '%s'.",
                    config_path,
                    exc_info=True,
                )
                sys.exit(1)
    except FileNotFoundError:
        logger.critical(
            "Configuration file could not be found at '%s'.",
            config_path,
            exc_info=True,
        )
        sys.exit(1)

    try:
        if hasattr(config, "VPNC_CONFIG_SERVICE"):
            active_tenant = config.VPNC_CONFIG_SERVICE.model_copy(deep=True)
            config.VPNC_CONFIG_SERVICE = models.Service(config=new_cfg_dict).config
        else:
            config.VPNC_CONFIG_SERVICE = models.Service(config=new_cfg_dict).config
            active_tenant = None
    except pydantic_core.ValidationError:
        logger.critical(
            "Configuration '%s' doesn't adhere to the schema",
            config_path,
            exc_info=True,
        )
        sys.exit(1)

    logger.info("Loaded new configuration.")

    return config.VPNC_CONFIG_SERVICE, active_tenant


def parse_downlink_network_instance_name(
    name: str,
) -> dict[str, Any]:
    """Parse a connection name into it's components."""
    if config.DOWNLINK_CON_RE.match(name):
        return {
            "tenant": name[:5],
            "tenant_ext": int(name[0], 16),
            "tenant_ext_str": name[0],
            "tenant_id": int(name[1:5], 16),
            "tenant_id_str": name[1:5],
            "network_instance": name[:8],
            "network_instance_id": int(name[6:8], 16),
            "connection": name,
            "connection_id": int(name[-1], 16),
        }

    if config.DOWNLINK_NI_RE.match(name):
        return {
            "tenant": name[:5],
            "tenant_ext": int(name[0], 16),
            "tenant_ext_str": name[0],
            "tenant_id": int(name[1:5], 16),
            "tenant_id_str": name[1:5],
            "network_instance": name[:8],
            "network_instance_id": int(name[6:8], 16),
            "connection": None,
            "connection_id": None,
        }
    if config.DOWNLINK_TEN_RE.match(name):
        return {
            "tenant": name[:5],
            "tenant_ext": int(name[0], 16),
            "tenant_ext_str": name[0],
            "tenant_id": int(name[1:5], 16),
            "tenant_id_str": name[1:5],
            "network_instance": None,
            "network_instance_id": None,
            "connection": None,
            "connection_id": None,
        }

    msg = f"Invalid network instance/connection name '{name}'"
    raise ValueError(msg)


def load_tenant_config(
    path: pathlib.Path,
) -> tuple[models.Tenant | None, models.Tenant | None]:
    """Load tenant configuration."""
    if not config.DOWNLINK_TEN_RE.match(path.stem):
        logger.exception("Invalid filename found in %s. Skipping.", path)
        return None, None

    # Open the configuration file and check if it's valid YAML.
    try:
        with path.open(encoding="utf-8") as f:
            try:
                config_yaml = yaml.safe_load(f)
            except yaml.YAMLError:
                logger.exception("Invalid YAML found in %s. Skipping.", path)
                return None
    except FileNotFoundError:
        logger.exception(
            "Configuration file could not be found at '%s'. Skipping",
            path,
        )
        return None, None

    # Parse the YAML file to a DOWNLINK object and validate the input.
    try:
        tenant = models.Tenant(**config_yaml)
    except (TypeError, ValueError):
        logger.exception(
            "Invalid configuration found in '%s'. Skipping.",
            path,
        )
        return None, None

    if tenant.id != path.stem:
        logger.error(
            (
                "VPN identifier '%s' and configuration file name"
                " '%s' do not match. Skipping."
            ),
            tenant.id,
            path.stem,
        )
        return None, None

    active_tenant = config.VPNC_CONFIG_TENANT.get(tenant.id)
    config.VPNC_CONFIG_TENANT[tenant.id] = tenant

    return tenant, active_tenant
