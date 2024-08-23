"""Manage the EXTERNAL namespace."""

import logging
import pathlib
import subprocess

from jinja2 import Environment, FileSystemLoader

from vpnc import models

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


def add_external_iptables(network_instance: models.NetworkInstance) -> None:
    """Add ip(6)table rules for the EXTERNAL namespace.

    The EXTERNAL network instance blocks all traffic except for IKE, ESP and IPsec.
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-external.conf.j2")
    iptables_configs = {
        "network_instance_name": network_instance.name,
    }
    iptables_render = iptables_template.render(**iptables_configs)
    logger.info(iptables_render)
    proc = subprocess.run(  # noqa: S602
        iptables_render,
        stdout=subprocess.PIPE,
        shell=True,
        check=True,
    )
    logger.debug(proc.stdout)
