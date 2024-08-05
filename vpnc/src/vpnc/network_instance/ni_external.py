import logging
import pathlib
import subprocess

from jinja2 import Environment, FileSystemLoader

from .. import models

logger = logging.getLogger("vpnc")

BASE_DIR = pathlib.Path(__file__).parent
TEMPLATES_DIR = BASE_DIR.joinpath("templates")
TEMPLATES_ENV = Environment(loader=FileSystemLoader(TEMPLATES_DIR))


def add_external_iptables(network_instance: models.NetworkInstance):
    """
    The EXTERNAL network instance blocks all traffic except for IKE, ESP and IPsec.
    """
    iptables_template = TEMPLATES_ENV.get_template("iptables-external.conf.j2")
    iptables_configs = {
        "network_instance_name": network_instance.name,
    }
    iptables_render = iptables_template.render(**iptables_configs)
    logger.info(iptables_render)
    subprocess.run(
        iptables_render,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=True,
    )
