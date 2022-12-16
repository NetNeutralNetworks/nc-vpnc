#!/usr/bin/env python3

import logging
import subprocess

import vici


def load_swanctl_all_config():
    """Load all swanctl strongswan configurations. Cannot find a way to do this with vici"""
    subprocess.run(
        "swanctl --load-all --clear",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        check=False,
    )


def terminate_swanctl_connection(connection: str):
    """Terminate an IKE/IPsec connection"""
    logging.debug("Terminating connection '%s'.", connection)
    vcs = vici.Session()
    output = vcs.terminate({"ike": connection, "child": connection})
    logging.debug(output)
