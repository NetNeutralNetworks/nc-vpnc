#!/usr/bin/env python3

import logging

import typer

from . import remote, service


logging.basicConfig()
logger = logging.getLogger()

app = typer.Typer(help="ncubed VPNC CLI configuration manager.", no_args_is_help=True)
app.add_typer(remote.app, name="remote", help="Edit remote connection settings.")
app.add_typer(service.app, name="service", help="Edit service settings.")


if __name__ == "__main__":
    app()
