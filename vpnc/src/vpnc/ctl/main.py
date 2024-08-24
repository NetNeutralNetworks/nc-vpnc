#!/usr/bin/env python3

import logging

import typer

from . import bgp, tenants

logging.basicConfig()
logger = logging.getLogger()

app = typer.Typer(help="ncubed VPNC CLI configuration manager.", no_args_is_help=True)
app.add_typer(tenants.app, name="tenants", help="Edit tenant settings.")
app.add_typer(bgp.app, name="bgp", help="Edit BGP settings.")


if __name__ == "__main__":
    app()
