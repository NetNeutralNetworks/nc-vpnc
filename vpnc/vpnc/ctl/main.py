#!/usr/bin/env python3

import logging

import typer

from . import remote, service


logging.basicConfig()
logger = logging.getLogger()

app = typer.Typer()
app.add_typer(remote.app, name="remote")
app.add_typer(service.app, name="service")


if __name__ == "__main__":
    app()
