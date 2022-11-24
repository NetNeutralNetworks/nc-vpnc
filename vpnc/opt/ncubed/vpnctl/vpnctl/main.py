#!/usr/bin/env python3

import logging

import typer

from . import vpncremote, vpncservice


logging.basicConfig()
logger = logging.getLogger()

app = typer.Typer()
app.add_typer(vpncremote.app, name="remote")
app.add_typer(vpncservice.app, name="service")


if __name__ == "__main__":
    app()
