#!/usr/bin/env python3


from ipaddress import IPv4Address
from typing import Optional

import typer
import yaml
from typing_extensions import Annotated

from .. import config, models

app = typer.Typer()


@app.command()
def show(active: Annotated[bool, typer.Option("--active/--candidate")] = False):
    """
    Show the service BGP configuration
    """
    if active:
        path = config.VPNC_A_SERVICE_CONFIG_PATH
    else:
        path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(config.VPNC_A_SERVICE_CONFIG_PATH, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name == "ENDPOINT":
        return "BGP is inactive. Running in 'endpoint' mode."

    with open(path, "r", encoding="utf-8") as f:
        bgp = models.BGP(**yaml.safe_load(f).get("bgp", {}))

    output = bgp.model_dump(mode="json")
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command(name="set")
def set_(
    # pylint: disable=unused-argument
    asn: Annotated[Optional[int], typer.Option()] = None,
    router_id: Annotated[
        Optional[IPv4Address], typer.Option(parser=IPv4Address)
    ] = None,
):
    """
    Set service BGP properties
    """
    all_args = {k: v for k, v in locals().items() if v is not None}

    path = config.VPNC_C_SERVICE_CONFIG_PATH

    if not path.exists():
        return

    with open(config.VPNC_A_SERVICE_CONFIG_PATH, "r", encoding="utf-8") as f:
        service = models.Service(**yaml.safe_load(f))

    if service.mode.name == "ENDPOINT":
        return "BGP is inactive. Running in 'endpoint' mode."

    updated_bgp = service.bgp.model_copy(update=all_args)
    service.bgp = updated_bgp

    # performs the class post_init construction.
    output = yaml.safe_dump(
        service.model_dump(mode="json"), explicit_start=True, explicit_end=True
    )
    with open(path, "w+", encoding="utf-8") as f:
        f.write(output)
    show(active=False)


if __name__ == "__main__":
    app()
