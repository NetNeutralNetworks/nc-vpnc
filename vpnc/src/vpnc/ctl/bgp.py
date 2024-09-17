"""Manage service configuration."""

from __future__ import annotations

import json
import subprocess
from typing import Any

import tabulate
import typer
import yaml
from rich import print
from typing_extensions import Annotated

from vpnc import config
from vpnc.ctl import helpers
from vpnc.models import enums

app = typer.Typer()


@app.command()
def show(
    ctx: typer.Context,
    active: Annotated[bool, typer.Option("--active/--candidate")] = False,  # noqa: FBT002
) -> None:
    """Show the service BGP configuration."""
    path = helpers.get_config_path(ctx, active=active).joinpath(
        f"{config.DEFAULT_TENANT}.yaml",
    )

    service = helpers.get_service_config(ctx, path)

    if service.mode is not enums.ServiceMode.HUB:
        print("BGP is inactive. Running in 'endpoint' mode.")
        return

    with path.open(encoding="utf-8") as f:
        bgp = service.bgp

    output = bgp.model_dump(mode="json")
    print(yaml.safe_dump(output, explicit_start=True, explicit_end=True))


@app.command()
def summary(
    ctx: typer.Context,
) -> None:
    """Show a network-instance's connectivity status."""
    path = helpers.get_config_path(ctx, active=True).joinpath(
        f"{config.DEFAULT_TENANT}.yaml",
    )

    service = helpers.get_service_config(ctx, path)

    if service.mode is not enums.ServiceMode.HUB:
        print("BGP is inactive. Running in 'endpoint' mode.")
        return

    output: list[dict[str, Any]] = []

    bgp: dict[str, Any] = json.loads(
        subprocess.run(  # noqa: S603
            [
                "/usr/bin/vtysh",
                "-c",
                f"show bgp vrf {config.CORE_NI} summary json",
            ],
            stdout=subprocess.PIPE,
            check=True,
        ).stdout,
    )

    for family, bgp_status in bgp.items():
        for peer, peer_status in bgp_status["peers"].items():
            output.append(
                {
                    "neighbor": peer,
                    "hostname": peer_status.get("hostname"),
                    "remote-as": peer_status.get("remoteAs"),
                    "address-family": family,
                    "state": peer_status.get("state"),
                    "uptime": peer_status.get("peerUptime"),
                    "peer-state": peer_status.get("peerState"),
                    "pfx-rcvd": peer_status.get("pfxRcd"),
                    "pfx-sent": peer_status.get("pfxSnt"),
                    "msg-rcvd": peer_status.get("msgRcvd"),
                    "msg-sent": peer_status.get("msgSent"),
                    "con-estb": peer_status.get("connectionsEstablished"),
                    "con-drop": peer_status.get("connectionsDropped"),
                },
            )

    print(tabulate.tabulate(output, headers="keys"))


# @app.command(name="set")
# def set_(
#     # pylint: disable=unused-argument
#     asn: Annotated[Optional[int], typer.Option()] = None,
#     router_id: Annotated[
#         Optional[IPv4Address],
#         typer.Option(parser=IPv4Address),
#     ] = None,
# ) -> None:
#     """Set service BGP properties."""
#     all_args = {k: v for k, v in locals().items() if v is not None}

#     path = config.VPNC_C_SERVICE_CONFIG_PATH

#     if not path.exists():
#         return

#     with config.VPNC_A_SERVICE_CONFIG_PATH.open(encoding="utf-8") as f:
#         service = models.ServiceHub(**yaml.safe_load(f))

#     if service.mode is not models.ServiceMode.HUB:
#         print("BGP is inactive. Running in 'endpoint' mode.")
#         return

#     updated_bgp = service.bgp.model_copy(update=all_args)
#     service.bgp = updated_bgp

#     # performs the class post_init construction.
#     output = yaml.safe_dump(
#         service.model_dump(mode="json"),
#         explicit_start=True,
#         explicit_end=True,
#     )
#     with path.open("w+", encoding="utf-8") as f:
#         f.write(output)
#     show(active=False)


if __name__ == "__main__":
    app()
