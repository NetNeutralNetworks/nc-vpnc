from __future__ import annotations

import logging
import pathlib
from datetime import datetime

import yaml
from packaging.version import Version

CONFIG_PATH = pathlib.Path("/opt/ncubed/config/vpnc/")
ACTIVE_PATH = CONFIG_PATH.joinpath("active")
CANDIDATE_PATH = CONFIG_PATH.joinpath("candidate")

BACKUP_DATE = datetime.now().strftime("%s")

logger = logging.getLogger("vpnc-migrate")


def _backup():
    # Backup service configs
    service_path = ACTIVE_PATH.joinpath("service", "config.yaml")
    service_backup_path = ACTIVE_PATH.joinpath("service", f"config.yaml.{BACKUP_DATE}")

    service_backup_path.write_text(
        service_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    # Backup remote configs
    remotes = ACTIVE_PATH.joinpath("remote")
    for remote_path in remotes.glob(pattern="*.yaml"):
        remote_backup_path = ACTIVE_PATH.joinpath(
            "remote",
            f"{remote_path.name}.{BACKUP_DATE}",
        )
        remote_backup_path.write_text(
            remote_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )


def _get_version(path: pathlib.Path) -> Version | None:
    with open(path, encoding="utf-8") as fh:
        try:
            service: dict = yaml.safe_load(fh)
        except yaml.YAMLError:
            logger.error("Invalid YAML found in %s. Skipping.", path, exc_info=True)
            return None

    return Version(service.get("version", "0.0.0"))


V12_SVC_AF = ACTIVE_PATH.joinpath("service", "config.yaml")
V12_SVC_CF = CANDIDATE_PATH.joinpath("service", "config.yaml")
V12_REM_AP = ACTIVE_PATH.joinpath("remote")
V12_REM_CP = CANDIDATE_PATH.joinpath("remote")

VERSION: Version | None = _get_version(V12_SVC_AF)
_backup()

if VERSION is not None and Version("0.0.12") > VERSION:
    with open(V12_SVC_AF, "r+", encoding="utf-8") as fa, open(
        V12_SVC_CF,
        "r+",
        encoding="utf-8",
    ) as fc:
        v12_svc: dict = yaml.safe_load(fa)

        v12_svc["version"] = "0.0.12"
        v12_svc["network"] = {
            "untrust": {
                "interface": v12_svc.pop("untrusted_if_name"),
                "addresses": [v12_svc.pop("untrusted_if_ip")],
                "routes": [{"to": "default", "via": v12_svc.pop("untrusted_if_gw")}],
            },
            "root": None,
        }
        if v12_svc["mode"] == "hub":
            v12_svc["connections"] = v12_svc.pop("uplinks", {})

            for idx, connection in v12_svc["connections"].items():
                connection["type"] = "ipsec"
                connection["interface_ip"] = connection.pop(
                    "prefix_uplink_tunnel",
                    None,
                )
                connection["connection"] = {
                    "remote_peer_ip": connection.pop("remote_peer_ip"),
                    "remote_id": connection.pop("remote_id", None),
                    "ike_version": connection.pop("ike_version", 2),
                    "ike_proposal": connection.pop(
                        "ike_proposal",
                        "aes256-sha384-ecp384",
                    ),
                    "ike_lifetime": connection.pop("ike_lifetime", 86400),
                    "ipsec_proposal": connection.pop(
                        "ipsec_proposal",
                        "aes256gcm16-prfsha384-ecp384",
                    ),
                    "ipsec_lifetime": connection.pop("ipsec_lifetime", 3600),
                    "initiation": connection.pop("initiation", "start"),
                    "psk": connection.pop("psk"),
                    "routes": connection.pop("routes", []),
                    "traffic_selectors": connection.pop(
                        "traffic_selectors",
                        {"local": [], "remote": []},
                    ),
                }

        fa.seek(0)
        yaml.dump(v12_svc, fa, explicit_start=True, explicit_end=True, sort_keys=False)
        yaml.dump(v12_svc, fc, explicit_start=True, explicit_end=True, sort_keys=False)
        fa.truncate()
        fc.truncate()

    # Backup remote configs
    for v12_rem_af in V12_REM_AP.glob(pattern="*.yaml"):
        v12_rem_cf = V12_REM_AP.joinpath(v12_rem_af.name)
        with open(v12_rem_af, "r+", encoding="utf-8") as fa, open(
            v12_rem_cf,
            "r+",
            encoding="utf-8",
        ) as fc:
            v12_rem: dict = yaml.safe_load(fa)

            v12_rem["version"] = "0.0.12"
            v12_rem["connections"] = v12_rem.pop("tunnels", {})

            for idx, connection in v12_rem["connections"].items():
                connection["type"] = "ipsec"
                connection["interface_ip"] = connection.pop("tunnel_ip", None)
                connection["connection"] = {
                    "remote_peer_ip": connection.pop("remote_peer_ip"),
                    "remote_id": connection.pop("remote_id", None),
                    "ike_version": connection.pop("ike_version", 2),
                    "ike_proposal": connection.pop(
                        "ike_proposal",
                        "aes256gcm16-prfsha384-ecp384",
                    ),
                    "ike_lifetime": connection.pop("ike_lifetime", 86400),
                    "ipsec_proposal": connection.pop(
                        "ipsec_proposal",
                        "aes256gcm16-prfsha384-ecp384",
                    ),
                    "ipsec_lifetime": connection.pop("ipsec_lifetime", 3600),
                    "initiation": connection.pop("initiation", "start"),
                    "psk": connection.pop("psk"),
                    "routes": connection.pop("routes", []),
                    "traffic_selectors": connection.pop(
                        "traffic_selectors",
                        {"local": [], "remote": []},
                    ),
                }

            fa.seek(0)
            yaml.dump(
                v12_rem,
                fa,
                explicit_start=True,
                explicit_end=True,
                sort_keys=False,
            )
            yaml.dump(
                v12_rem,
                fc,
                explicit_start=True,
                explicit_end=True,
                sort_keys=False,
            )
            fa.truncate()
            fc.truncate()
