"""Post-quantum settings are enforced (end results on hub00, hub01 and end00)."""

from __future__ import annotations

import subprocess
import time

import pytest
import yaml

from . import conftest

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"
# end00's CORE-0 to hub00: ML-KEM-768 with a PPK; CORE-1 to hub01: classical.
END = "end00"
PPK_PATH = "network_instances.CORE.connections.0.config.post_quantum.ppk.key"
# hub00's PPK id of its connection to end00.
HUB_PPK_ID = "C0001-00-0-hub00"
CANDIDATE_DIR = "/opt/ncubed/config/vpnc/candidate"
# Makes the SSH server classical only; first in sshd_config.d, so it wins.
SSH_KEX_FILE = "/etc/ssh/sshd_config.d/00-classical-kex.conf"

REKEY_TIMEOUT = 30
# Applied, then initiated again.
APPLY_TIMEOUT = 120
# IKE retransmits before an initiator gives up on a try.
DOWN_TIME = 20
# Reconnect delay is capped at 30s, plus connect time.
SSH_TIMEOUT = 60


def vpnctl(host: str, args: str) -> str:
    """Run vpnctl (no spaces in arguments)."""
    return conftest.run_cmd(host, f"{VPNCTL} {args}")


def ike_key_exchanges(host: str, connection: str) -> set[str]:
    """Return the key exchanges of a connection's established IKE SAs."""
    return conftest.key_exchanges(host).get(connection, {}).get("ike", set())


def reload_sshd() -> None:
    """Make the SSH server read its configuration and close its sessions."""
    conftest.run_cmd_shell(conftest.SSH_SERVER, "pkill -HUP -f 'sshd.*listener'")
    conftest.close_ssh_sessions()


class TestPostQuantum:
    """ML-KEM and PPKs are used and required where configured."""

    def test_rekeyed_child_sas(self) -> None:
        """Rekeyed child SAs add ML-KEM where configured, only ECP elsewhere."""
        for connection in ("CORE-0", "CORE-1"):
            conftest.run_cmd(END, f"swanctl --rekey --child {connection}")
        conftest.wait_until(
            lambda: (
                (sas := conftest.key_exchanges(END))
                and "ECP_384/KE1_ML_KEM_768" in sas["CORE-0"]["child"]
                and "ECP_384" in sas["CORE-1"]["child"]
            ),
            timeout=REKEY_TIMEOUT,
            message="the rekeyed child SAs",
        )
        assert conftest.key_exchanges(END)["CORE-1"]["child"] <= {"", "ECP_384"}

    def test_ppk_mismatch(self) -> None:
        """With another PPK the tunnel doesn't come up; with the right one it does."""
        # Quoted: vpnctl reads values as YAML, which reads 0x... as a number.
        vpnctl(END, f"config set DEFAULT {PPK_PATH} \"0x{'ab' * 32}\"")
        vpnctl(END, "config commit DEFAULT")
        try:
            conftest.run_cmd(END, "swanctl --terminate --ike CORE-0")
            deadline = time.monotonic() + DOWN_TIME
            while time.monotonic() < deadline:
                assert not ike_key_exchanges(END, "CORE-0"), "Up with the wrong PPK"
                time.sleep(2)
        finally:
            vpnctl(END, "config restore DEFAULT 1")
            vpnctl(END, "config commit DEFAULT")
        conftest.wait_until(
            lambda: ike_key_exchanges(END, "CORE-0") == {"ECP_384/KE1_ML_KEM_768/PPK"},
            timeout=APPLY_TIMEOUT,
            message="CORE-0 to be up with the right PPK",
        )

    def test_duplicate_ppk_id_refused(self) -> None:
        """A PPK id used by another tenant's connection isn't committed."""
        tenant = {
            "version": "0.1.4",
            "id": "C0004",
            "name": "Duplicate PPK id",
            "network_instances": {
                "00": {
                    "type": "downlink",
                    "connections": {
                        0: {
                            "config": {
                                "type": "ipsec",
                                "remote_addrs": ["192.0.2.99"],
                                "psk": "duplicateppkid",
                                "post_quantum": {
                                    "enabled": True,
                                    "ppk": {"id": HUB_PPK_ID, "key": "x" * 32},
                                },
                            },
                        },
                    },
                },
            },
        }
        conftest.write_file(
            "hub00",
            f"{CANDIDATE_DIR}/C0004.yaml",
            yaml.safe_dump(tenant),
        )
        try:
            with pytest.raises(subprocess.CalledProcessError) as err:
                vpnctl("hub00", "config commit C0004")
            assert f"PPK id {HUB_PPK_ID} is used by" in err.value.stderr
        finally:
            conftest.run_cmd("hub00", f"rm -f {CANDIDATE_DIR}/C0004.yaml")

    @pytest.mark.parametrize(
        ("value", "error"),
        [
            # ML-KEM without hybrid, and an optional additional key exchange.
            ("aes256gcm16-prfsha384-mlkem768", "set ML-KEM with post_quantum"),
            ("aes256gcm16-prfsha384-ecp384-ke1_none", "set ML-KEM with post_quantum"),
        ],
    )
    def test_proposal_refused(self, value: str, error: str) -> None:
        """ML-KEM in a proposal is refused: it's set with post_quantum."""
        path = "network_instances.00.connections.0.config.ike_proposal"
        with pytest.raises(subprocess.CalledProcessError) as err:
            vpnctl("hub00", f"config set C0001 {path} {value}")
        assert error in err.value.stderr

    def test_short_ppk_refused(self) -> None:
        """A PPK shorter than 32 bytes is refused."""
        path = "network_instances.00.connections.0.config.post_quantum.ppk.key"
        with pytest.raises(subprocess.CalledProcessError) as err:
            vpnctl("hub00", f"config set C0001 {path} \"0x{'ab' * 31}\"")
        assert "at least 32 bytes" in err.value.stderr

    def test_ssh_requires_ml_kem(self) -> None:
        """A classical SSH server only gets hub01's classical tunnel."""
        conftest.write_file(
            conftest.SSH_SERVER,
            SSH_KEX_FILE,
            "KexAlgorithms curve25519-sha256\n",
        )
        try:
            reload_sshd()
            conftest.wait_until(
                lambda: conftest.ssh_tunnel_works("hub01"),
                timeout=SSH_TIMEOUT,
                message="hub01's classical SSH tunnel to reconnect",
            )
            time.sleep(DOWN_TIME)
            assert not conftest.ssh_tunnel_works("hub00")
        finally:
            conftest.run_cmd(conftest.SSH_SERVER, f"rm -f {SSH_KEX_FILE}")
            reload_sshd()
        conftest.wait_until(
            lambda: conftest.ssh_tunnel_works("hub00"),
            timeout=SSH_TIMEOUT,
            message="hub00's post-quantum SSH tunnel to reconnect",
        )
