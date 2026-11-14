"""IPsec connections are established with the configured key exchanges."""

from __future__ import annotations

import pytest

from . import conftest

# Per node the key exchanges of each connection's IKE SA; /PPK if it uses a PPK.
# end01 uses WireGuard only.
TESTDATA_IKE = {
    "hub00": {
        "CORE-0": "ECP_384/KE1_ML_KEM_1024/PPK",
        "CORE-1": "ECP_384",
        "C0001-00-0": "ECP_384/KE1_ML_KEM_768/PPK",
    },
    "hub01": {
        "CORE-0": "ECP_384/KE1_ML_KEM_1024",
        "CORE-1": "ECP_384",
        "C0001-00-0": "ECP_384",
    },
    "end00": {
        "CORE-0": "ECP_384/KE1_ML_KEM_768/PPK",
        "CORE-1": "ECP_384",
    },
    "end01": {},
}


class TestConnections:
    """IPsec connections: hybrid ML-KEM where configured, classical elsewhere."""

    @pytest.mark.parametrize("host", list(TESTDATA_IKE))
    def test_connections_established(self, host: str) -> None:
        """Exactly these are established, with their key exchanges."""
        expected = TESTDATA_IKE[host]
        sas = conftest.key_exchanges(host)

        assert {name: sa["ike"] for name, sa in sas.items()} == {
            name: {key_exchange} for name, key_exchange in expected.items()
        }
        # Rekeyed child SAs add the same key exchanges (PFS); new ones have none.
        for name, key_exchange in expected.items():
            assert sas[name]["child"] <= {"", key_exchange.removesuffix("/PPK")}


class TestCharon:
    """Charon runs with vpnc's settings."""

    @pytest.mark.parametrize("host", ["hub00", "hub01", "end00", "end01"])
    def test_runs_as_swan(self, host: str) -> None:
        """Charon has dropped root for the swan user."""
        assert conftest.run_cmd(host, "ps -C charon -o user=").split() == ["swan"]
