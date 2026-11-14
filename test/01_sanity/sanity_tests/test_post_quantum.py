"""Post-quantum and classical tunnels use the configured key exchanges."""

from __future__ import annotations

import pytest

from . import conftest

# The key exchanges of the IKE SA per connection; /PPK if it uses a PPK.
TESTDATA_IKE = [
    ("hub00", "CORE-0", "ECP_384/KE1_ML_KEM_1024/PPK"),
    ("hub00", "CORE-1", "ECP_384"),
    ("hub00", "C0001-00-0", "ECP_384/KE1_ML_KEM_768/PPK"),
    ("hub01", "CORE-0", "ECP_384/KE1_ML_KEM_1024"),
    ("hub01", "CORE-1", "ECP_384"),
    ("hub01", "C0001-00-0", "ECP_384"),
    ("end00", "CORE-0", "ECP_384/KE1_ML_KEM_768/PPK"),
    ("end00", "CORE-1", "ECP_384"),
]


class TestPostQuantum:
    """Hybrid ML-KEM where configured, classical elsewhere."""

    @pytest.mark.parametrize(("host", "connection", "expected"), TESTDATA_IKE)
    def test_ike_key_exchange(self, host: str, connection: str, expected: str) -> None:
        """The IKE SA uses the configured key exchanges and PPK."""
        sas = conftest.key_exchanges(host)[connection]
        assert sas["ike"] == {expected}
        # Rekeyed child SAs add the same key exchanges (PFS); new ones have none.
        assert sas["child"] <= {"", expected.removesuffix("/PPK")}

    # hub00's SSH tunnel is post-quantum, hub01's classical.
    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ssh_tunnel(self, host: str) -> None:
        """The SSH tunnel passes traffic."""
        assert conftest.ssh_tunnel_works(host)
