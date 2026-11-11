"""vpnctl reports the lab's state through vpnc's local API."""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from . import conftest

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"

HUB_CONNECTIONS = {
    "C0001-00-0": ("ipsec", "xfrm0"),
    "C0001-00-1": ("ssh", "tun1"),
    "C0001-01-0": ("wireguard", "wg-C0001-01-0"),
    "CORE-0": ("ipsec", "xfrm0"),
    "CORE-1": ("ipsec", "xfrm1"),
    "EXTERNAL-0": ("physical", "eth1"),
}
CONNECTIONS = {
    "hub00": HUB_CONNECTIONS,
    "hub01": HUB_CONNECTIONS,
    "end00": {
        "CORE-0": ("ipsec", "xfrm0"),
        "CORE-1": ("ipsec", "xfrm1"),
        "ENDPOINT-0": ("physical", "eth2"),
        "EXTERNAL-0": ("physical", "eth1"),
    },
    "end01": {
        "CORE-0": ("wireguard", "wg-CORE-0"),
        "CORE-1": ("wireguard", "wg-CORE-1"),
        "ENDPOINT-0": ("physical", "eth2"),
        "EXTERNAL-0": ("physical", "eth1"),
    },
}

TRANSLATIONS_C0001_00 = [
    {"type": "nat64", "local": "fdcc:0:c:1::/96", "remote": "0.0.0.0/0"},
    {"type": "nptv6", "local": "fd6c:1::/52", "remote": "fdff:db8:c57::/52"},
    {
        "type": "nptv6",
        "local": "fd6c:1:0:1000::/52",
        "remote": "fdff:db8:c57:1000::/52",
    },
    {
        "type": "nptv6",
        "local": "fd6c:1:0:2000::/56",
        "remote": "fdff:db8:c57:2000::/56",
    },
    {
        "type": "nptv6",
        "local": "fd6c:1:0:3000::/52",
        "remote": "fdff:db8:c57:3000::/52",
    },
]


def vpnctl(host: str, args: str) -> Any:  # noqa: ANN401
    """Run vpnctl with JSON output and return the decoded output."""
    return json.loads(conftest.run_cmd(host, f"{VPNCTL} -o json {args}"))


class TestVpnctl:
    """vpnctl shows the state of the lab."""

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_status(self, host: str) -> None:
        """The overview has the mode, and all connections are up."""
        status = vpnctl(host, "status")

        assert status["mode"] == ("hub" if host.startswith("hub") else "endpoint")
        assert (
            status["connections_up"]
            == status["connections"]
            == len(
                CONNECTIONS[host],
            )
        )

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_connections(self, host: str) -> None:
        """Every connection is listed with its type and interface, and is up."""
        connections = {
            c["id"]: (c["type"], c["interface"], c["state"])
            for c in vpnctl(host, "connections list")
        }

        assert connections == {
            cid: (ctype, ifname, "up")
            for cid, (ctype, ifname) in CONNECTIONS[host].items()
        }

    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_connection_filter(self, host: str) -> None:
        """Connections can be listed per network instance."""
        connections = vpnctl(host, "connections list C0001-00")

        assert sorted(c["id"] for c in connections) == ["C0001-00-0", "C0001-00-1"]

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_connection_type_filter(self, host: str) -> None:
        """Connections can be listed per type."""
        connections = vpnctl(host, "connections list --type ipsec")

        assert sorted(c["id"] for c in connections) == sorted(
            cid for cid, (ctype, _) in CONNECTIONS[host].items() if ctype == "ipsec"
        )

    @pytest.mark.parametrize("host", ["hub00", "end00"])
    def test_ipsec_logs(self, host: str) -> None:
        """An IPsec connection's log has charon's lines for its IKE SA."""
        lines = vpnctl(host, "connections logs CORE-0 -n 500")

        assert any(line["source"] == "charon" for line in lines)

    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ipsec_connection(self, host: str) -> None:
        """An IPsec connection shows its IKE and child SA."""
        connection = vpnctl(host, "connections show C0001-00-0")

        assert connection["details"]["ike_state"] == "ESTABLISHED"
        assert connection["details"]["child_sas"] == [
            {"name": "C0001-00-0", "state": "INSTALLED"},
        ]

    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_translations(self, host: str) -> None:
        """A network instance shows its NAT64 and NPTv6 translations as applied."""
        network_instance = vpnctl(host, "ni show C0001-00")

        assert network_instance["translations"] == TRANSLATIONS_C0001_00

    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_bgp_neighbors(self, host: str) -> None:
        """Both management routers are BGP neighbors, established."""
        neighbors = vpnctl(host, "bgp neighbors")

        assert {(n["hostname"], n["state"]) for n in neighbors} == {
            ("mgt00", "Established"),
            ("mgt01", "Established"),
        }

    @pytest.mark.parametrize("host", ["end00", "end01"])
    def test_bgp_on_endpoint(self, host: str) -> None:
        """BGP isn't available in endpoint mode."""
        with pytest.raises(subprocess.CalledProcessError) as err:
            conftest.run_cmd(host, f"{VPNCTL} bgp neighbors")

        assert "hub mode" in err.value.stderr

    def test_unknown_connection(self) -> None:
        """An unknown connection is an error."""
        with pytest.raises(subprocess.CalledProcessError) as err:
            conftest.run_cmd("hub00", f"{VPNCTL} connections show C0009-00-0")

        assert "No connection 'C0009-00-0'" in err.value.stderr

    def test_table(self) -> None:
        """The default output is a table with a header and a row per connection."""
        lines = conftest.run_cmd("hub00", f"{VPNCTL} connections list").splitlines()

        assert lines[0].split() == [
            "CONNECTION",
            "TYPE",
            "STATE",
            "REMOTE",
            "INTERFACE",
        ]
        assert sorted(line.split()[0] for line in lines[1:]) == sorted(HUB_CONNECTIONS)


def neighbor_address(host: str, hostname: str) -> str:
    """Return the address of a BGP neighbor."""
    neighbors = vpnctl(host, "bgp neighbors")
    return next(n["neighbor"] for n in neighbors if n["hostname"] == hostname)


@pytest.mark.parametrize("host", ["hub00", "hub01"])
class TestVpnctlBgp:
    """vpnctl shows BGP sessions and routes in detail."""

    def test_neighbor(self, host: str) -> None:
        """A neighbor shows its state, BFD and the prefixes it accepted."""
        neighbor = vpnctl(host, f"bgp neighbor {neighbor_address(host, 'mgt00')}")

        assert neighbor["state"] == "Established"
        # Only hub00 has BFD.
        assert neighbor["bfd"] == ("Up" if host == "hub00" else None)
        families = {f["family"]: f for f in neighbor["address_families"]}
        assert families["ipv6Unicast"]["accepted"] >= 1

    def test_routes(self, host: str) -> None:
        """The BGP table has the management prefix, learned from both routers."""
        paths = [r for r in vpnctl(host, "bgp routes") if r["prefix"] == "fd00::/16"]

        assert {r["learned_from"] for r in paths} == {"mgt00", "mgt01"}
        assert sum(r["best"] for r in paths) == 1

    def test_received_and_advertised(self, host: str) -> None:
        """Routes are received from and advertised to a neighbor."""
        address = neighbor_address(host, "mgt00")
        received = vpnctl(host, f"bgp routes --received-from {address}")
        advertised = vpnctl(host, f"bgp routes --advertised-to {address}")

        assert "fd00::/16" in {r["prefix"] for r in received}
        # C0001-00's NPTv6 prefixes.
        assert {t["local"] for t in TRANSLATIONS_C0001_00 if t["type"] == "nptv6"} <= {
            r["prefix"] for r in advertised
        }


class TestVpnctlTroubleshooting:
    """vpnctl troubleshoots inside network instances."""

    def test_routes(self) -> None:
        """A network instance's routes show where they come from."""
        core = {r["destination"]: r for r in vpnctl("hub00", "routes CORE -6")}
        downlink = {r["destination"]: r for r in vpnctl("hub00", "routes C0001-00 -4")}

        assert core["fd00::/16"]["protocol"] == "bgp"
        assert downlink["172.16.30.1"]["interfaces"] == ["xfrm0"]

    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_ping(self, host: str) -> None:
        """A BGP neighbor answers pings from CORE."""
        address = neighbor_address(host, "mgt00")
        result = vpnctl(host, f"ping CORE {address} -c 3 -s 100")

        assert result["transmitted"] == 3  # noqa: PLR2004
        assert result["received"] == 3  # noqa: PLR2004
        assert result["rtt_avg_ms"] is not None

    def test_ping_unreachable(self) -> None:
        """No replies is an error."""
        with pytest.raises(subprocess.CalledProcessError):
            conftest.run_cmd("hub00", f"{VPNCTL} ping C0001-00 192.0.2.250 -c 1")

    def test_traceroute(self) -> None:
        """A directly connected neighbor is the first hop."""
        address = neighbor_address("hub00", "mgt00")
        result = vpnctl("hub00", f"traceroute CORE {address}")

        assert result["hops"][0]["address"] == address

    def test_tcp(self) -> None:
        """A TCP connection through the SSH tunnel succeeds; a closed port fails."""
        result = vpnctl("hub00", "tcp C0001-00 172.16.31.1 22")
        assert result["connected"] is True

        with pytest.raises(subprocess.CalledProcessError) as err:
            conftest.run_cmd("hub00", f"{VPNCTL} tcp C0001-00 172.16.31.1 9")
        assert "Couldn't connect to 172.16.31.1 port 9" in err.value.stdout

    @pytest.mark.parametrize("host", ["hub00", "end00"])
    def test_version(self, host: str) -> None:
        """The versions of vpnc, strongSwan and (in hub mode) FRR."""
        version = vpnctl(host, "version")

        assert version["vpnc"] == version["vpnctl"]
        assert version["strongswan"]
        assert (version["frr"] is not None) == host.startswith("hub")

    def test_service_without_systemd(self) -> None:
        """The lab doesn't run systemd, so vpnc can't be restarted through it."""
        with pytest.raises(subprocess.CalledProcessError) as err:
            conftest.run_cmd("hub00", f"{VPNCTL} service restart")

        assert "doesn't run under systemd" in err.value.stderr
