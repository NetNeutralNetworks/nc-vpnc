"""vpnctl reports the lab's state through vpnc's local API."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any

import pytest

from . import conftest

VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"

HUB_CONNECTIONS = {
    "C0001-00-0": ("IPSEC", "xfrm0"),
    "C0001-00-1": ("SSH", "tun1"),
    "C0001-01-0": ("WIREGUARD", "wg-C0001-01-0"),
    "CORE-0": ("IPSEC", "xfrm0"),
    "CORE-1": ("IPSEC", "xfrm1"),
    "EXTERNAL-0": ("PHYSICAL", "eth1"),
}
CONNECTIONS = {
    "hub00": HUB_CONNECTIONS,
    "hub01": HUB_CONNECTIONS,
    "end00": {
        "CORE-0": ("IPSEC", "xfrm0"),
        "CORE-1": ("IPSEC", "xfrm1"),
        "ENDPOINT-0": ("PHYSICAL", "eth2"),
        "EXTERNAL-0": ("PHYSICAL", "eth1"),
    },
    "end01": {
        "CORE-0": ("WIREGUARD", "wg-CORE-0"),
        "CORE-1": ("WIREGUARD", "wg-CORE-1"),
        "ENDPOINT-0": ("PHYSICAL", "eth2"),
        "EXTERNAL-0": ("PHYSICAL", "eth1"),
    },
}

TRANSLATIONS_C0001_00 = [
    {"type": "NAT64", "local": "fdcc:0:c:1::/96", "remote": "0.0.0.0/0"},
    {"type": "NPTV6", "local": "fd6c:1::/52", "remote": "fdff:db8:c57::/52"},
    {
        "type": "NPTV6",
        "local": "fd6c:1:0:1000::/52",
        "remote": "fdff:db8:c57:1000::/52",
    },
    {
        "type": "NPTV6",
        "local": "fd6c:1:0:2000::/56",
        "remote": "fdff:db8:c57:2000::/56",
    },
    {
        "type": "NPTV6",
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

        hub = host.startswith("hub")
        assert status["mode"] == ("HUB" if hub else "ENDPOINT")
        assert status["restart_needed"] == []
        if hub:
            assert status["vpncmangle"]["running"] is True
            # C0001-00's NAT64 and NPTv6 translations at least.
            assert status["vpncmangle"]["translations"] >= len(TRANSLATIONS_C0001_00)
        else:
            assert status["vpncmangle"] is None
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
            c["id"]: (c["type"], c["interface"], c["admin_status"], c["oper_status"])
            for c in vpnctl(host, "connections list")
        }

        assert connections == {
            cid: (ctype, ifname, "UP", "UP")
            for cid, (ctype, ifname) in CONNECTIONS[host].items()
        }

    @pytest.mark.parametrize("host", ["hub00", "hub01"])
    def test_connection_filter(self, host: str) -> None:
        """Connections can be listed per network instance."""
        connections = vpnctl(host, "connections list C0001-00")

        assert sorted(c["id"] for c in connections) == ["C0001-00-0", "C0001-00-1"]

    @pytest.mark.parametrize("host", list(CONNECTIONS))
    def test_connection_type_filter(self, host: str) -> None:
        """Connections can be listed per type; lower case is accepted."""
        connections = vpnctl(host, "connections list --type ipsec")

        assert sorted(c["id"] for c in connections) == sorted(
            cid for cid, (ctype, _) in CONNECTIONS[host].items() if ctype == "IPSEC"
        )
        assert vpnctl(host, "connections list --oper-status DOWN") == []

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
        # During a rekey (every 90 seconds here) the old child SA is listed too.
        assert {"name": "C0001-00-0", "state": "INSTALLED"} in connection["details"][
            "child_sas"
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

        assert {(n["hostname"], n["session_state"]) for n in neighbors} == {
            ("mgt00", "ESTABLISHED"),
            ("mgt01", "ESTABLISHED"),
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

        assert re.split(r"\s{2,}", lines[0]) == [
            "CONNECTION",
            "TYPE",
            "ADMIN",
            "OPER",
            "LAST CHANGE",
            "REMOTE",
            "INTERFACE",
        ]
        assert sorted(line.split()[0] for line in lines[1:]) == sorted(HUB_CONNECTIONS)

    def test_completion(self) -> None:
        """Completion offers the connections, and the tenants with configuration."""
        connections = conftest.run_cmd("hub00", f"{VPNCTL} __complete connections show")
        assert sorted(connections.split()) == sorted(HUB_CONNECTIONS)

        targets = conftest.run_cmd("hub00", f"{VPNCTL} __complete config show")
        assert sorted(targets.split()) == ["C0001", "service"]


def neighbor_address(host: str, hostname: str) -> str:
    """Return the address of a BGP neighbor."""
    neighbors = vpnctl(host, "bgp neighbors")
    return next(n["neighbor_address"] for n in neighbors if n["hostname"] == hostname)


@pytest.mark.parametrize("host", ["hub00", "hub01"])
class TestVpnctlBgp:
    """vpnctl shows BGP sessions and routes in detail."""

    def test_neighbor(self, host: str) -> None:
        """A neighbor shows its state, BFD and the prefixes it accepted."""
        neighbor = vpnctl(host, f"bgp neighbor {neighbor_address(host, 'mgt00')}")

        assert neighbor["session_state"] == "ESTABLISHED"
        assert neighbor["last_established"]
        # Only hub00 has BFD.
        assert neighbor["bfd"] == ("UP" if host == "hub00" else None)
        families = {f["afi_safi_name"]: f["prefixes"] for f in neighbor["afi_safis"]}
        assert families["IPV6_UNICAST"]["received"] >= 1

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
        core = {r["prefix"]: r for r in vpnctl("hub00", "routes CORE -6")}
        downlink = {r["prefix"]: r for r in vpnctl("hub00", "routes C0001-00 -4")}
        external = {r["prefix"]: r for r in vpnctl("hub00", "routes EXTERNAL -4")}

        assert core["fd00::/16"]["protocol"] == "BGP"
        assert downlink["172.16.30.1"]["interfaces"] == ["xfrm0"]
        assert external["0.0.0.0/0"]["next_hops"] == ["192.0.2.1"]

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

    @pytest.mark.parametrize("target", ["C0001-00-1", "C0001-00"])
    def test_capture(self, target: str) -> None:
        """A capture on a connection or network instance shows its packets."""
        tcp = f"{VPNCTL} tcp C0001-00 172.16.31.1 22"
        # -e is passed on to tcpdump.
        packets = "host 172.16.31.1 and tcp port 22"
        capture = f"timeout 20 {VPNCTL} capture {target} -c 2 -e {packets}"
        output = conftest.run_cmd_shell(
            "hub00",
            f"bash -c '(sleep 2; {tcp} > /dev/null) & {capture}'",
        )

        assert "100.99.0.17" in output
        assert "> 172.16.31.1.22: Flags [S]" in output

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


class TestVpnctlLogsAndCounters:
    """vpnctl shows the daemon logs and traffic counters."""

    def test_logs(self) -> None:
        """vpnc's log, by level; vpncmangle's and charon's log."""
        lines = vpnctl("hub00", "logs -n 20")
        assert 0 < len(lines) <= 20  # noqa: PLR2004
        assert {line["source"] for line in lines} == {"vpnc"}

        warnings = vpnctl("hub00", "logs -n 500 --level warning")
        assert {line["level"] for line in warnings} <= {"WARNING", "ERROR", "CRITICAL"}

        assert vpnctl("hub00", "logs --source vpncmangle")
        assert vpnctl("hub00", "logs --source charon")

    def test_follow_logs(self) -> None:
        """A followed log shows the last lines and stays open."""
        follower = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker",
                "exec",
                "clab-vpnc-hub00",
                "timeout",
                "3",
                VPNCTL,
                "logs",
                "-n",
                "5",
                "-f",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        # Ended by timeout.
        assert follower.returncode == 124  # noqa: PLR2004
        assert len(follower.stdout.splitlines()) >= 5  # noqa: PLR2004

    def test_network_instance_logs(self) -> None:
        """A network instance's log has its vpnc lines and its IKE SAs' lines."""
        lines = vpnctl("hub00", "logs --ni C0001-00 -n 2000")

        assert {line["source"] for line in lines} >= {"vpnc", "charon"}
        assert all(
            "C0001-00" in line["message"]
            for line in lines
            if line["source"] in ("vpnc", "ssh")
        )

    def test_counters(self) -> None:
        """Traffic through the SSH tunnel shows in its counters."""
        before = vpnctl("hub00", "connections show C0001-00-1")
        vpnctl("hub00", "tcp C0001-00 172.16.31.1 22")
        after = vpnctl("hub00", "connections show C0001-00-1")

        assert after["counters"]["out_pkts"] > before["counters"]["out_pkts"]
        assert after["counters"]["in_pkts"] > before["counters"]["in_pkts"]

    def test_rate(self) -> None:
        """Traffic through the SSH tunnel shows in its rates."""

        def rates() -> bool:
            vpnctl("hub00", "tcp C0001-00 172.16.31.1 22")
            rates = vpnctl("hub00", "connections show C0001-00-1")["rates"]
            return rates["in_bits_rate"] > 0 and rates["out_bits_rate"] > 0

        conftest.wait_until(rates, timeout=60, message="a traffic rate")

    def test_wide_list(self) -> None:
        """The wide list shows the MTU, the bytes in and out, and their rates."""
        header = conftest.run_cmd("hub00", f"{VPNCTL} connections list -o wide")
        columns = re.split(r"\s{2,}", header.splitlines()[0])
        assert columns[7:12] == ["MTU", "IN", "OUT", "IN RATE", "OUT RATE"]
