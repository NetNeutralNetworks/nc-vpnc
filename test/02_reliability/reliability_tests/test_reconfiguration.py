"""vpnc applies configuration changes and corrects drift (end results on hub00)."""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
import time
from typing import TYPE_CHECKING, Any

import pytest
import yaml

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

HOST = "hub00"
HUBS = ("hub00", "hub01")
TENANT_FILE = "/opt/ncubed/config/vpnc/active/C0002.yaml"
CANDIDATE_FILE = "/opt/ncubed/config/vpnc/candidate/C0002.yaml"
HISTORY_DIR = "/opt/ncubed/config/vpnc/history/C0002"
VPNCTL = "/opt/ncubed/vpnc/bin/vpnctl"
NI = "C0002-00"
# Its key in the tenant's configuration.
NI_KEY = "00"
CORE_LINK = f"{NI}_C"
APPLY_TIMEOUT = 60
# Drift is corrected by the full check, which runs every 30 seconds.
DRIFT_TIMEOUT = 90

DRIFT_NI = "C0001-00"
DRIFT_NI_KEY = "00"

# A DNS server of C0001-00 (through NAT64), and a name with only an AAAA record
# in a network that is translated with NPTv6.
DNS_SERVER = "fdcc:0:c:1::172.16.31.1"
DNS_NAME = "v6lonly.example.com"
DNS_ROUTE = "fdff:db8:c57::/52"
DNS_ANSWER = "fd6c:1:0:31::6"
DNS_ANSWER_WITHOUT_NPTV6 = "fdff:db8:c57:31::6"

# Route destinations as "ip --json route" reports them.
ROUTES_4 = ["10.201.0.0/24"]
ROUTES_6 = ["fdcc:201::/48"]


def ipsec_connection(
    connection_id: int,
    addresses: tuple[str, str],
    routes_4: list[str],
    routes_6: list[str],
) -> dict[str, Any]:
    """Return an IPsec responder connection to a peer that doesn't exist.

    Its id is its key in the configuration.
    """
    return {
        "id": connection_id,
        "interface": {"ipv4": [addresses[0]], "ipv6": [addresses[1]]},
        "routes": {
            "ipv4": [{"to": route} for route in routes_4],
            "ipv6": [{"to": route} for route in routes_6],
        },
        "config": {
            "type": "ipsec",
            "remote_addrs": ["192.0.2.99"],
            "ike_proposal": "aes128gcm16-prfsha384-ecp384",
            "ipsec_proposal": "aes128gcm16-prfsha384-ecp384",
            "initiation": "none",
            "psk": "reconfigurationtest",
        },
    }


BASE_CONNECTION = ipsec_connection(
    0,
    ("10.200.0.1/30", "fdcc:200::1/64"),
    ROUTES_4,
    ROUTES_6,
)


def write_tenant(connections: list[dict[str, Any]]) -> None:
    """Write the test tenant's configuration."""
    tenant = {
        "version": "0.1.4",
        "id": "C0002",
        "name": "Reconfiguration test",
        "network_instances": {
            NI_KEY: {
                "type": "downlink",
                "connections": {
                    c["id"]: {k: v for k, v in c.items() if k != "id"}
                    for c in connections
                },
            },
        },
    }
    conftest.write_file(HOST, TENANT_FILE, yaml.safe_dump(tenant))


def dns_answer() -> str:
    """Return the answer mgt00 gets for the test name."""
    return conftest.run_cmd(
        "mgt00",
        f"dig +short +time=1 +tries=1 {DNS_NAME} AAAA @{DNS_SERVER}",
    ).strip()


def netns_list() -> set[str]:
    """Return the network namespaces."""
    output = conftest.run_cmd(HOST, "ip netns list")
    return {line.split()[0] for line in output.splitlines() if line}


def links(netns: str) -> set[str]:
    """Return the interface names in a network namespace."""
    output = json.loads(conftest.run_cmd(HOST, f"ip --json --netns {netns} link"))
    return {link["ifname"] for link in output}


def addresses(netns: str, ifname: str) -> set[str]:
    """Return the global addresses of an interface as address/prefixlen."""
    output = json.loads(
        conftest.run_cmd(HOST, f"ip --json --netns {netns} address show dev {ifname}"),
    )
    return {
        f"{a['local']}/{a['prefixlen']}"
        for link in output
        for a in link["addr_info"]
        if a.get("scope") == "global"
    }


def route_destinations(netns: str) -> set[str]:
    """Return the route destinations in a network namespace."""
    destinations: set[str] = set()
    for family in ("-4", "-6"):
        output = json.loads(
            conftest.run_cmd(HOST, f"ip --json --netns {netns} {family} route"),
        )
        destinations |= {route["dst"] for route in output}
    return destinations


def connections() -> set[str]:
    """Return the connections loaded in charon."""
    output = conftest.run_cmd_shell(HOST, "swanctl --list-conns 2>/dev/null")
    return {line.split(":")[0] for line in output.splitlines() if line[:1].isalnum()}


def tenant_removed() -> bool:
    """Return whether nothing of the test tenant is left."""
    return (
        NI not in netns_list()
        and CORE_LINK not in links("CORE")
        and not {c for c in connections() if c.startswith(NI)}
    )


def connection_applied(connection: dict[str, Any]) -> bool:
    """Return whether a connection's interface, addresses, routes and conn exist."""
    ifname = f"xfrm{connection['id']}"
    expected_addresses = set(connection["interface"]["ipv4"]) | set(
        connection["interface"]["ipv6"],
    )
    expected_routes = {r["to"] for r in connection["routes"]["ipv4"]} | {
        r["to"] for r in connection["routes"]["ipv6"]
    }
    return (
        ifname in links(NI)
        and addresses(NI, ifname) == expected_addresses
        and expected_routes <= route_destinations(NI)
        and f"{NI}-{connection['id']}" in connections()
    )


@pytest.fixture
def test_tenant() -> Iterator[None]:
    """Add the test tenant and remove it afterwards."""
    write_tenant([BASE_CONNECTION])
    conftest.wait_until(
        lambda: connection_applied(BASE_CONNECTION) and CORE_LINK in links("CORE"),
        timeout=APPLY_TIMEOUT,
        message=f"tenant C0002 to be applied on {HOST}",
    )
    yield
    # Without its pending file, an unconfirmed commit isn't rolled back.
    conftest.run_cmd(HOST, f"rm -rf {TENANT_FILE} {CANDIDATE_FILE} {HISTORY_DIR}")
    conftest.wait_until(
        tenant_removed,
        timeout=APPLY_TIMEOUT,
        message=f"tenant C0002 to be removed from {HOST}",
    )


@pytest.mark.usefixtures("test_tenant")
class TestReconfiguration:
    """Configuration changes are applied."""

    def test_remove_tenant(self) -> None:
        """Removing a tenant removes its network instance, links and connections."""
        conftest.run_cmd(HOST, f"rm -f {TENANT_FILE}")
        conftest.wait_until(
            tenant_removed,
            timeout=APPLY_TIMEOUT,
            message=f"tenant C0002 to be removed from {HOST}",
        )

    def test_add_and_remove_connection(self) -> None:
        """A connection added to a network instance is set up, and removed again."""
        second = ipsec_connection(
            1,
            ("10.200.0.5/30", "fdcc:200:0:1::1/64"),
            ["10.203.0.0/24"],
            ["fdcc:203::/48"],
        )
        write_tenant([BASE_CONNECTION, second])
        conftest.wait_until(
            lambda: connection_applied(second),
            timeout=APPLY_TIMEOUT,
            message="connection 1 to be applied",
        )

        write_tenant([BASE_CONNECTION])
        conftest.wait_until(
            lambda: (
                "xfrm1" not in links(NI)
                and f"{NI}-1" not in connections()
                and not {"10.203.0.0/24", "fdcc:203::/48"} & route_destinations(NI)
            ),
            timeout=APPLY_TIMEOUT,
            message="connection 1 to be removed",
        )
        assert connection_applied(BASE_CONNECTION)

    def test_change_routes(self) -> None:
        """Changed routes replace the old ones."""
        changed = ipsec_connection(
            0,
            ("10.200.0.1/30", "fdcc:200::1/64"),
            ["10.202.0.0/24"],
            ["fdcc:202::/48"],
        )
        write_tenant([changed])
        conftest.wait_until(
            lambda: (
                connection_applied(changed)
                and not {*ROUTES_4, *ROUTES_6} & route_destinations(NI)
            ),
            timeout=APPLY_TIMEOUT,
            message="changed routes to be applied",
        )

    def test_change_addresses(self) -> None:
        """Changed interface addresses replace the old ones."""
        changed = ipsec_connection(
            0,
            ("10.200.0.9/30", "fdcc:200:0:2::1/64"),
            ROUTES_4,
            ROUTES_6,
        )
        write_tenant([changed])
        conftest.wait_until(
            lambda: connection_applied(changed),
            timeout=APPLY_TIMEOUT,
            message="changed addresses to be applied",
        )

    def test_nptv6_prefixes_dont_overlap(self) -> None:
        """New NPTv6 prefixes don't overlap assigned ones; too big routes are skipped.

        C0002-00's NPTv6 scope is fd6c:2::/48.
        """
        connection = ipsec_connection(
            0,
            ("10.200.0.1/30", "fdcc:200::1/64"),
            ROUTES_4,
            [],
        )
        connection["routes"]["ipv6"] = [
            # Assigned earlier.
            {"to": "fdcc:211::/56", "nptv6_prefix": "fd6c:2:0:100::/56"},
            # Bigger than the scope.
            {"to": "fdcc:220::/44"},
            # fd6c:2::/52 would contain fd6c:2:0:100::/56.
            {"to": "fdcc:212::/52"},
        ]
        write_tenant([connection])
        expected = {
            ("fd6c:2:0:100::/56", "fdcc:211::/56"),
            ("fd6c:2:0:1000::/52", "fdcc:212::/52"),
        }
        # On a timeout the assert shows what differs.
        with contextlib.suppress(TimeoutError):
            conftest.wait_until(
                lambda: nptv6_mappings(NI) == expected,
                timeout=APPLY_TIMEOUT,
            )
        assert nptv6_mappings(NI) == expected

    def test_config_edit_and_commit(self) -> None:
        """An edited candidate shows in the diff and is applied on commit."""
        output = vpnctl_edit("s|fdcc:201::/48|fdcc:209::/48|")
        assert any(
            line.startswith("+") and "fdcc:209::/48" in line
            for line in output.splitlines()
        )

        staged = {c["id"]: c["status"] for c in vpnctl_json("config list")}
        assert staged["C0002"] == "modified"

        assert conftest.run_cmd(HOST, f"{VPNCTL} config commit C0002") == "Committed.\n"
        conftest.wait_until(
            lambda: (
                "fdcc:209::/48" in route_destinations(NI)
                and "fdcc:201::/48" not in route_destinations(NI)
            ),
            timeout=APPLY_TIMEOUT,
            message="the committed route to be applied",
        )
        assert conftest.run_cmd(HOST, f"{VPNCTL} config diff C0002") == "No changes.\n"

    def test_config_edit_invalid(self) -> None:
        """An invalid edit is rejected and leaves the candidate unchanged."""
        with pytest.raises(subprocess.CalledProcessError) as err:
            vpnctl_edit("s|C0002|C0003|")

        assert "doesn't match 'C0002'" in err.value.stderr
        assert conftest.run_cmd(HOST, f"{VPNCTL} config diff C0002") == "No changes.\n"

    def test_config_discard(self) -> None:
        """Discarding a candidate undoes the edit; nothing is applied."""
        vpnctl_edit("s|Reconfiguration|Discarded|")
        output = conftest.run_cmd(HOST, f"{VPNCTL} config discard C0002")

        assert output == "Discarded the changes.\n"
        assert conftest.run_cmd(HOST, f"{VPNCTL} config diff C0002") == "No changes.\n"
        assert vpnctl_json("tenants show C0002")["name"] == "Reconfiguration test"

    def test_config_set_list_item(self) -> None:
        """Setting a route in a list stages it; commit applies it."""
        vpnctl(f"config set C0002 {ROUTES_PATH}.ipv4.0.to 10.209.0.0/24")
        assert vpnctl(f"config show C0002 {ROUTES_PATH}.ipv4.0.to --candidate") == (
            "10.209.0.0/24\n"
        )
        # Staged only.
        assert "10.201.0.0/24" in route_destinations(NI)

        assert vpnctl("config commit C0002") == "Committed.\n"
        conftest.wait_until(
            lambda: (
                "10.209.0.0/24" in route_destinations(NI)
                and "10.201.0.0/24" not in route_destinations(NI)
            ),
            timeout=APPLY_TIMEOUT,
            message="the set route to be applied",
        )

    def test_config_delete_path(self) -> None:
        """Deleting a route removes it on commit."""
        vpnctl(f"config delete C0002 {ROUTES_PATH}.ipv6.0")
        vpnctl("config commit C0002")
        conftest.wait_until(
            lambda: "fdcc:201::/48" not in route_destinations(NI),
            timeout=APPLY_TIMEOUT,
            message="the deleted route to be removed",
        )
        assert "10.201.0.0/24" in route_destinations(NI)

    def test_config_delete_tenant(self) -> None:
        """Deleting a tenant is staged; commit removes it."""
        vpnctl("config delete C0002")
        staged = {c["id"]: c["status"] for c in vpnctl_json("config list")}
        assert staged["C0002"] == "deleted"
        assert NI in netns_list()

        vpnctl("config commit C0002")
        conftest.wait_until(
            tenant_removed,
            timeout=APPLY_TIMEOUT,
            message="tenant C0002 to be removed",
        )

    def test_config_tenant_lifecycle(self) -> None:
        """A tenant is created, changed and deleted with vpnctl."""
        try:
            # A new tenant starts empty; \x20 is a space.
            conftest.run_cmd_shell(
                HOST,
                f"env EDITOR='sed -i s|name:.*|name:\\x20Created|' "
                f"{VPNCTL} config edit C0003",
            )
            vpnctl("config commit C0003")
            conftest.wait_until(
                lambda: "C0003" in tenant_ids(),
                timeout=APPLY_TIMEOUT,
                message="tenant C0003 to be created",
            )
            assert vpnctl_json("tenants show C0003")["name"] == "Created"

            vpnctl("config set C0003 name Changed")
            vpnctl("config commit C0003")
            conftest.wait_until(
                lambda: vpnctl_json("tenants show C0003")["name"] == "Changed",
                timeout=APPLY_TIMEOUT,
                message="the name to change",
            )

            vpnctl("config delete C0003")
            vpnctl("config commit C0003")
            conftest.wait_until(
                lambda: "C0003" not in tenant_ids(),
                timeout=APPLY_TIMEOUT,
                message="tenant C0003 to be removed",
            )
            assert "C0003" not in [c["id"] for c in vpnctl_json("config list")]
        finally:
            conftest.run_cmd(
                HOST,
                f"rm -rf {TENANT_FILE.replace('C0002', 'C0003')} "
                f"{CANDIDATE_FILE.replace('C0002', 'C0003')} "
                f"{HISTORY_DIR.replace('C0002', 'C0003')}",
            )

    def test_staged_changes_survive_nptv6_assignment(self) -> None:
        """Assigning NPTv6 prefixes doesn't overwrite staged changes.

        vpnc writes assigned prefixes back to the configuration files.
        """
        addresses = ("10.200.0.1/30", "fdcc:200::1/64")
        write_tenant([ipsec_connection(0, addresses, ROUTES_4, [])])
        conftest.wait_until(
            lambda: not nptv6_mappings(NI),
            timeout=APPLY_TIMEOUT,
            message="the IPv6 route to be removed",
        )
        vpnctl("config set C0002 name Staged")

        # Applied directly; vpnc assigns the route a prefix and writes it back.
        write_tenant([ipsec_connection(0, addresses, ROUTES_4, ["fdcc:203::/48"])])
        conftest.wait_until(
            lambda: any(remote == "fdcc:203::/48" for _, remote in nptv6_mappings(NI)),
            timeout=APPLY_TIMEOUT,
            message="the NPTv6 prefix to be assigned",
        )

        assert vpnctl("config show C0002 name --candidate") == "Staged\n"

    def test_config_history_and_restore(self) -> None:
        """A commit keeps the replaced configuration; restoring it brings it back."""
        set_route("10.209.0.0/24")
        assert vpnctl("config commit C0002") == "Committed.\n"
        wait_for_route("10.209.0.0/24")

        history = vpnctl_json("config history C0002")
        assert [(h["revision"], h["exists"]) for h in history] == [(1, True)]
        revision = vpnctl_json("config history C0002 1")
        assert revision["network_instances"][NI_KEY]["connections"]["0"]["routes"][
            "ipv4"
        ] == [{"to": "10.201.0.0/24", "via": None}]

        output = vpnctl("config restore C0002 1")
        assert any(
            line.startswith("+") and "to: 10.201.0.0/24" in line
            for line in output.splitlines()
        )
        vpnctl("config commit C0002")
        wait_for_route("10.201.0.0/24")
        assert len(vpnctl_json("config history C0002")) == 2  # noqa: PLR2004

    def test_unconfirmed_commit_rolls_back(self) -> None:
        """A commit that isn't confirmed in time is rolled back; it stays staged."""
        set_route("10.209.0.0/24")
        output = vpnctl("config commit C0002 --confirm 10s")
        assert "vpnctl config confirm C0002" in output
        wait_for_route("10.209.0.0/24")
        staged = {c["id"]: c for c in vpnctl_json("config list")}
        assert staged["C0002"]["confirm_by"] is not None

        wait_for_route("10.201.0.0/24", timeout=10 + APPLY_TIMEOUT)
        staged = {c["id"]: c for c in vpnctl_json("config list")}
        assert staged["C0002"]["status"] == "modified"
        assert staged["C0002"]["confirm_by"] is None

    def test_confirmed_commit_stays(self) -> None:
        """A confirmed commit isn't rolled back."""
        set_route("10.209.0.0/24")
        vpnctl("config commit C0002 --confirm 10s")
        wait_for_route("10.209.0.0/24")
        assert vpnctl("config confirm C0002") == "Confirmed.\n"

        time.sleep(15)
        assert "10.209.0.0/24" in route_destinations(NI)
        assert vpnctl("config diff C0002") == "No changes.\n"

    def test_config_commit_all(self) -> None:
        """--all commits and discards the staged changes of every tenant."""
        set_route("10.209.0.0/24")
        assert vpnctl("config commit --all") == "Committed C0002.\n"
        wait_for_route("10.209.0.0/24")

        vpnctl("config set C0002 name Discarded")
        assert vpnctl("config discard --all") == "Discarded the changes of C0002.\n"
        assert vpnctl("config commit --all") == "No changes.\n"

    @pytest.mark.parametrize("secret", ["new secret", "12345"])
    def test_config_set_prompted_secret(self, secret: str) -> None:
        """A prompted value (here on stdin) is taken as text, e.g. a secret."""
        psk = f"network_instances.{NI_KEY}.connections.0.config.psk"
        conftest.run_cmd_shell(
            HOST,
            f"bash -c 'echo \"{secret}\" | {VPNCTL} config set C0002 {psk}'",
        )

        shown = vpnctl_json(f"config show C0002 {psk} --candidate --reveal-secrets")
        assert shown == secret


class TestRestartNotice:
    """Service settings that apply after a restart are pointed out."""

    def test_restart_notice(self) -> None:
        """Changing the NAT64 prefix needs a restart; changing it back doesn't."""
        host = "hub01"
        path = "prefix_downlink_nat64"
        original = conftest.run_cmd(host, f"{VPNCTL} config show service {path}")
        try:
            conftest.run_cmd(host, f"{VPNCTL} config set service {path} 64:ff9a::/32")
            output = conftest.run_cmd(host, f"{VPNCTL} config commit service")
            assert f"Restart vpnc to apply {path}" in output
            status = json.loads(conftest.run_cmd(host, f"{VPNCTL} -o json status"))
            assert status["restart_needed"] == [path]
        finally:
            conftest.run_cmd(host, f"{VPNCTL} config set service {path} {original}")
            output = conftest.run_cmd(host, f"{VPNCTL} config commit service")

        assert "Restart" not in output
        conftest.wait_until(
            lambda: json.loads(
                conftest.run_cmd(host, f"{VPNCTL} -o json ni show C0001-00"),
            )["translations"][0]["local"]
            == "fdcc:0:c:1::/96",
            timeout=APPLY_TIMEOUT,
            message="the NAT64 translation to be restored",
        )


class TestOldConfiguration:
    """Configuration of the previous version is converted."""

    def test_old_file_is_converted(self) -> None:
        """A 0.1.3 file is applied, converted in place and its original kept."""
        backup = "/opt/ncubed/config/vpnc/backup/0.1.3/active/C0002.yaml"
        old = yaml.safe_dump(
            {
                "version": "0.1.3",
                "id": "C0002",
                "name": "Conversion test",
                "network_instances": {
                    NI: {
                        "id": NI,
                        "type": "downlink",
                        "connections": {0: BASE_CONNECTION},
                    },
                },
            },
        )
        try:
            conftest.write_file(HOST, TENANT_FILE, old)
            conftest.wait_until(
                lambda: connection_applied(BASE_CONNECTION),
                timeout=APPLY_TIMEOUT,
                message=f"the 0.1.3 tenant C0002 to be applied on {HOST}",
            )
            new = yaml.safe_load(conftest.run_cmd(HOST, f"cat {TENANT_FILE}"))
            assert new["version"] == "0.1.4"
            assert [f"{key:02}" for key in new["network_instances"]] == [NI_KEY]
            network_instance = next(iter(new["network_instances"].values()))
            assert "id" not in network_instance
            # vpnc may have written the file again (NPTv6 prefixes).
            assert [int(key) for key in network_instance["connections"]] == [0]
            assert "id" not in next(iter(network_instance["connections"].values()))
            assert conftest.run_cmd(HOST, f"cat {backup}") == old
        finally:
            conftest.run_cmd(HOST, f"rm -f {TENANT_FILE} {backup}")
            conftest.wait_until(
                tenant_removed,
                timeout=APPLY_TIMEOUT,
                message=f"tenant C0002 to be removed from {HOST}",
            )


def set_route(route: str) -> None:
    """Stage the test connection's IPv4 route."""
    vpnctl(f"config set C0002 {ROUTES_PATH}.ipv4.0.to {route}")


def wait_for_route(route: str, timeout: float = APPLY_TIMEOUT) -> None:
    """Wait until the IPv4 route is the only one applied of the test routes."""
    other = {"10.201.0.0/24", "10.209.0.0/24"} - {route}
    conftest.wait_until(
        lambda: route in route_destinations(NI) and not other & route_destinations(NI),
        timeout=timeout,
        message=f"route {route} to be applied",
    )


ROUTES_PATH = f"network_instances.{NI_KEY}.connections.0.routes"


def tenant_ids() -> list[str]:
    """Return the tenants vpnc runs."""
    return [t["id"] for t in vpnctl_json("tenants list")]


def vpnctl(args: str) -> str:
    """Run vpnctl on the host (no spaces in arguments)."""
    return conftest.run_cmd(HOST, f"{VPNCTL} {args}")


def vpnctl_json(args: str) -> Any:  # noqa: ANN401
    """Run vpnctl on the host with JSON output."""
    return json.loads(conftest.run_cmd(HOST, f"{VPNCTL} -o json {args}"))


def vpnctl_edit(sed_expression: str) -> str:
    """Edit C0002's candidate with sed as the editor (no spaces in the expression)."""
    return conftest.run_cmd_shell(
        HOST,
        f"env EDITOR='sed -i {sed_expression}' {VPNCTL} config edit C0002",
    )


NPTV6_RULE_RE = re.compile(r"ip6 daddr (\S+) dnat (?:ip6 )?prefix to (\S+)")


def nptv6_mappings(netns: str) -> set[tuple[str, str]]:
    """Return the NPTv6 translations of a network instance (prefix, route)."""
    rules = conftest.run_cmd(
        HOST,
        f"ip netns exec {netns} nft list chain inet vpnc prerouting",
    )
    return set(NPTV6_RULE_RE.findall(rules))


def drift_snapshot() -> dict[str, Any]:
    """Return links, global addresses and non-BGP routes of C0001-00 and CORE."""
    snapshot: dict[str, Any] = {}
    for netns in (DRIFT_NI, "CORE"):
        names = links(netns)
        routes: set[tuple[str, str]] = set()
        for family in ("-4", "-6"):
            output = json.loads(
                conftest.run_cmd(HOST, f"ip --json --netns {netns} {family} route"),
            )
            routes |= {
                (r["dst"], r.get("dev", r.get("type", "")))
                for r in output
                if r.get("protocol") not in ("kernel", "bgp")
            }
        snapshot[netns] = {
            "links": names,
            "addresses": {n: addresses(netns, n) for n in names},
            "routes": routes,
        }
    return snapshot


def assert_drift_corrected(tamper: str) -> None:
    """Run a command that changes the lab by hand and wait until it's corrected."""
    expected = drift_snapshot()
    conftest.run_cmd_shell(HOST, tamper)
    assert drift_snapshot() != expected, f"'{tamper}' didn't change anything"
    conftest.wait_until(
        lambda: drift_snapshot() == expected,
        timeout=DRIFT_TIMEOUT,
        message=f"drift from '{tamper}' to be corrected",
    )


class TestDrift:
    """Manual changes are corrected by the full check."""

    def test_deleted_route(self) -> None:
        """A deleted route is restored."""
        assert_drift_corrected(f"ip --netns {DRIFT_NI} route del 172.16.30.1/32")

    def test_deleted_address(self) -> None:
        """A deleted interface address is restored."""
        assert_drift_corrected(
            f"ip --netns {DRIFT_NI} address flush dev xfrm0 scope global",
        )

    def test_deleted_interface(self) -> None:
        """A deleted XFRM interface is recreated with its addresses and routes."""
        assert_drift_corrected(f"ip --netns {DRIFT_NI} link del xfrm0")

    def test_deleted_core_link(self) -> None:
        """A deleted link between CORE and a network instance is recreated."""
        assert_drift_corrected(f"ip --netns CORE link del {DRIFT_NI}_C")

    def test_removed_wireguard_peer(self) -> None:
        """A WireGuard peer removed by hand is restored."""
        wg = "ip netns exec C0001-01 wg show wg-C0001-01-0 peers"
        peer = conftest.run_cmd_shell(HOST, wg).strip()
        assert peer, "No WireGuard peer before the test"
        conftest.run_cmd_shell(
            HOST,
            f"ip netns exec C0001-01 wg set wg-C0001-01-0 peer {peer} remove",
        )
        assert not conftest.run_cmd_shell(HOST, wg).strip()
        conftest.wait_until(
            lambda: conftest.run_cmd_shell(HOST, wg).strip() == peer,
            timeout=DRIFT_TIMEOUT,
            message="WireGuard peer to be restored",
        )

    def test_killed_vpncmangle(self) -> None:
        """A killed vpncmangle process is restarted."""
        pgrep = "pgrep -f bin/vpncmangle || true"
        before = conftest.run_cmd_shell(HOST, pgrep).split()
        assert before, "vpncmangle not running"
        conftest.run_cmd_shell(HOST, "pkill -f bin/vpncmangle")
        conftest.wait_until(
            lambda: (
                (pids := conftest.run_cmd_shell(HOST, pgrep).split())
                and not set(pids) & set(before)
            ),
            timeout=DRIFT_TIMEOUT,
            message="vpncmangle to be restarted",
        )
        conftest.wait_until(
            lambda: dns_answer() == DNS_ANSWER,
            timeout=APPLY_TIMEOUT,
            message="DNS answers to be translated again",
        )


class TestDnsTranslation:
    """DNS answers follow the configuration."""

    def test_follows_nptv6_setting(self) -> None:
        """Without NPTv6 for a route, its addresses are answered untranslated."""
        path = "/opt/ncubed/config/vpnc/active/C0001.yaml"
        # mgt00 is answered through either hub.
        original = {hub: conftest.run_cmd(hub, f"cat {path}") for hub in HUBS}
        assert dns_answer() == DNS_ANSWER
        try:
            for hub, text in original.items():
                tenant = yaml.safe_load(text)
                # YAML reads an unquoted 00 as 0.
                network_instances = {
                    f"{key:02d}" if isinstance(key, int) else key: ni
                    for key, ni in tenant["network_instances"].items()
                }
                connections = network_instances[DRIFT_NI_KEY]["connections"]
                for connection in connections.values():
                    for route in (connection.get("routes") or {}).get("ipv6") or []:
                        if route["to"] == DNS_ROUTE:
                            route.update(nptv6=False, nptv6_prefix=None)
                conftest.write_file(hub, path, yaml.safe_dump(tenant))
            conftest.wait_until(
                lambda: dns_answer() == DNS_ANSWER_WITHOUT_NPTV6,
                timeout=APPLY_TIMEOUT,
                message="the untranslated DNS answer",
            )
        finally:
            for hub, text in original.items():
                conftest.write_file(hub, path, text)
            conftest.wait_until(
                lambda: dns_answer() == DNS_ANSWER,
                timeout=APPLY_TIMEOUT,
                message="the translated DNS answer",
            )


CONFIG_DIR = "/opt/ncubed/config/vpnc"
# Tenants of the WireGuard port tests; B0001 sorts before the others.
PORT_TENANTS = ("B0001", "C0003", "C0004")


def wireguard_tenant(tenant_id: str, port: int, route: str = "10.210.0.0/24") -> str:
    """Return a tenant with one WireGuard connection to a peer that doesn't exist."""
    tenant = {
        "version": "0.1.4",
        "id": tenant_id,
        "name": "WireGuard port test",
        "network_instances": {
            "00": {
                "type": "downlink",
                "connections": {
                    0: {
                        "routes": {"ipv4": [{"to": route}]},
                        "config": {
                            "type": "wireguard",
                            "local_port": port,
                            "remote_addrs": ["192.0.2.99"],
                            "private_key": (
                                "aCIwvWZ7aknX9Lpyk40zEu2HhneHyWSxgl6NVJRU50s="
                            ),
                            "public_key": (
                                "9xdzIRK5ARFePwKZUKZAMwXPddTRtQTlQ00J3aUEeGc="
                            ),
                        },
                    },
                },
            },
        },
    }
    return yaml.safe_dump(tenant)


def stage(tenant_id: str, port: int) -> None:
    """Stage a WireGuard tenant."""
    path = f"{CONFIG_DIR}/candidate/{tenant_id}.yaml"
    conftest.write_file(HOST, path, wireguard_tenant(tenant_id, port))


def listen_port(tenant_id: str) -> int | None:
    """Return the port of a tenant's WireGuard interface (None: no interface)."""
    ni = f"{tenant_id}-00"
    try:
        output = conftest.run_cmd(
            HOST,
            f"ip netns exec {ni} wg show wg-{ni}-0 listen-port",
        )
    except subprocess.CalledProcessError:
        return None
    return int(output)


def wait_for_ports(ports: dict[str, int | None]) -> None:
    """Wait until the tenants' WireGuard interfaces listen on these ports."""
    conftest.wait_until(
        lambda: {tenant_id: listen_port(tenant_id) for tenant_id in ports} == ports,
        timeout=APPLY_TIMEOUT,
        message=f"WireGuard ports {ports}",
    )


@pytest.fixture
def port_tenants() -> Iterator[None]:
    """Remove the tenants of the WireGuard port tests afterwards."""
    yield
    for tenant_id in PORT_TENANTS:
        conftest.run_cmd(
            HOST,
            f"rm -rf {CONFIG_DIR}/active/{tenant_id}.yaml"
            f" {CONFIG_DIR}/candidate/{tenant_id}.yaml"
            f" {CONFIG_DIR}/history/{tenant_id}",
        )
    conftest.wait_until(
        lambda: not {f"{tenant_id}-00" for tenant_id in PORT_TENANTS} & netns_list(),
        timeout=APPLY_TIMEOUT,
        message="the WireGuard port tenants to be removed",
    )


@pytest.mark.usefixtures("port_tenants")
class TestWireGuardPorts:
    """Only one WireGuard connection uses a local port."""

    def test_port_in_use_is_refused(self) -> None:
        """A commit with the port of another tenant's connection is refused."""
        # C0001-01-0 uses the default port.
        stage("C0003", 51820)
        with pytest.raises(subprocess.CalledProcessError) as err:
            vpnctl("config commit C0003")

        assert "WireGuard port 51820 is used by" in err.value.stderr
        assert "C0003" not in tenant_ids()

        stage("C0003", 51900)
        vpnctl("config commit C0003")
        wait_for_ports({"C0003": 51900})

    def test_duplicate_port_in_commit_all_commits_nothing(self) -> None:
        """Two staged tenants with the same port stop the commit of all."""
        stage("C0003", 51900)
        stage("C0004", 51900)
        with pytest.raises(subprocess.CalledProcessError) as err:
            vpnctl("config commit --all")

        assert "WireGuard port 51900 is used by" in err.value.stderr
        time.sleep(5)
        assert not {"C0003", "C0004"} & set(tenant_ids())

    def test_port_moves_between_tenants(self) -> None:
        """A port moves to another tenant, in a commit of all and in two commits."""
        stage("C0003", 51900)
        stage("C0004", 51901)
        vpnctl("config commit --all")
        wait_for_ports({"C0003": 51900, "C0004": 51901})

        stage("C0003", 51902)
        stage("C0004", 51900)
        vpnctl("config commit --all")
        wait_for_ports({"C0003": 51902, "C0004": 51900})

        # Committed right after each other: the first isn't applied yet.
        stage("C0003", 51903)
        stage("C0004", 51902)
        conftest.run_cmd_shell(
            HOST,
            f"bash -c '{VPNCTL} config commit C0003 && {VPNCTL} config commit C0004'",
        )
        wait_for_ports({"C0003": 51903, "C0004": 51902})

    def test_connection_with_the_port_keeps_it(self) -> None:
        """A duplicate added outside vpnctl doesn't take over a port in use."""
        stage("C0004", 51900)
        vpnctl("config commit C0004")
        wait_for_ports({"C0004": 51900})

        conftest.write_file(
            HOST,
            f"{CONFIG_DIR}/active/B0001.yaml",
            wireguard_tenant("B0001", 51900),
        )
        conftest.wait_until(
            lambda: "B0001-00" in netns_list(),
            timeout=APPLY_TIMEOUT,
            message="B0001 to be applied",
        )
        # Changes of the connection that has the port are still applied.
        conftest.write_file(
            HOST,
            f"{CONFIG_DIR}/active/C0004.yaml",
            wireguard_tenant("C0004", 51900, "10.211.0.0/24"),
        )
        conftest.wait_until(
            lambda: "10.211.0.0/24" in route_destinations("C0004-00"),
            timeout=APPLY_TIMEOUT,
            message="the route of C0004 to be applied",
        )
        assert [listen_port("C0004"), listen_port("B0001")] == [51900, None]
