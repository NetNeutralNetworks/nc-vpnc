"""vpnc runs 200 network instances with 300 live connections (end results).

The scale lab (scale.clab.yaml) has hub00 with vpnc and peer00, the other end of
every connection. Half of the IPsec connections are initiated by hub00, half by
peer00.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

import pytest
import yaml

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

HOST = "scale-hub00"
PEER = "scale-peer00"
CONFIG_DIR = "/opt/ncubed/config/vpnc/active"
TENANTS = [f"C{n:04d}" for n in range(100, 125)]
NIS_PER_TENANT = 8
# The first network instances get two connections: 300 in total.
NIS_WITH_TWO = 100
# Every WIREGUARD_EVERY-th connection is WireGuard, the others IPsec.
WIREGUARD_EVERY = 15

HUB_ADDRESS = "2001:db8::5"
PEER_PREFIX = "2001:db8::1:0/112"
PSK = "scaletest"
PROPOSAL = "aes128gcm16-prfsha384-ecp384"
IKE_LIFETIME = 900
IPSEC_LIFETIME = 300
# Test keys of hub00's and peer00's WireGuard interfaces.
HUB_WG_PRIVATE = "AOpPyGj0NFhDSXIjevMslo6nA5hEyhojXF7JWmQ3VFk="
HUB_WG_PUBLIC = "19pR/ryIl2yz/l8qRu3WY+IhPkzOYFgh33Bxlj342RM="
PEER_WG_PRIVATE = "2Dg9OKiJp2qTcPJ7iE5cHvjw1B/R813KA6hVU5OP2Go="
PEER_WG_PUBLIC = "liqiKh82ZQKZD0hP5T/MOCAiwZhtvhJ78IJhkSg1xBg="

LAB_TIMEOUT = 300
APPLY_TIMEOUT = 900
CHANGE_TIMEOUT = 15
# Drift is corrected by the full check, which runs every 30 seconds.
DRIFT_TIMEOUT = 120
# Longer than dead peer detection (30s delay, ~165s of retransmits).
OUTAGE = 240
RECOVER_TIMEOUT = 300
REMOVE_TIMEOUT = 300
CPU_SAMPLE = 90
# After the tunnels came up, links go up and routes follow for a while.
SETTLE = 60
# What a vpnctl command may take, including docker exec.
VPNCTL_TIMEOUT = 5

# Prints per scale namespace its addresses and routes as JSON lines, and the
# WireGuard handshakes.
STATE_SCRIPT = "/tmp/scale_state.sh"  # noqa: S108
STATE_SCRIPT_CONTENT = """\
for ns in $(ip netns list | awk '{print $1}' | grep -E '^C01[0-2][0-9]-'); do
  echo "# $ns"
  ip -j -n "$ns" address
  ip -j -n "$ns" -4 route
  ip -j -n "$ns" -6 route
  ip netns exec "$ns" wg show all latest-handshakes | sed "s/^/W $ns /"
done
"""


def peer_address(index: int) -> str:
    """Return peer00's address of connection index."""
    return f"2001:db8::1:{index:x}"


def is_wireguard(index: int) -> bool:
    """Return whether connection index is WireGuard."""
    return index % WIREGUARD_EVERY == WIREGUARD_EVERY - 1


def wireguard_port(index: int) -> int:
    """Return hub00's port of WireGuard connection index.

    Outside 51820-51899 on purpose: vpnc accepts exactly the configured ports.
    """
    return 52000 + index // WIREGUARD_EVERY


def hub_initiates(index: int) -> bool:
    """Return whether hub00 initiates IPsec connection index."""
    return index % 2 == 0


def connection(index: int) -> dict[str, Any]:
    """Return hub00's connection; index numbers all connections."""
    routes = {
        "ipv4": [{"to": f"10.{150 + index // 250}.{index % 250}.0/24"}],
        "ipv6": [{"to": f"fdcc:{0x1000 + index:x}::/48"}],
    }
    if is_wireguard(index):
        config = {
            "type": "wireguard",
            "remote_addrs": [peer_address(index)],
            "local_port": wireguard_port(index),
            "remote_port": 53000 + index,
            "private_key": HUB_WG_PRIVATE,
            "public_key": PEER_WG_PUBLIC,
        }
    else:
        config = {
            "type": "ipsec",
            "remote_addrs": [peer_address(index)],
            "ike_proposal": PROPOSAL,
            "ike_lifetime": IKE_LIFETIME,
            "ipsec_proposal": PROPOSAL,
            "ipsec_lifetime": IPSEC_LIFETIME,
            "initiation": "start" if hub_initiates(index) else "none",
            "psk": PSK,
        }
    return {"routes": routes, "config": config}


def scale_tenants() -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
    """Return the tenants and network instances by id, and connection indexes."""
    tenants: dict[str, Any] = {}
    network_instances: dict[str, Any] = {}
    indexes: dict[str, int] = {}
    for tenant_id in TENANTS:
        tenant_nis: dict[str, Any] = {}
        for n in range(NIS_PER_TENANT):
            ni = f"{tenant_id}-{n:02d}"
            count = 2 if len(network_instances) < NIS_WITH_TWO else 1
            connections = {}
            for connection_id in range(count):
                connections[connection_id] = connection(len(indexes))
                indexes[f"{ni}-{connection_id}"] = len(indexes)
            # Configured by its number; named after the tenant and the number.
            network_instances[ni] = tenant_nis[f"{n:02d}"] = {
                "type": "downlink",
                "connections": connections,
            }
        tenants[tenant_id] = {
            "version": "0.1.4",
            "id": tenant_id,
            "name": "Scale test",
            "network_instances": tenant_nis,
        }
    return tenants, network_instances, indexes


TENANT_CONFIG, NETWORK_INSTANCES, INDEXES = scale_tenants()


def write_tenant(tenant: dict[str, Any]) -> None:
    """Write a scale tenant's configuration file on hub00."""
    conftest.write_file(
        HOST,
        f"{CONFIG_DIR}/{tenant['id']}.yaml",
        yaml.safe_dump(tenant),
    )


def peer_swanctl() -> str:
    """Return peer00's swanctl configuration for hub00's IPsec connections."""
    conns = []
    for index in INDEXES.values():
        if is_wireguard(index):
            continue
        # The side that doesn't initiate only responds.
        if hub_initiates(index):
            actions = "start_action = none, dpd_action = clear, close_action = none"
        else:
            actions = "start_action = start, dpd_action = restart, close_action = start"
        conns.append(f"""
  scale-{index} {{
    local_addrs = {peer_address(index)}
    remote_addrs = {HUB_ADDRESS}
    dpd_delay = 30s
    keyingtries = 0
    unique = replace
    if_id_in = {index + 1}
    if_id_out = {index + 1}
    local {{
      id = {peer_address(index)}
      auth = psk
    }}
    remote {{
      id = {HUB_ADDRESS}
      auth = psk
    }}
    proposals = {PROPOSAL}
    rekey_time = {IKE_LIFETIME}s
    children {{
      scale-{index} {{
        local_ts = 0.0.0.0/0,::/0
        remote_ts = 0.0.0.0/0,::/0
        esp_proposals = {PROPOSAL}
        rekey_time = {IPSEC_LIFETIME}s
        life_time = {round(IPSEC_LIFETIME * 1.1)}s
        {actions.replace(", ", chr(10) + " " * 8)}
      }}
    }}
  }}""")
    return (
        "connections {"
        + "".join(conns)
        + f"\n}}\n\nsecrets {{\n  ike-hub {{\n    id = {HUB_ADDRESS}\n"
        + f"    secret = {PSK}\n  }}\n}}\n"
    )


def peer_setup_script() -> str:
    """Return the script that adds peer00's addresses and WireGuard interfaces."""
    lines = ["set -e", "ip -batch - << 'EOF'"]
    lines += [
        f"address replace {peer_address(index)}/64 dev eth1 nodad"
        for index in INDEXES.values()
    ]
    lines += ["EOF", f"echo {PEER_WG_PRIVATE} > /etc/wireguard/scale.key"]
    for index in INDEXES.values():
        if not is_wireguard(index):
            continue
        wg = f"wg{index}"
        lines += [
            f"ip link show {wg} &> /dev/null || ip link add {wg} type wireguard",
            (
                f"wg set {wg} private-key /etc/wireguard/scale.key"
                f" listen-port {53000 + index} peer {HUB_WG_PUBLIC}"
                f" endpoint [{HUB_ADDRESS}]:{wireguard_port(index)}"
                " allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 25"
            ),
            f"ip link set {wg} up",
        ]
    return "\n".join(lines) + "\n"


def namespace_state() -> dict[str, dict[str, Any]]:
    """Return per scale namespace its global addresses, routes and handshakes."""
    output = conftest.run_cmd(HOST, f"bash {STATE_SCRIPT}")
    result: dict[str, dict[str, Any]] = {}
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("# "):
            ni = lines[i][2:]
            addresses, routes4, routes6 = (json.loads(x) for x in lines[i + 1 : i + 4])
            result[ni] = {
                "addresses": {
                    link["ifname"]: {
                        f"{a['local']}/{a['prefixlen']}"
                        for a in link["addr_info"]
                        if a.get("scope") == "global"
                    }
                    for link in addresses
                },
                "routes": {route["dst"] for route in [*routes4, *routes6]},
                "handshakes": set(),
            }
            i += 4
            continue
        if lines[i].startswith("W "):
            _, ni, interface, _, timestamp = lines[i].split()
            if int(timestamp):
                result[ni]["handshakes"].add(interface)
        i += 1
    return result


def core_links() -> set[str]:
    """Return the interface names in CORE."""
    output = json.loads(conftest.run_cmd(HOST, "ip --json --netns CORE link"))
    return {link["ifname"] for link in output}


def swanctl_conns() -> set[str]:
    """Return the connections loaded in hub00's charon."""
    output = conftest.run_cmd_shell(HOST, "swanctl --list-conns 2>/dev/null")
    return {line.split(":")[0] for line in output.splitlines() if line[:1].isalnum()}


def established() -> set[str]:
    """Return hub00's connections with an established IKE SA and installed child."""
    output = conftest.run_cmd_shell(HOST, "swanctl --list-sas 2>/dev/null")
    ike = ""
    up: set[str] = set()
    with_child: set[str] = set()
    for line in output.splitlines():
        if line[:1].isalnum():
            ike = line.split(":")[0]
            if "ESTABLISHED" in line:
                up.add(ike)
        elif "INSTALLED" in line:
            with_child.add(ike)
    return up & with_child


def interface_name(name: str, conn: dict[str, Any]) -> str:
    """Return the interface name of a connection, e.g. of C0001-00-0."""
    if conn["config"]["type"] == "wireguard":
        return f"wg-{name}"
    return f"xfrm{name[-1]}"


def connection_problems(
    name: str,
    conn: dict[str, Any],
    current: dict[str, Any],
    conns: set[str],
    sas: set[str] | None,
) -> list[str]:
    """Return what isn't applied (with sas: or up) of a connection."""
    interface = interface_name(name, conn)
    addresses = current["addresses"].get(interface)
    if addresses is None:
        return [f"{name}: no {interface}"]
    problems: list[str] = []
    if not any(":" in a for a in addresses) or all(":" in a for a in addresses):
        problems.append(f"{name}: {interface} lacks addresses ({addresses})")
    routes = {r["to"] for family in conn["routes"].values() for r in family}
    if not_routed := routes - current["routes"]:
        problems.append(f"{name}: no routes {sorted(not_routed)}")
    if conn["config"]["type"] == "wireguard":
        if sas is not None and interface not in current["handshakes"]:
            problems.append(f"{name}: no WireGuard handshake")
    elif name not in conns:
        problems.append(f"{name}: not loaded")
    elif sas is not None and name not in sas:
        problems.append(f"{name}: not established")
    return problems


def missing(network_instances: dict[str, Any], *, tunnels: bool = True) -> list[str]:
    """Return what isn't applied (with tunnels: or up) of the network instances."""
    namespaces = namespace_state()
    links = core_links()
    conns = swanctl_conns()
    sas = established() if tunnels else None
    problems: list[str] = []
    for ni, network_instance in network_instances.items():
        if ni not in namespaces:
            problems.append(f"{ni}: no namespace")
            continue
        if f"{ni}_C" not in links:
            problems.append(f"{ni}: no link in CORE")
        for connection_id, conn in network_instance["connections"].items():
            problems += connection_problems(
                f"{ni}-{connection_id}",
                conn,
                namespaces[ni],
                conns,
                sas,
            )
    return problems


def removed() -> list[str]:
    """Return what is left of the scale tenants."""
    namespaces = set(namespace_state())
    links = core_links()
    conns = swanctl_conns()
    left = sorted(namespaces & set(NETWORK_INSTANCES))
    left += sorted(f"CORE {ni}_C" for ni in NETWORK_INSTANCES if f"{ni}_C" in links)
    left += sorted(c for c in conns if c[:8] in NETWORK_INSTANCES)
    return left


def wait_for_none(check: Callable[[], list[str]], timeout: float, what: str) -> float:
    """Wait until check reports no problems; return the seconds it took."""
    start = time.monotonic()
    problems: list[str] = []
    while time.monotonic() - start < timeout:
        try:
            problems = check()
        except Exception as exc:  # noqa: BLE001
            problems = [repr(exc)]
        if not problems:
            return time.monotonic() - start
        time.sleep(2)
    msg = f"Timed out after {timeout}s waiting for {what}: {len(problems)} left"
    msg += f", e.g. {problems[:5]}"
    raise TimeoutError(msg)


def vpnc_cpu_seconds() -> float:
    """Return the CPU time vpnc used so far (user and system)."""
    output = conftest.run_cmd_shell(
        HOST,
        "bash -c 'cat /proc/$(pgrep -f bin/vpnc$)/stat; getconf CLK_TCK'",
    )
    stat, ticks = output.splitlines()
    fields = stat.rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / int(ticks)


@pytest.fixture(scope="module", autouse=True)
def scale_tenants_applied() -> Iterator[None]:
    """Set up peer00, add the scale tenants and remove them afterwards."""
    conftest.wait_until(
        lambda: "CORE-0" in established(),
        timeout=LAB_TIMEOUT,
        message=f"{HOST}'s CORE connection to be up",
    )
    conftest.write_file(PEER, "/tmp/scale_setup.sh", peer_setup_script())  # noqa: S108
    conftest.run_cmd(PEER, "bash /tmp/scale_setup.sh")

    conftest.write_file(HOST, STATE_SCRIPT, STATE_SCRIPT_CONTENT)
    for tenant in TENANT_CONFIG.values():
        write_tenant(tenant)
    took = wait_for_none(
        lambda: missing(NETWORK_INSTANCES, tunnels=False),
        APPLY_TIMEOUT,
        "the scale tenants to be applied",
    )
    print(f"Applied {len(NETWORK_INSTANCES)} network instances in {took:.0f}s.")  # noqa: T201
    # Like customers, peer00 starts once hub00 has the connections: charon doesn't
    # retry after a failed authentication.
    conftest.write_file(PEER, "/etc/swanctl/conf.d/scale.conf", peer_swanctl())
    conftest.run_cmd_shell(PEER, "swanctl --load-all")
    took = wait_for_none(
        lambda: missing(NETWORK_INSTANCES),
        APPLY_TIMEOUT,
        "the scale tunnels to be up",
    )
    print(f"Tunnels up {took:.0f}s later.")  # noqa: T201
    yield
    for tenant_id in TENANTS:
        conftest.run_cmd(HOST, f"rm -f {CONFIG_DIR}/{tenant_id}.yaml")
    took = wait_for_none(removed, REMOVE_TIMEOUT, "the scale tenants to be removed")
    print(f"Removed the scale tenants in {took:.0f}s.")  # noqa: T201


class TestScale:
    """With 200 network instances and 300 tunnels, vpnc stays responsive."""

    def test_idle_cpu(self) -> None:
        """Report the CPU vpnc uses when nothing changes (no limit)."""
        time.sleep(SETTLE)
        before = vpnc_cpu_seconds()
        time.sleep(CPU_SAMPLE)
        used = (vpnc_cpu_seconds() - before) / CPU_SAMPLE
        print(f"vpnc used {used:.1%} of one core.")  # noqa: T201

    def test_change_applied_quickly(self) -> None:
        """A route change in the last network instance is applied within seconds."""
        ni = f"{TENANTS[-1]}-{NIS_PER_TENANT - 1:02d}"
        tenant = yaml.safe_load(yaml.safe_dump(TENANT_CONFIG[TENANTS[-1]]))
        changed = tenant["network_instances"][ni[-2:]]
        changed["connections"][0]["routes"]["ipv4"].append({"to": "10.199.0.0/24"})
        write_tenant(tenant)
        try:
            took = wait_for_none(
                lambda: missing({ni: changed}, tunnels=False),
                CHANGE_TIMEOUT,
                "the route change to be applied",
            )
            print(f"Applied the change in {took:.1f}s.")  # noqa: T201
        finally:
            write_tenant(TENANT_CONFIG[TENANTS[-1]])

    def test_drift_corrected(self) -> None:
        """A deleted XFRM interface is recreated and its tunnel is up again."""
        # The first network instance from the middle with an IPsec connection 0.
        ni = next(
            ni
            for ni, network_instance in list(NETWORK_INSTANCES.items())[100:]
            if network_instance["connections"][0]["config"]["type"] == "ipsec"
        )
        conftest.run_cmd(HOST, f"ip --netns {ni} link del xfrm0")
        took = wait_for_none(
            lambda: missing({ni: NETWORK_INSTANCES[ni]}),
            DRIFT_TIMEOUT,
            "the deleted interface to be recreated",
        )
        print(f"Corrected the drift in {took:.0f}s.")  # noqa: T201

    def test_outage_recovery(self) -> None:
        """After an outage longer than dead peer detection, every tunnel comes back."""
        with conftest.nft_drop(HOST, "EXTERNAL", f"ip6 saddr {PEER_PREFIX}"):
            time.sleep(OUTAGE)
            down = sum(not is_wireguard(i) for i in INDEXES.values()) - len(
                established() & set(INDEXES),
            )
            print(f"{down} IPsec tunnels down at the end of the outage.")  # noqa: T201
        assert down, "The outage didn't bring any tunnel down"
        took = wait_for_none(
            lambda: missing(NETWORK_INSTANCES),
            RECOVER_TIMEOUT,
            "the tunnels to recover",
        )
        print(f"Recovered in {took:.0f}s.")  # noqa: T201

    def test_vpnctl_responsive(self) -> None:
        """vpnctl shows status, every connection and an NI's logs within seconds."""
        ni = f"{TENANTS[-1]}-{NIS_PER_TENANT - 1:02d}"
        for command in (
            "vpnctl status",
            "vpnctl connections list",
            "vpnctl connections list -o wide",
            f"vpnctl logs --ni {ni} -n 50",
        ):
            started = time.monotonic()
            conftest.run_cmd(HOST, command)
            took = time.monotonic() - started
            print(f"{command}: {took:.1f}s")  # noqa: T201
            assert took < VPNCTL_TIMEOUT, f"{command} took {took:.1f}s"
        connections = json.loads(
            conftest.run_cmd(HOST, "vpnctl connections list -o json"),
        )
        up = [
            c for c in connections if c["tenant"] in TENANTS and c["state"] == "up"
        ]
        assert len(up) == len(INDEXES)

    def test_all_still_applied(self) -> None:
        """After the changes, every network instance is still complete."""
        assert not missing(NETWORK_INSTANCES)
