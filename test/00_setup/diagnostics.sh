#! /bin/bash
# Print the state of a containerlab lab to diagnose failures, e.g. in CI. What
# each node shows depends on what it runs: vpnc (hub, endpoint), FRR (mgt),
# only charon (peer) or none of these (other).
# Usage: sudo test/00_setup/diagnostics.sh [vpnc|vpnc-scale|vpnc-fuzz]  (default vpnc)
LAB="${1:-vpnc}"

section() { echo "::group::$*"; }
endsection() { echo "::endgroup::"; }
in_node() { docker exec "$1" bash -c "$2" 2>&1; }
sas() { in_node "$1" 'swanctl --list-sas 2>/dev/null | grep -E "^[A-Za-z0-9-]+: #"'; }

node_kind() {
  in_node "$1" '
    if pgrep -x vpnc > /dev/null; then
      sed -n "s/^mode: *//p" /opt/ncubed/config/vpnc/active/DEFAULT.yaml | tr A-Z a-z
    elif pgrep -x bgpd > /dev/null; then echo mgt
    elif pgrep -x charon > /dev/null; then echo peer
    else echo other
    fi'
}

# Links, addresses, routes, WireGuard and nftables of every network namespace.
namespaces() {
  in_node "$1" '
    for ns in $(ip netns list | cut -d" " -f1 | sort); do
      echo "--- ${ns}"
      ip -n "${ns}" -br link; ip -n "${ns}" -br addr
      ip -n "${ns}" route; ip -n "${ns}" -6 route
      ip netns exec "${ns}" wg show 2> /dev/null
      ip netns exec "${ns}" nft list ruleset
    done'
}

hub() {
  in_node "$1" 'vpnctl status; vpnctl -o wide connections list; vpnctl config list'
  sas "$1"
  namespaces "$1"
  echo "--- vpncmangle translations.json"
  in_node "$1" 'cat /opt/ncubed/config/vpncmangle/translations.json; echo'
  echo "--- vpncmangle's log"
  in_node "$1" 'journalctl --no-pager -n 200 -t vpncmangle'
  echo "--- BGP"
  in_node "$1" 'vtysh -c "show bgp vrf CORE summary"'
  echo "--- events"
  in_node "$1" 'vpnctl events | tail -100'
}

endpoint() {
  in_node "$1" 'vpnctl status; vpnctl -o wide connections list'
  sas "$1"
  namespaces "$1"
  echo "--- events"
  in_node "$1" 'vpnctl events | tail -100'
}

mgt() {
  sas "$1"
  in_node "$1" 'vtysh -c "show bgp ipv6 unicast summary"; vtysh -c "show bgp ipv6 unicast"'
  in_node "$1" 'ip -br addr; ip route; ip -6 route'
}

peer() {
  in_node "$1" 'echo "$(swanctl --list-sas 2> /dev/null | grep -cE "^[A-Za-z0-9-]+: #") IKE SAs"'
  in_node "$1" 'ip -br addr; wg show 2> /dev/null'
}

other() {
  in_node "$1" 'ip -br addr; ip route; ip -6 route'
}

uname -a
lsmod | grep -E '^(jool|xfrm|wireguard)' || true
docker ps -a --filter "label=containerlab=${LAB}"

for c in $(docker ps -a --filter "label=containerlab=${LAB}" --format '{{.Names}}' | sort); do
  section "${c} logs"
  docker inspect --format 'restarts={{.RestartCount}} state={{.State.Status}} exit={{.State.ExitCode}}' "${c}"
  docker logs --tail 300 "${c}" 2>&1
  docker exec "${c}" journalctl --no-pager -n 300 -t vpnc 2>/dev/null || true
  endsection
  [[ "$(docker inspect --format '{{.State.Running}}' "${c}")" == true ]] || continue
  kind="$(node_kind "${c}")"
  section "${c} state (${kind})"
  case "${kind}" in
    hub | endpoint | mgt | peer) "${kind}" "${c}" ;;
    *) other "${c}" ;;
  esac
  endsection
done
