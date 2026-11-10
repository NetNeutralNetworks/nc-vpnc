#! /bin/bash
# Print the state of the containerlab lab to diagnose failures, e.g. in CI.
# Usage: sudo test/00_setup/diagnostics.sh

section() { echo "::group::$*"; }
endsection() { echo "::endgroup::"; }
in_node() { docker exec "clab-vpnc-$1" bash -c "$2" 2>&1; }

uname -a
lsmod | grep -E '^(jool|xfrm|wireguard)' || true
docker ps -a

for c in $(docker ps -a --format '{{.Names}}' | grep '^clab-vpnc-' | sort); do
  section "${c} logs"
  docker inspect --format 'restarts={{.RestartCount}} state={{.State.Status}} exit={{.State.ExitCode}}' "${c}"
  docker logs --tail 300 "${c}" 2>&1
  docker exec "${c}" tail -n 300 /var/log/ncubed/vpnc/vpnc.log 2>/dev/null || true
  endsection
done

for h in hub00 hub01; do
  docker inspect "clab-vpnc-${h}" &> /dev/null || continue
  section "${h} state"
  in_node "${h}" 'swanctl --list-sas 2>/dev/null | grep -E "^[A-Za-z0-9-]+: #"'
  for ni in CORE C0001-00 C0001-01; do
    echo "--- ${ni} links/routes"
    in_node "${h}" "ip -n ${ni} -br link; ip -n ${ni} route; ip -n ${ni} -6 route"
  done
  echo "--- C0001-01 wireguard"
  in_node "${h}" 'ip netns exec C0001-01 wg show'
  echo "--- CORE nftables (vpnc table, vpncmangle queue)"
  in_node "${h}" 'ip netns exec CORE nft list ruleset'
  echo "--- vpncmangle translations.json"
  in_node "${h}" 'cat /opt/ncubed/config/vpncmangle/translations.json; echo'
  echo "--- vpncmangle.log"
  in_node "${h}" 'tail -n 200 /var/log/ncubed/vpnc/vpncmangle.log'
  echo "--- BGP"
  in_node "${h}" 'vtysh -c "show bgp vrf CORE summary"'
  endsection
done

for h in end00 end01; do
  section "${h} state"
  in_node "${h}" 'swanctl --list-sas 2>/dev/null | grep -E "^[A-Za-z0-9-]+: #"'
  in_node "${h}" 'for ni in CORE ENDPOINT; do echo "--- ${ni}"; ip -n ${ni} -br addr; ip -n ${ni} route; ip -n ${ni} -6 route; done'
  in_node "${h}" 'ip netns exec CORE wg show'
  endsection
done

for h in mgt00 mgt01; do
  section "${h} state"
  in_node "${h}" 'swanctl --list-sas 2>/dev/null | grep -E "^[A-Za-z0-9-]+: #"'
  in_node "${h}" 'vtysh -c "show bgp ipv6 unicast summary"; vtysh -c "show bgp ipv6 unicast"'
  in_node "${h}" 'ip -6 route'
  endsection
done
