#! /bin/bash
# hub00 of the scale lab: the normal lab's DEFAULT configuration, no tenants. The
# scale tests add those.
BASE="$(dirname -- "$BASH_SOURCE")/../../../00_base/lab/hub00"
for i in candidate active; do
    cp -f "${BASE}/DEFAULT.yaml" "/opt/ncubed/config/vpnc/${i}/DEFAULT.yaml"
done

exec "${BASE}/../init.sh" eth1
