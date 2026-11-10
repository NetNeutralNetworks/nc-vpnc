#! /bin/bash
# hub00 of the scale lab: the normal lab's DEFAULT configuration, no tenants. The
# scale tests add those.
BASE="$(dirname -- "$BASH_SOURCE")/../../lab/hub00"
for i in candidate active; do
    cp -f "${BASE}/DEFAULT.yaml" "/opt/ncubed/config/vpnc/${i}/DEFAULT.yaml"
done

if [ "$(ps -p 1 -o comm=)" != "systemd" ]; then
    /opt/ncubed/vpnc/bin/vpnc
fi
