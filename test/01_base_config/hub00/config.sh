#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# # Run the normal installer in hub mode
# ${SCRIPTDIR}/../../../install.sh hub

for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/service.config.yaml /opt/ncubed/config/vpnc/${i}/service/config.yaml
    cp -f ${SCRIPTDIR}/tenant.c0001.yaml /opt/ncubed/config/vpnc/${i}/tenant/c0001.yaml
done

# If systemd is NOT the init system
if [ "$(ps -p 1 -o comm=)" != "systemd" ]; then
    /opt/ncubed/vpnc/bin/vpnc
fi
# /usr/lib/frr/frrinit.sh start
