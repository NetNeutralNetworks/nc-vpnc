#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/DEFAULT.yaml /opt/ncubed/config/vpnc/${i}/DEFAULT.yaml
done

exec ${SCRIPTDIR}/../init.sh eth1 eth2
