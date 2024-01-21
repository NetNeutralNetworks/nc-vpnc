#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/service.config.yaml /opt/ncubed/config/vpnc/${i}/service/config.yaml
    cp -f ${SCRIPTDIR}/remote.c0001.yaml /opt/ncubed/config/vpnc/${i}/remote/c0001.yaml
done

# Run the normal installer in endpoint mode
${SCRIPTDIR}/../../install.sh endpoint

/usr/bin/systemctl restart ncubed-vpnc.service
