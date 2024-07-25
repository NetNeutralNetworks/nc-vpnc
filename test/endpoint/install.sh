#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# Run the normal installer in endpoint mode
${SCRIPTDIR}/../../install.sh endpoint

for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/service.config.yaml /opt/ncubed/config/vpnc/${i}/service/config.yaml
    cp -f ${SCRIPTDIR}/tenant.e0001.yaml /opt/ncubed/config/vpnc/${i}/tenant/e0001.yaml
done

/usr/bin/systemctl restart ncubed-vpnc.service
