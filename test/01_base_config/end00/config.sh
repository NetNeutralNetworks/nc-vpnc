#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# # Run the normal installer in endpoint mode
# ${SCRIPTDIR}/../../../install.sh endpoint

for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/DEFAULT.yaml /opt/ncubed/config/vpnc/${i}/DEFAULT.yaml
done

# If systemd is the init system
if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
    /usr/bin/systemctl restart ncubed-vpnc.service
else
    /opt/ncubed/vpnc/bin/vpnc
fi
