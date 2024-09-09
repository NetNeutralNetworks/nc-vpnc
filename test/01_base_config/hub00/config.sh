#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# # Run the normal installer in hub mode
# ${SCRIPTDIR}/../../../install.sh hub
for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/DEFAULT.yaml /opt/ncubed/config/vpnc/${i}/DEFAULT.yaml
    cp -f ${SCRIPTDIR}/C0001.yaml /opt/ncubed/config/vpnc/${i}/C0001.yaml
done

cp -f ${SCRIPTDIR}/id_ed25519 /root/.ssh/
chmod 600 /root/.ssh/id_ed25519

# If systemd is NOT the init system
if [ "$(ps -p 1 -o comm=)" != "systemd" ]; then
    /opt/ncubed/vpnc/bin/vpnc
fi
# /usr/lib/frr/frrinit.sh start
