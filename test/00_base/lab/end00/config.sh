#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# # Run the normal installer in endpoint mode
# make -C ${SCRIPTDIR}/../../../.. endpoint

for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/DEFAULT.yaml /opt/ncubed/config/vpnc/${i}/DEFAULT.yaml
done

${SCRIPTDIR}/../snmpd.sh
${SCRIPTDIR}/../journald.sh

# containerlab adds the links after the container starts, also after a
# restart: vpnc takes them over when it starts.
for link in eth1 eth2; do
    until ip link show "${link}" &> /dev/null; do sleep 0.2; done
done

# If systemd is the init system
if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
    /usr/bin/systemctl restart ncubed-vpnc.service
else
    # Replaces the shell: the init process (tini) signals vpnc itself.
    exec /opt/ncubed/vpnc/bin/vpnc
fi
