#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# # Run the normal installer in hub mode
# make -C ${SCRIPTDIR}/../../../.. hub
for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/DEFAULT.yaml /opt/ncubed/config/vpnc/${i}/DEFAULT.yaml
    cp -f ${SCRIPTDIR}/C0001.yaml /opt/ncubed/config/vpnc/${i}/C0001.yaml
done

# The key of the SSH connection.
install -m 600 -o vpnc-ssh -g vpnc-ssh ${SCRIPTDIR}/id_ed25519 /var/lib/vpnc-ssh/.ssh/C0001-00-1

${SCRIPTDIR}/../snmpd.sh
${SCRIPTDIR}/../journald.sh

# containerlab adds the links after the container starts, also after a
# restart: vpnc takes them over when it starts.
for link in eth1; do
    until ip link show "${link}" &> /dev/null; do sleep 0.2; done
done

# If systemd is NOT the init system
if [ "$(ps -p 1 -o comm=)" != "systemd" ]; then
    # Replaces the shell: the init process (tini) signals vpnc itself.
    exec /opt/ncubed/vpnc/bin/vpnc
fi
# /usr/lib/frr/frrinit.sh start
