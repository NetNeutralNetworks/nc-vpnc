#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

for i in {candidate,active};
do
    cp -f ${SCRIPTDIR}/DEFAULT.yaml /opt/ncubed/config/vpnc/${i}/DEFAULT.yaml
    cp -f ${SCRIPTDIR}/C0001.yaml /opt/ncubed/config/vpnc/${i}/C0001.yaml
done

# The key of the SSH connection.
install -m 600 -o vpnc-ssh -g vpnc-ssh ${SCRIPTDIR}/id_ed25519 /var/lib/vpnc-ssh/.ssh/C0001-00-1

exec ${SCRIPTDIR}/../init.sh eth1
