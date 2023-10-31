#! /bin/bash

SERVICENAME=vpnc
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
BASEDIR=/opt/ncubed
INSTALLDIR=${BASEDIR}/${SERVICENAME}

function install_apt {
    # update and install general packages
    apt update
    apt install -y python3-dev python3-pip python3-venv strongswan strongswan-swanctl build-essential libnetfilter-queue-dev

    # add FRR GPG key
    curl -s https://deb.frrouting.org/frr/keys.asc | sudo apt-key add -

    # possible values for FRRVER: frr-6 frr-7 frr-8 frr-stable
    # frr-stable will be the latest official stable release
    FRRVER="frr-8"
    echo deb https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER | sudo tee /etc/apt/sources.list.d/frr.list

    # update and install FRR and NAT64 (jool)
    apt update
    apt install -y jool-tools frr frr-pythontools frr-snmp

}

case $1 in
hub)
    echo "Installing in hub mode"

    install_apt

    # Configure FRR daemon
    sed -i 's/^bgpd=no$/bgpd=yes/' /etc/frr/daemons
    sed -i 's/^bfdd=no$/bfdd=yes/' /etc/frr/daemons

    sed -i 's/^zebra_options="  -A 127.0.0.1 -s 90000000.*"$/zebra_options="  -A 127.0.0.1 -s 90000000 -n -M snmp"/' /etc/frr/daemons
    sed -i 's/^bgpd_options="   -A 127.0.0.1.*"$/bgpd_options="   -A 127.0.0.1 -M snmp"/' /etc/frr/daemons
    # Enable the FRR service
    /usr/bin/systemctl enable frr.service
    ;;
endpoint)
    echo "Installing in endpoint mode"

    install_apt

    ;;
*)
    echo "Argument should be either 'hub' or 'endpoint'"
    exit 1
    ;;
esac

# Create directories if not exist
mkdir -p ${BASEDIR}/config
mkdir -p ${INSTALLDIR}

# Copy configuration files over to the configuration directories.
cp -rf ${SCRIPTDIR}/etc/* /etc/
cp -rf ${SCRIPTDIR}/config/* ${BASEDIR}/config/

# Remove old code if exist.
rm -rf ${INSTALLDIR}/

# Install new code
python3 -m venv ${INSTALLDIR}
${INSTALLDIR}/bin/python3 -m pip install --upgrade pip setuptools wheel
${INSTALLDIR}/bin/python3 -m pip install --upgrade ${SCRIPTDIR}/${SERVICENAME}

# Add VPNCTL to path
cp -s ${INSTALLDIR}/bin/vpnctl /usr/local/bin

# Disable the IPsec service
/usr/bin/systemctl disable ipsec.service
/usr/bin/systemctl stop ipsec.service

# Configure SNMP daemon
sed -i -E 's/^rocommunity (.*)/#rocommunity \1/' /etc/snmp/snmpd.conf
sed -i -E 's/^rocommunity6 (.*)/#rocommunity6 \1/' /etc/snmp/snmpd.conf
sed -i -E 's/^agentaddress(.*)/#agentaddress\1/' /etc/snmp/snmpd.conf
sed -i 's/^rouser authPrivUser authpriv -V systemonly$/#rouser authPrivUser authpriv -V systemonly/' /etc/snmp/snmpd.conf

# Enable the SNMP service
/usr/bin/systemctl enable snmpd.service
/usr/bin/systemctl restart snmpd.service

# It's important to have the link have the same name as the desired service, otherwise the symlink won't work.
/usr/bin/systemctl stop ncubed-${SERVICENAME}.service
/usr/bin/systemctl disable ncubed-${SERVICENAME}.service

/usr/bin/systemctl link ${BASEDIR}/config/vpnc/units/ncubed-${SERVICENAME}.service

cp -n ${BASEDIR}/config/${SERVICENAME}/candidate/service/config-$1.yaml.example \
    ${BASEDIR}/config/${SERVICENAME}/candidate/service/config.yaml
cp -n ${BASEDIR}/config/${SERVICENAME}/candidate/service/config-$1.yaml.example \
    ${BASEDIR}/config/${SERVICENAME}/active/service/config.yaml

# Run migrations to current version
${SCRIPTDIR}/setup/migrate.sh

# Enable the VPNC service
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable ncubed-${SERVICENAME}
/usr/bin/systemctl restart ncubed-${SERVICENAME}

# Add the default profile for the service
cp ${SCRIPTDIR}/setup/profile-nc-vpn.sh /etc/profile.d/

echo "Configure SNMP with the following command (if not already configured) after stopping the snmpd service."
echo "The space in front of the command makes sure it isn't logged into the Bash history."
echo " net-snmp-create-v3-user -ro -a SHA -A <authpass> -x AES -X <privpass> nc-snmp"
