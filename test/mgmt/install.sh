#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# Copy the script to setup the management server and the service file that runs it to the correct
# locations.
mkdir -p /opt/ncubed/vpnc/units/
cp -rf ${SCRIPTDIR}/ncubed-vpnc-mgmt-test.sh /opt/ncubed/vpnc/ncubed-vpnc-mgmt-test.sh
cp -rf ${SCRIPTDIR}/ncubed-vpnc-mgmt-test.service /opt/ncubed/vpnc/units/ncubed-vpnc-mgmt-test.service

# Enable and start the service. This allows the survival of reboots
/usr/bin/systemctl link /opt/ncubed/vpnc/units/ncubed-vpnc-mgmt-test.service
/usr/bin/systemctl enable ncubed-vpnc-mgmt-test.service
/usr/bin/systemctl restart ncubed-vpnc-mgmt-test.service
