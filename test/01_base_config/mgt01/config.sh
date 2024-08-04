#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# Copy the script to setup the management server and the service file that runs it to the correct
# locations.
mkdir -p /opt/ncubed/vpnc/units/
cp -rf ${SCRIPTDIR}/ncubed-vpnc-mgt-test.sh /opt/ncubed/vpnc/ncubed-vpnc-mgt-test.sh
cp -rf ${SCRIPTDIR}/ncubed-vpnc-mgt-test.service /opt/ncubed/vpnc/units/ncubed-vpnc-mgt-test.service

# If systemd is the init system
if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
    # Enable and start the service. This allows the survival of reboots
    /usr/bin/systemctl link /opt/ncubed/vpnc/units/ncubed-vpnc-mgt-test.service
    /usr/bin/systemctl enable ncubed-vpnc-mgt-test.service
    /usr/bin/systemctl restart ncubed-vpnc-mgt-test.service
else
    /opt/ncubed/vpnc/ncubed-vpnc-mgt-test.sh
fi
