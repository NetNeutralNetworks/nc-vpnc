#! /bin/bash

echo "Running migrations."
# Migration steps
## < 0.0.2
rm -rf /opt/ncubed/vpnc.service
## < 0.0.3
rm -rf /opt/ncubed/vpncservice
rm -rf /opt/ncubed/vpnctl
## < 0.0.4
# remove old profile file
if [ -f /etc/profile.d/nc.sh ]; then
  rm /etc/profile.d/nc.sh
fi

/usr/bin/systemctl stop ncubed-vpnc-hub.service
/usr/bin/systemctl disable ncubed-vpnc-hub.service
/usr/bin/systemctl stop ncubed-vpnc-endpoint.service
/usr/bin/systemctl disable ncubed-vpnc-endpoint.service

rm /opt/ncubed/config/vpnc/units/ncubed-vpnc-hub.service
rm /opt/ncubed/config/vpnc/units/ncubed-vpnc-endpoint.service

# Remove the units if disable failed somehow to remove the unit file.
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl reset-failed
