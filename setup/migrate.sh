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
