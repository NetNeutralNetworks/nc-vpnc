#! /bin/bash

echo "Running migrations."
# Migration steps
## < 0.0.2
rm -rf /opt/ncubed/vpnc.service
## < 0.0.3
rm -rf /opt/ncubed/vpncservice
rm -rf /opt/ncubed/vpnctl
