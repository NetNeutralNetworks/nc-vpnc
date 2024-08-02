#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

# Install containerlab repo
echo "deb [trusted=yes] https://netdevops.fury.site/apt/ /" | \
  sudo tee -a /etc/apt/sources.list.d/netdevops.list

apt-get update
apt-get upgrade -y
apt-get install -y bridge-utils \
  docker-compose-v2 docker-buildx \
  containerlab
  # jool-tools

# Install the Jool kernel module on the host so it's available in containers.
wget https://github.com/NICMx/Jool/releases/download/v4.1.11/jool-dkms_4.1.11-1_all.deb -O /tmp/jool-dkms_4.1.11-1_all.deb
apt-get install -y /tmp/jool-dkms_4.1.11-1_all.deb
modprobe jool


echo "
network:
  version: 2
  renderer: networkd

  bridges:
    br-nc-vpnc:
      mtu: 1500
      parameters:
        stp: true
        forward-delay: 4
" > /etc/netplan/10-clab.yaml
chmod 600 /etc/netplan/10-clab.yaml
# This may cause some disruption
netplan apply -v

if [ -f /var/run/reboot-required ]; then
  echo 'Reboot required!'
fi
