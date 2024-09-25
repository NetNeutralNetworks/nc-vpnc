#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

apt-get update
# Don't update in GitHub actions as it saves a lot of time
if [[ -z "${GITHUB_ACTIONS}" ]]; then
apt-get upgrade -y
fi
apt-get install -y bridge-utils python3-pytest
# jool-tools

if [[ -z "${GITHUB_ACTIONS}" ]]; then
apt-get install -y docker-compose-v2 docker-buildx wireguard
fi

# Install the Jool kernel module on the host so it's available in containers.
# if [[ "$(lsb_release -r | awk '{ print $2; }')" == "22.04" ]]; then
# wget https://github.com/NICMx/Jool/releases/download/v4.1.7/jool-dkms_4.1.7-1_all.deb -O /tmp/jool-dkms_4.1.7-1_all.deb
# apt-get install -y /tmp/jool-dkms_4.1.7-1_all.deb
# elif [[ "$(lsb_release -r | awk '{ print $2; }')" == "24.04" ]]; then
# wget https://github.com/NICMx/Jool/releases/download/v4.1.11/jool-dkms_4.1.11-1_all.deb -O /tmp/jool-dkms_4.1.11-1_all.deb
# apt-get install -y /tmp/jool-dkms_4.1.11-1_all.deb
# fi
wget https://github.com/NICMx/Jool/releases/download/v4.1.11/jool-dkms_4.1.11-1_all.deb -O /tmp/jool-dkms_4.1.11-1_all.deb
apt-get install -y /tmp/jool-dkms_4.1.11-1_all.deb
modprobe jool

# Install containerlab
bash -c "$(curl -sL https://get.containerlab.dev)"

# Add a network bridge for containerlab intra-container "internet" communication
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
