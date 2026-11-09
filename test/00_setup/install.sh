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
# GitHub runners ship Docker; a fresh VM doesn't.
if ! command -v docker > /dev/null; then
  apt-get install -y docker.io
fi
if [[ -n "${SUDO_USER}" ]]; then
  usermod -aG docker "${SUDO_USER}"
fi
fi

# Install the Jool kernel module on the host so it's available in containers.
# Ubuntu 26.04 (kernel 7.0) ships jool-dkms 4.1.15; the 4.1.11 deb from GitHub
# doesn't target that kernel. The 4.1.11 jool-tools inside the noble-based
# image work with the 4.1.15 module.
source /etc/os-release
if [[ "${VERSION_ID}" == "24.04" ]]; then
  wget https://github.com/NICMx/Jool/releases/download/v4.1.11/jool-dkms_4.1.11-1_all.deb -O /tmp/jool-dkms_4.1.11-1_all.deb
  apt-get install -y /tmp/jool-dkms_4.1.11-1_all.deb
else
  apt-get install -y jool-dkms jool-tools
fi
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
