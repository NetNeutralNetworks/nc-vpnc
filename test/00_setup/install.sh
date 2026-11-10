#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

apt-get update
# Don't update in GitHub actions as it saves a lot of time
if [[ -z "${GITHUB_ACTIONS}" ]]; then
apt-get upgrade -y
fi
apt-get install -y bridge-utils python3-pytest python3-yaml
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
# The containers only ship jool-tools; userspace 4.1.x works with any 4.1.x module.
# Ubuntu 26.04 ships jool-dkms 4.1.15. On 24.04 use the 4.1.15 release from
# GitHub: the distro and older releases (e.g. 4.1.11) don't build on newer
# kernels such as the 7.0 HWE kernel on GitHub's ubuntu-24.04 runners.
JOOL_VERSION="4.1.15"
apt-get install -y "linux-headers-$(uname -r)"
source /etc/os-release
if [[ "${VERSION_ID}" == "24.04" ]]; then
  wget "https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-dkms_${JOOL_VERSION}-1_all.deb" \
    -O "/tmp/jool-dkms_${JOOL_VERSION}-1_all.deb"
  apt-get install -y "/tmp/jool-dkms_${JOOL_VERSION}-1_all.deb"
else
  apt-get install -y jool-dkms jool-tools
fi
# Fail here instead of later in the lab when the module didn't build.
if ! modprobe jool; then
  echo "ERROR: could not load the Jool kernel module for kernel $(uname -r)." >&2
  dkms status >&2 || true
  exit 1
fi

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
