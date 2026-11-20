#! /bin/bash
# Install what the labs need on the host (as root): Docker, containerlab, the
# Jool module, the bridge of the base lab and the test tools.
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

apt-get update
# Don't update in GitHub actions as it saves a lot of time
if [[ -z "${GITHUB_ACTIONS}" ]]; then
apt-get upgrade -y
fi
# python3-hypothesis: the fuzz tests (04_fuzz).
apt-get install -y bridge-utils python3-pytest python3-yaml python3-hypothesis
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
# JOOL_MODULES: a folder with the module built for this kernel (CI caches it);
# without one there, it's built and put there.
MODULES="/lib/modules/$(uname -r)/updates/dkms"
if [[ -n "${JOOL_MODULES}" ]] && compgen -G "${JOOL_MODULES}/jool*.ko*" > /dev/null; then
  # Not jool-dkms, which jool-tools recommends: it would build the module.
  apt-get install -y --no-install-recommends jool-tools
  mkdir -p "${MODULES}"
  cp "${JOOL_MODULES}"/jool*.ko* "${MODULES}/"
  depmod -a
else
  apt-get install -y "linux-headers-$(uname -r)" jool-dkms jool-tools
  if [[ -n "${JOOL_MODULES}" ]]; then
    mkdir -p "${JOOL_MODULES}"
    cp "${MODULES}"/jool*.ko* "${JOOL_MODULES}/"
  fi
fi
# Fail here instead of later in the lab when the module didn't build.
if ! modprobe jool; then
  echo "ERROR: could not load the Jool kernel module for kernel $(uname -r)." >&2
  dkms status >&2 || true
  exit 1
fi

# Install containerlab, the version the lab is tested with.
bash -c "$(curl -sL https://get.containerlab.dev)" -- -v 0.83.0

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
