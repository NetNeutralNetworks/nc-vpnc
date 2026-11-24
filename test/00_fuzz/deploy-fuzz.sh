#! /bin/bash
# Deploy the fuzz lab next to the base lab (as root).
# Usage: deploy-fuzz.sh [26.04]  (default: the last built image)
set -euo pipefail
cd "$(dirname -- "$BASH_SOURCE")"
export VPNC_VERSION="${1:-latest}"

if ! ip link show br-vpnc-fuzz &> /dev/null; then
    ip link add br-vpnc-fuzz type bridge
    ip link set br-vpnc-fuzz up
fi
mkdir -p /run/vpnc-fuzz-hub00
../00_setup/apparmor.sh "localhost/nc-vpnc:${VPNC_VERSION}"
containerlab deploy --runtime podman -t fuzz.clab.yaml --reconfigure
