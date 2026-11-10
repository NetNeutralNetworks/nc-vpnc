#! /bin/bash
# Deploy the scale lab next to the normal lab (as root).
# Usage: deploy-scale.sh [24.04|26.04]  (default: the last built image)
set -euo pipefail
cd "$(dirname -- "$BASH_SOURCE")"
export VPNC_VERSION="${1:-latest}"

if ! ip link show br-vpnc-scale &> /dev/null; then
    ip link add br-vpnc-scale type bridge
    ip link set br-vpnc-scale up
fi
containerlab deploy -t scale.clab.yaml --reconfigure
