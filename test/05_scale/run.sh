#! /bin/bash
# Deploy the scale lab next to the normal lab and run its tests (as root).
# Usage: run.sh [24.04|26.04] [pytest arguments]
set -euo pipefail
cd "$(dirname -- "$BASH_SOURCE")"
export VPNC_VERSION="${1:-26.04}"
shift || true

if ! ip link show br-vpnc-scale &> /dev/null; then
    ip link add br-vpnc-scale type bridge
    ip link set br-vpnc-scale up
fi
containerlab deploy -t scale.clab.yaml --reconfigure
python3 -m pytest -p no:cacheprovider -q scale_tests "$@"
