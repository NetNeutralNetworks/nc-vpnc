#! /bin/bash
# Deploy the base lab (as root).
# Usage: deploy-base.sh [26.04]  (default: the last built image)
set -euo pipefail
cd "$(dirname -- "$BASH_SOURCE")"
export VPNC_VERSION="${1:-latest}"

containerlab deploy -t base.clab.yaml --reconfigure
