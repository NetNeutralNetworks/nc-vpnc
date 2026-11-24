#! /bin/bash
# Deploy the base lab (as root).
# Usage: deploy-base.sh [26.04]  (default: the last built image)
set -euo pipefail
cd "$(dirname -- "$BASH_SOURCE")"
export VPNC_VERSION="${1:-latest}"

../00_setup/apparmor.sh "localhost/nc-vpnc:${VPNC_VERSION}"
containerlab deploy --runtime podman -t base.clab.yaml --reconfigure
