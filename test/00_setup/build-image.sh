#! /bin/bash
# Build the vpnc and lab images for an Ubuntu version (default 26.04).
# Usage: build-image.sh [26.04]
set -euo pipefail
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
VERSION="${1:-26.04}"
DOCKERFILE=${SCRIPTDIR}/../../docker/${VERSION}/Dockerfile

# The docker format keeps SHELL. The host's network: Docker's firewall, where
# installed, drops what podman's network forwards.
build() {
  podman build --format docker --network host -f ${DOCKERFILE} ${SCRIPTDIR}/../../ \
    --target "$1" -t "$2:${VERSION}" -t "$2:latest"
}
build vpnc nc-vpnc
build lab nc-vpnc-lab
