#! /bin/bash
# Build the vpnc and lab images for an Ubuntu version (default 26.04).
# Usage: build-image.sh [26.04]
set -euo pipefail
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
VERSION="${1:-26.04}"
DOCKERFILE=${SCRIPTDIR}/../../docker/${VERSION}/Dockerfile

docker build -f ${DOCKERFILE} ${SCRIPTDIR}/../../ --target vpnc \
  -t nc-vpnc:${VERSION} -t nc-vpnc:latest
docker build -f ${DOCKERFILE} ${SCRIPTDIR}/../../ --target lab \
  -t nc-vpnc-lab:${VERSION} -t nc-vpnc-lab:latest
