#! /bin/bash
# Build the vpnc lab image for an Ubuntu version (default 24.04).
# Tags it as nc-vpnc:<version> and nc-vpnc:latest. The lab topology uses
# ${VPNC_IMAGE}, defaulting to nc-vpnc:latest, i.e. the image built last.
#
# Usage: build-image.sh [24.04|26.04]
set -euo pipefail
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
VERSION="${1:-24.04}"

docker build -f "${SCRIPTDIR}/../../docker/${VERSION}/Dockerfile" "${SCRIPTDIR}/../../" \
  -t "nc-vpnc:${VERSION}" -t nc-vpnc:latest
