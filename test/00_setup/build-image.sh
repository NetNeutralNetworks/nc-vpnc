#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

DOCKERFILE=${SCRIPTDIR}/../../docker/24.04/Dockerfile
docker build -f ${DOCKERFILE} ${SCRIPTDIR}/../../ --target vpnc -t nc-vpnc:latest
docker build -f ${DOCKERFILE} ${SCRIPTDIR}/../../ --target lab -t nc-vpnc-lab:latest
