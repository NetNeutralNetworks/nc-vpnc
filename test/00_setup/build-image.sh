#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

docker build -f ${SCRIPTDIR}/../../docker/24.04/Dockerfile ${SCRIPTDIR}/../../ -t nc-vpnc:latest
