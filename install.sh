#! /bin/bash

SERVICENAME=vpnc
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
BASEDIR=/opt/ncubed
INSTALLDIR=${BASEDIR}/${SERVICENAME}
VENVDIR=${INSTALLDIR}/.venv

mkdir -p ${BASEDIR}/config
mkdir -p ${INSTALLDIR}

case $1 in
hub)
    # add FRR GPG key
    curl -s https://deb.frrouting.org/frr/keys.asc | sudo apt-key add -

    # possible values for FRRVER: frr-6 frr-7 frr-8 frr-stable
    # frr-stable will be the latest official stable release
    FRRVER="frr-8"
    echo deb https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER | sudo tee /etc/apt/sources.list.d/frr.list

    # update and install FRR/strongSwan
    apt update
    apt install -y python3-venv python3-pip python3-dev strongswan strongswan-swanctl jool-tools frr frr-pythontools frr-snmp build-essential libnetfilter-queue-dev

    cp -rf $SCRIPTDIR/etc/* /etc/
    cp -rf $SCRIPTDIR/config/* ${BASEDIR}/config/
    cp -rf $SCRIPTDIR/${SERVICENAME}/* ${INSTALLDIR}/

    python3 -m venv $VENVDIR
    $VENVDIR/bin/python3 -m pip install --upgrade pip setuptools wheel
    $VENVDIR/bin/python3 -m pip install ${INSTALLDIR}

    ${INSTALLDIR}/install.sh hub
    ;;
endpoint)
    # update and install strongSwan
    apt update
    apt install -y python3-venv python3-pip strongswan strongswan-swanctl

    cp -rf $SCRIPTDIR/etc/* /etc/
    cp -rf $SCRIPTDIR/config/* ${BASEDIR}/config/
    cp -rf $SCRIPTDIR/${SERVICENAME}/* ${INSTALLDIR}/

    python3 -m venv $VENVDIR
    $VENVDIR/bin/python3 -m pip install --upgrade pip setuptools wheel
    $VENVDIR/bin/python3 -m pip install ${INSTALLDIR}

    ${INSTALLDIR}/install.sh endpoint
    ;;
*)
    echo "Argument should be either 'hub' or 'endpoint'"
    exit 1
    ;;
esac
