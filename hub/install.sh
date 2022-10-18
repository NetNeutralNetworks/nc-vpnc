#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
VENVDIR=/opt/ncubed/vpnc.service/.venv
apt update
apt install -y strongswan strongswan-swanctl jool-tools python3-venv python3-pip

cp -r $SCRIPTDIR/etc/* /etc/
cp -r $SCRIPTDIR/opt/* /opt/
python3 -m venv $VENVDIR
$VENVDIR/bin/python3 -m pip install vici watchdog

/opt/ncubed/vpnc.service/install.sh
