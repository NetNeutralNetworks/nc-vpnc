#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
apt update
apt install -y strongswan strongswan-swanctl jool-tools python3-watchdog python3-venv

cp -r $SCRIPTDIR/etc/* /etc/
cp -r $SCRIPTDIR/opt/* /opt/
python3 -m venv /opt/ncubed/.venv
/opt/ncubed/.venv/bin/python3 -m pip install vici watchdog

/opt/ncubed/vpnc.service/install.sh
