#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
VENVDIR=/opt/ncubed/vpnc.service/.venv

# add FRR GPG key
curl -s https://deb.frrouting.org/frr/keys.asc | sudo apt-key add -

# possible values for FRRVER: frr-6 frr-7 frr-8 frr-stable
# frr-stable will be the latest official stable release
FRRVER="frr-8"
echo deb https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER | sudo tee /etc/apt/sources.list.d/frr.list

# update and install FRR/strongSwan
apt install -y python3-venv python3-pip strongswan strongswan-swanctl jool-tools frr frr-pythontools frr-snmp

cp -rf $SCRIPTDIR/etc/* /etc/
cp -rf $SCRIPTDIR/opt/* /opt/
python3 -m venv $VENVDIR
$VENVDIR/bin/python3 -m pip install jinja2 pyyaml vici watchdog

/opt/ncubed/vpnc.service/scripts/install.sh
