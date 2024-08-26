#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

export RRVER="frr-stable"
export XTERNAL_IF="eth1"
export XTERNAL_IF_IP4="192.0.2.4/24"
export XTERNAL_GW_IP4="192.0.2.1"
export XTERNAL_IF_IP6="2001:db8::4/64"

export OOPBACK_IF_IP="fd00::4/128"

export GP_AS="4244444444"
export GP_ROUTER_ID="4.4.4.4"

export PN_PEER_PSK="secretpasswordcore"

export PN_TUNNEL_IF_IP_0="fd00:1:2::1:1/127"
export PN_PEER_IP4_0="192.0.2.5"
export PN_PEER_IP6_0="2001:db8::5"
export PN_PEER_IP_0="${VPN_PEER_IP6_0}"
export GP_PEER_IP_0="fd00:1:2::1:0"
export GP_PEER_AS_0="4255555555"

export PN_TUNNEL_IF_IP_1="fd00:1:2::1:3/127"
export PN_PEER_IP4_1="192.0.2.6"
export PN_PEER_IP6_1="2001:db8::6"
export PN_PEER_IP_1="${VPN_PEER_IP6_1}"
export GP_PEER_IP_1="fd00:1:2::1:2"
export GP_PEER_AS_1="4266666666"

# Copy the script to setup the management server and the service file that runs it to the correct
# locations.
mkdir -p /opt/ncubed/vpnc/units/
cp -rf ${SCRIPTDIR}/ncubed-vpnc-mgt-test.sh /opt/ncubed/vpnc/ncubed-vpnc-mgt-test.sh
cp -rf ${SCRIPTDIR}/ncubed-vpnc-mgt-test.service /opt/ncubed/vpnc/units/ncubed-vpnc-mgt-test.service

# If systemd is the init system
if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
    echo "Running in systemd"
    # Enable and start the service. This allows the survival of reboots
    /usr/bin/systemctl link /opt/ncubed/vpnc/units/ncubed-vpnc-mgt-test.service
    /usr/bin/systemctl enable ncubed-vpnc-mgt-test.service
    /usr/bin/systemctl restart ncubed-vpnc-mgt-test.service
else
    echo "Not running in systemd"
    /opt/ncubed/vpnc/ncubed-vpnc-mgt-test.sh
fi
