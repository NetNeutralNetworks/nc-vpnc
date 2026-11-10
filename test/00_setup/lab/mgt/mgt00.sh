#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

export FRRVER="frr-stable"
export EXTERNAL_IF="eth1"
export EXTERNAL_IF_IP4="192.0.2.3/24"
export EXTERNAL_GW_IP4="192.0.2.1"
export EXTERNAL_IF_IP6="2001:db8::3/64"

export LOOPBACK_IF_IP="fd00::3/128"

export BGP_AS="4233333333"
export BGP_ROUTER_ID="3.3.3.3"

export VPN_PEER_PSK="secretpasswordcore"

export VPN_TUNNEL_IF_IP_0="fd00:1:2::1/127"
export VPN_PEER_IP4_0="192.0.2.5"
export VPN_PEER_IP6_0="2001:db8::5"
export VPN_PEER_IP_0="${VPN_PEER_IP6_0}"
export BGP_PEER_IP_0="fd00:1:2::"
export BGP_PEER_AS_0="4255555555"

export VPN_TUNNEL_IF_IP_1="fd00:1:2::3/127"
export VPN_PEER_IP4_1="192.0.2.6"
export VPN_PEER_IP6_1="2001:db8::6"
export VPN_PEER_IP_1="${VPN_PEER_IP6_1}"
export BGP_PEER_IP_1="fd00:1:2::2"
export BGP_PEER_AS_1="4266666666"

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
