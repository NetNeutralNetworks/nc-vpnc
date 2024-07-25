#! /bin/sh
# add FRR GPG key
curl -s https://deb.frrouting.org/frr/keys.asc | sudo apt-key add -
FRRVER="frr-8"
UNTRUST_IF="ens4"
UNTRUST_IF_IP4="192.0.2.3/24"
UNTRUST_GW_IP4="192.0.2.1"
UNTRUST_IF_IP6="2001:DB8::3/64"

TUNNEL_IF_IP="fd00:1:2::1/127"
LOOPBACK_IF_IP="fd00::1/128"

BGP_AS="4255786769"
BGP_ROUTER_ID="1.1.1.1"

VPN_PEER_IP4="192.0.2.5"
VPN_PEER_IP6="2001:DB8::5"
VPN_PEER_IP="${VPN_PEER_IP6}"
VPN_PEER_PSK="secretpasswordcore"
BGP_PEER_IP="fd00:1:2::"
BGP_PEER_AS="4255786777"

# Add FRR and other required services to the installation
echo deb https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER | sudo tee /etc/apt/sources.list.d/frr.list
apt update
apt install -y strongswan strongswan-swanctl frr frr-pythontools frr-snmp # jool-tools python3-watchdog
# Disable the strongswan service, as we will be starting it in another namespace.
systemctl disable ipsec.service
systemctl stop ipsec.service

# Enable bgpd in FRR
sed -i 's/^bgpd=no$/bgpd=yes/' /etc/frr/daemons
sed -i 's/^bfdd=no$/bfdd=yes/' /etc/frr/daemons

# Configure FRR to use snmpd
sed -i 's/^zebra_options="  -A 127.0.0.1 -s 90000000.*"$/zebra_options="  -A 127.0.0.1 -s 90000000 -n -M snmp"/' /etc/frr/daemons
sed -i 's/^bgpd_options="   -A 127.0.0.1.*"$/bgpd_options="   -A 127.0.0.1 -M snmp"/' /etc/frr/daemons

# comment SNMP agentaddress in snmpd
sed -i -E 's/^agentaddress(.*)/#agentaddress\1/' /etc/snmp/snmpd.conf

# Enable forwarding
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

systemctl restart frr

# Create the UNTRUST namespace, configure routing and start the strongswan daemon
ip netns add UNTRUST
ip link set ${UNTRUST_IF} netns UNTRUST
# ip -n UNTRUST address add ${UNTRUST_IP}/29 dev ${UNTRUST_IF}
ip -n UNTRUST address add ${UNTRUST_IF_IP4} dev ${UNTRUST_IF}
ip -n UNTRUST address add ${UNTRUST_IF_IP6} dev ${UNTRUST_IF}
ip -n UNTRUST link set dev ${UNTRUST_IF} up
ip netns exec UNTRUST sysctl -w net.ipv4.conf.all.forwarding=1
ip netns exec UNTRUST sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec UNTRUST ipsec start

ip -n UNTRUST link add xfrm-uplink000 type xfrm dev ${UNTRUST_IF} if_id 0x9999000
ip -n UNTRUST link set dev xfrm-uplink000 netns 1
ip link set dev xfrm-uplink000 up
ip address add ${TUNNEL_IF_IP} dev xfrm-uplink000
ip address add ${LOOPBACK_IF_IP} dev lo

# Generate Swanctl configuration file
echo "connections {
    # Section for an IKE connection named <conn>.
    uplink000 {
        # IKE major version to use for connection.
        version = 2
        # Local address(es) to use for IKE communication, comma separated.
        local_addrs = %any
        # Remote address(es) to use for IKE communication, comma separated.
        remote_addrs = ${VPN_PEER_IP}
        aggressive = no
        dpd_delay = 30s
        # Default inbound XFRM interface ID for children.
        if_id_in = 0x9999000
        # Default outbound XFRM interface ID for children.
        if_id_out = 0x9999000
        # Section for a local authentication round.
        local {
            auth = psk
            # id = \${UNTRUST_IP}
            # id = %any
        }
        # Section for a remote authentication round.
        remote {
            auth = psk
            id = ${VPN_PEER_IP}

        }
        proposals = aes256gcm16-prfsha384-ecp384
        rekey_time = 24h
        children {
            # CHILD_SA configuration sub-section.
            routed {
                # Local traffic selectors to include in CHILD_SA.
                local_ts = ::/0
                # Remote selectors to include in CHILD_SA.
                remote_ts = ::/0
                life_time = 3600s
                rekey_bytes = 1024000000
                esp_proposals = aes256gcm16-prfsha384-ecp384
                start_action = start
            }
        }
    }
}
secrets {
    ike-uplink000 {
        # id-1a = \"\${UNTRUST_IP}\"
        # id-1b = \"\${VPN_PEER_IP}\"
        id-1 = \"${VPN_PEER_IP}\"
        secret = \"${VPN_PEER_PSK}\"
    }
}
" > /etc/swanctl/conf.d/uplink.conf

# Generate FRR configuration file
echo "
ip forwarding
ipv6 forwarding
!
ip router-id ${BGP_ROUTER_ID}
!
router bgp ${BGP_AS}
  neighbor MGMT-TRANSIT peer-group
  neighbor MGMT-TRANSIT bfd
  neighbor MGMT-TRANSIT advertisement-interval 0
  neighbor MGMT-TRANSIT timers 10 30
  neighbor ${BGP_PEER_IP} remote-as ${BGP_PEER_AS}
  neighbor ${BGP_PEER_IP} peer-group MGMT-TRANSIT
  address-family ipv6 unicast
    aggregate-address fd00::/16 summary-only
    redistribute connected route-map REDIS-RM-STATIC-TO-BGP
    redistribute kernel route-map REDIS-RM-STATIC-TO-BGP
    neighbor MGMT-TRANSIT activate
    neighbor MGMT-TRANSIT route-map MGMT-TRANSIT-RM-IN in
    neighbor MGMT-TRANSIT route-map MGMT-TRANSIT-RM-OUT out
    neighbor MGMT-TRANSIT soft-reconfiguration inbound
  exit-address-family
exit
!
ipv6 prefix-list MGMT-TRANSIT-PL-IN seq 10 permit fdcc:0:c::/48 le 96 ge 96
ipv6 prefix-list MGMT-TRANSIT-PL-IN seq 20 permit fd60::/12 ge 48
ipv6 prefix-list MGMT-TRANSIT-PL-IN seq 30 permit 2000::/3 ge 32
ipv6 prefix-list MGMT-TRANSIT-PL-OUT seq 10 permit ::/0 ge 1
ipv6 prefix-list REDIS-PL-IN seq 10 permit fd00::/16 ge 64
!
route-map MGMT-TRANSIT-RM-IN permit 1
  match ipv6 address prefix-list MGMT-TRANSIT-PL-IN
exit
!
route-map MGMT-TRANSIT-RM-IN deny 2
exit
!
route-map MGMT-TRANSIT-RM-OUT permit 1
  match ipv6 address prefix-list MGMT-TRANSIT-PL-OUT
exit
!
route-map MGMT-TRANSIT-RM-OUT deny 2
exit
!
route-map REDIS-RM-STATIC-TO-BGP permit 1
  match ipv6 address prefix-list REDIS-PL-IN
exit
!
bfd
  peer ${BGP_PEER_IP}
exit
!
end
" > /etc/frr/ffr.conf

vtysh -f /etc/frr/ffr.conf

swanctl --load-all
swanctl --list-conns
swanctl --list-sas

while true;
do
    ping -c 5 fdcc:0:c:1::172.16.31.254
    ping -c 5 2001:DB8:c57::ffff
    ping -c 5 fd6c:1::ffff
done
