#! /bin/sh
# add FRR GPG key
apt update
apt install -y curl lsb-release
curl -s https://deb.frrouting.org/frr/keys.asc | apt-key add -
FRRVER="frr-stable"
UNTRUST_IF="eth1"
UNTRUST_IF_IP4="192.0.2.4/24"
UNTRUST_GW_IP4="192.0.2.1"
UNTRUST_IF_IP6="2001:db8::4/64"

LOOPBACK_IF_IP="fd00::4/128"

BGP_AS="4244444444"
BGP_ROUTER_ID="4.4.4.4"

VPN_PEER_PSK="secretpasswordcore"

VPN_TUNNEL_IF_IP_0="fd00:1:2::1:1/127"
VPN_PEER_IP4_0="192.0.2.5"
VPN_PEER_IP6_0="2001:db8::5"
VPN_PEER_IP_0="${VPN_PEER_IP6_0}"
BGP_PEER_IP_0="fd00:1:2::1:0"
BGP_PEER_AS_0="4255555555"

VPN_TUNNEL_IF_IP_1="fd00:1:2::1:3/127"
VPN_PEER_IP4_1="192.0.2.6"
VPN_PEER_IP6_1="2001:db8::6"
VPN_PEER_IP_1="${VPN_PEER_IP6_1}"
BGP_PEER_IP_1="fd00:1:2::1:2"
BGP_PEER_AS_1="4266666666"

# Add FRR and other required services to the installation
echo deb https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER | tee /etc/apt/sources.list.d/frr.list
DEBIAN_FRONTEND=noninteractive apt install -y dnsutils iproute2 iputils-ping strongswan strongswan-swanctl frr frr-pythontools frr-snmp
# If systemd is the init system
if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
  # Disable the strongswan service, as we will be starting it in another namespace.
  systemctl disable ipsec.service
  systemctl stop ipsec.service
fi

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

# If systemd is the init system
if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
    systemctl stop frr
    systemctl mask frr
fi
/usr/lib/frr/frrinit.sh start

echo "
# /etc/strongswan.conf - strongSwan configuration file

swanctl {
  load = pem pkcs1 x509 revocation constraints pubkey openssl random
}
charon {
  # https://docs.strongswan.org/docs/5.9/config/lookupTuning.html#_hash_table_size
  ikesa_table_size = 256
  # https://docs.strongswan.org/docs/5.9/config/lookupTuning.html#_locking
  ikesa_table_segments = 16
  # https://docs.strongswan.org/docs/5.9/config/rekeying.html#_reauthentication
  make_before_break = yes
  retry_initiate_interval = 60
}
charon-systemd {
  load = random nonce aes sha1 sha2 hmac kdf pem pkcs1 x509 revocation curve25519 gmp curl kernel-netlink socket-default updown vici
}
" > /etc/strongswan.conf

# Create the UNTRUST namespace, configure routing and start the strongswan daemon
mkdir -p /var/run/netns
ip netns add UNTRUST
ip link set ${UNTRUST_IF} netns UNTRUST
# ip -netns UNTRUST address add ${UNTRUST_IP}/29 dev ${UNTRUST_IF}
ip -netns UNTRUST address add ${UNTRUST_IF_IP4} dev ${UNTRUST_IF}
ip -netns UNTRUST address add ${UNTRUST_IF_IP6} dev ${UNTRUST_IF}
ip -netns UNTRUST link set dev ${UNTRUST_IF} up
ip netns exec UNTRUST sysctl -w net.ipv4.conf.all.forwarding=1
ip netns exec UNTRUST sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec UNTRUST ipsec start

ip -netns UNTRUST link add xfrm0 type xfrm dev ${UNTRUST_IF} if_id 0x9999000
ip -netns UNTRUST link set dev xfrm0 netns 1
ip address flush dev xfrm0 scope global
ip link set dev xfrm0 up
ip address add ${VPN_TUNNEL_IF_IP_0} dev xfrm0
ip -netns UNTRUST link add xfrm1 type xfrm dev ${UNTRUST_IF} if_id 0x9999001
ip -netns UNTRUST link set dev xfrm1 netns 1
ip link set dev xfrm1 up
ip address flush dev xfrm1 scope global
ip address add ${VPN_TUNNEL_IF_IP_1} dev xfrm1
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
        remote_addrs = ${VPN_PEER_IP_0}
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
            id = ${VPN_PEER_IP_0}

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
    uplink001 {
        # IKE major version to use for connection.
        version = 2
        # Local address(es) to use for IKE communication, comma separated.
        local_addrs = %any
        # Remote address(es) to use for IKE communication, comma separated.
        remote_addrs = ${VPN_PEER_IP_1}
        aggressive = no
        dpd_delay = 30s
        # Default inbound XFRM interface ID for children.
        if_id_in = 0x9999001
        # Default outbound XFRM interface ID for children.
        if_id_out = 0x9999001
        # Section for a local authentication round.
        local {
            auth = psk
            # id = \${UNTRUST_IP}
            # id = %any
        }
        # Section for a remote authentication round.
        remote {
            auth = psk
            id = ${VPN_PEER_IP_1}

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
        id-1 = \"${VPN_PEER_IP_0}\"
        secret = \"${VPN_PEER_PSK}\"
    }
    ike-uplink001 {
        id-1 = \"${VPN_PEER_IP_1}\"
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
router bgp ${BGP_AS}
  neighbor MGMT-TRANSIT peer-group
  neighbor MGMT-TRANSIT bfd
  neighbor MGMT-TRANSIT advertisement-interval 0
  neighbor MGMT-TRANSIT timers 10 30
  neighbor ${BGP_PEER_IP_0} remote-as ${BGP_PEER_AS_0}
  neighbor ${BGP_PEER_IP_0} peer-group MGMT-TRANSIT
  neighbor ${BGP_PEER_IP_1} remote-as ${BGP_PEER_AS_1}
  neighbor ${BGP_PEER_IP_1} peer-group MGMT-TRANSIT
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
bfd
  peer ${BGP_PEER_IP_0}
  peer ${BGP_PEER_IP_1}
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
    ping -c 3 fdcc:0:c:1:0::172.16.30.254
    ping -c 3 fdcc:0:c:1:1::172.17.30.254
    ping -c 3 fdcc:0:c:1:0::172.16.30.1
    ping -c 3 fdcc:0:c:1:1::172.17.30.1
    ping -c 3 2001:db8:c57::ffff
    ping -c 3 2001:db8:c58::ffff
    ping -c 3 2001:db8:c57::1
    ping -c 3 2001:db8:c58::1
    ping -c 3 fd6c:1:0::ffff
    ping -c 3 fd6c:1:1::ffff
    ping -c 3 fd6c:1:0::1
    ping -c 3 fd6c:1:1::1
    dig +short +time=1 +tries=1 v6gonly.example.com AAAA @fdcc:0:c:1::172.16.31.1
    dig +short +time=1 +tries=1 v6gonly.example.com AAAA @fdcc:0:c:1:1::172.17.31.1
    dig +short +time=1 +tries=1 v6lonly.example.com AAAA @2001:db8:c57:31::1
    dig +short +time=1 +tries=1 v6lonly.example.com AAAA @2001:db8:c58:31::1
    dig +short +time=1 +tries=1 v4lonly.example.com @fd6c:1:0:31::1
    dig +short +time=1 +tries=1 v4lonly.example.com @fd6c:1:1:31::1
done
