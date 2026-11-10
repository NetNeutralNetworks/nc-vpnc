#! /bin/bash
# peer00 of the scale lab: the other end of hub00's 300 connections. The scale
# tests add its addresses, IPsec connections and WireGuard interfaces.
until ip link show eth1 &> /dev/null; do sleep 1; done
ip link set eth1 up
ip address add 2001:db8::7/64 dev eth1 nodad

# Route-based (if_id) connections without XFRM interfaces: no routes needed.
cat > /etc/strongswan.d/scale.conf << 'CONF'
charon {
    install_routes = no
    # 140 connections initiate at once; with the default 16 charon stalled.
    threads = 64
}
CONF
/usr/lib/ipsec/starter --daemon charon
exec sleep infinity
