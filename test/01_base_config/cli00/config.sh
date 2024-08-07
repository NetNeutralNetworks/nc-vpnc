#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

apt update
apt install -y iproute2 bind9 dnsutils

# Enable forwarding
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Configure router addresses
ip -4 address add 172.16.30.1/24 dev eth1
ip -6 address add fdff:db8:c57::1/64 dev eth1
ip -6 address add 2001:db8:c57::1/64 dev eth1

# Configure loopback IPs on host
ip -4 address add 172.16.31.1/24 dev lo
ip -6 address add 2001:db8:c57:31::1/64 dev lo
ip -6 address add fdff:db8:c57:31::1/64 dev lo

cp -f ${SCRIPTDIR}/db.example.com /etc/bind/
cp -f ${SCRIPTDIR}/named.conf.local /etc/bind/
cp -f ${SCRIPTDIR}/named.conf.options /etc/bind/

# Start DNS server
named

while true; do sleep 60; done
