#! /bin/bash
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"

PACKAGES="iproute2 bind9 dnsutils openssh-server iptables"
# Packages are in the lab image; only install when missing.
if ! dpkg -s $PACKAGES > /dev/null 2>&1; then
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y $PACKAGES
fi

# Wait for containerlab to attach the lab interface.
for i in $(seq 120); do ip link show eth1 > /dev/null 2>&1 && break; sleep 0.5; done

# Enable forwarding
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Configure router addresses
ip -4 address add 172.16.30.1/24 dev eth1
ip -6 address add fdff:db8:c57::1/64 dev eth1
ip -6 address add 2001:db8:c57::1/64 dev eth1

# Configure loopback IPs on host
ip -4 address add 172.16.31.1/24 dev lo
ip -4 address add 172.16.31.4/24 dev lo
ip -4 address add 172.16.31.6/24 dev lo
ip -4 address add 172.16.31.64/24 dev lo
ip -6 address add 2001:db8:c57:31::1/64 dev lo
ip -6 address add fdff:db8:c57:31::1/64 dev lo
ip -6 address add 2001:db8:c57:31::4/64 dev lo
ip -6 address add fdff:db8:c57:31::4/64 dev lo
ip -6 address add 2001:db8:c57:31::6/64 dev lo
ip -6 address add fdff:db8:c57:31::6/64 dev lo
ip -6 address add 2001:db8:c57:31::64/64 dev lo
ip -6 address add fdff:db8:c57:31::64/64 dev lo

cp -f ${SCRIPTDIR}/authorized_keys /root/.ssh/
cp -f ${SCRIPTDIR}/sshd_lab.conf /etc/ssh/sshd_config.d/
cp -f ${SCRIPTDIR}/db.example.com_cli00 /etc/bind/db.example.com
cp -f ${SCRIPTDIR}/named.conf.local /etc/bind/
cp -f ${SCRIPTDIR}/named.conf.options /etc/bind/

# start ssh server
service ssh start
sshd -D

# Start DNS server
named

while true; do sleep 60; done
