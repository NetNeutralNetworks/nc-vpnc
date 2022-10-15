UNTRUSTED_INTERFACE="ens4"
TRUSTED_TRANSIT="fd33:2:f"
TRUSTED_NETWORK="fd33::/16"

ip netns add UNTRUST
touch /var/run/netns/ROOT
# Alias the default namespace (and it's children) to the ROOT namespace
mount --bind /proc/1/ns/net /var/run/netns/ROOT
ip netns add TRUST
ip netns add C0001

ip netns exec TRUST sysctl -w net.ipv6.conf.all.forwarding=1
ip link set $UNTRUSTED_INTERFACE netns UNTRUST
ip -n UNTRUST addr add 192.168.0.151/22
ip -n UNTRUST addr add 192.168.0.151/22 dev ens4
ip -n UNTRUST link set dev ens4 up
ip -n UNTRUST route add default via 192.168.0.1
ip netns exec UNTRUST ipsec restart

# setup VETH interface
ip link add TRUST_I type veth peer name TRUST_E

ip link set netns TRUST TRUST_E
ip -n TRUST link set dev TRUST_E up
ip -n TRUST addr add $TRUSTED_TRANSIT::1/127 dev TRUST_E

ip link set dev TRUST_I up
ip addr add $TRUSTED_TRANSIT::0/127 dev TRUST_I

ip -6 route add $TRUSTED_NETWORK via $TRUSTED_TRANSIT::1
ip -6 route add fdcc::/16 via $TRUSTED_TRANSIT::1

systemctl restart frr.service
