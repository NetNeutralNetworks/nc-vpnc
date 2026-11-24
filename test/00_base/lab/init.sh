#! /bin/bash
# Lab only: the end of a vpnc node's script. Waits for its links, then runs
# systemd as on the VMs; it starts snmpd and vpnc.
# Usage: exec init.sh <link>...

# snmpd readable with the community "public".
cat > /etc/snmp/snmpd.conf.d/lab.conf <<CONF
agentaddress udp:161,udp6:161
rocommunity public
rocommunity6 public
CONF

# containerlab adds the links after the container starts, also after a
# restart: vpnc takes them over when it starts.
for link in "$@"; do
    until ip link show "${link}" &> /dev/null; do sleep 0.2; done
done

# A fresh /run, as at a boot. systemd would mount one over binds into /run, so
# a lab binds into /lab/run instead (the fuzz lab: the API socket's directory).
mount -t tmpfs -o mode=755,nosuid,nodev tmpfs /run
shopt -s nullglob
for dir in /lab/run/*/; do
    target="/run/$(basename "${dir}")"
    mkdir -p "${target}"
    mount --bind "${dir}" "${target}"
done

exec /sbin/init
