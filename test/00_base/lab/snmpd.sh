#! /bin/bash
# Lab only: start snmpd as its service does, readable with the community "public".
cat > /etc/snmp/snmpd.conf.d/lab.conf <<CONF
agentaddress udp:161,udp6:161
rocommunity public
rocommunity6 public
CONF
/usr/sbin/snmpd -LOw -u Debian-snmp -g Debian-snmp -I -smux,mteTrigger,mteTriggerConf
