#! /bin/bash
servicename=vpnc
servicefile=/etc/systemd/system/ncubed-$servicename.service
if [ -L $servicefile ]; then
  rm $servicefile
fi
ln -s /opt/ncubed/$servicename.service/units/ncubed-$servicename.service $servicefile

# Enable bgpd in FRR
sed -i 's/^bgpd=no$/bgpd=yes/' /etc/frr/daemons
sed -i 's/^zebra_options="  -A 127.0.0.1 -s 90000000.*"$/zebra_options="  -A 127.0.0.1 -s 90000000 -n -M snmp"/' /etc/frr/daemons
sed -i 's/^bgpd_options="   -A 127.0.0.1.*"$/bgpd_options="   -A 127.0.0.1 -M snmp"/' /etc/frr/daemons

# comment SNMP agentaddress in snmpd
sed -i -E 's/^agentaddress(.*)/#agentaddress\1/' /etc/snmp/snmpd.conf

/usr/bin/systemctl daemon-reload
/usr/bin/systemctl disable ipsec.service
/usr/bin/systemctl stop ipsec.service
/usr/bin/systemctl enable ncubed-$servicename
/usr/bin/systemctl start ncubed-$servicename
/usr/bin/systemctl enable frr.service
/usr/bin/systemctl start frr.service
