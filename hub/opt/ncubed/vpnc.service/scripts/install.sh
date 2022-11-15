#! /bin/bash
servicename=vpnc
case $1 in
hub)
    /usr/bin/systemctl disable ncubed-$servicename-hub.service
    /usr/bin/systemctl stop ncubed-$servicename-endpoint.service
    /usr/bin/systemctl disable ncubed-$servicename-endpoint.service

    /usr/bin/systemctl link /opt/ncubed/$servicename.service/units/ncubed-$servicename-hub.service

    # Enable bgpd in FRR
    sed -i 's/^bgpd=no$/bgpd=yes/' /etc/frr/daemons
    sed -i 's/^zebra_options="  -A 127.0.0.1 -s 90000000.*"$/zebra_options="  -A 127.0.0.1 -s 90000000 -n -M snmp"/' /etc/frr/daemons
    sed -i 's/^bgpd_options="   -A 127.0.0.1.*"$/bgpd_options="   -A 127.0.0.1 -M snmp"/' /etc/frr/daemons

    # comment SNMP agentaddress in snmpd
    sed -i -E 's/^agentaddress(.*)/#agentaddress\1/' /etc/snmp/snmpd.conf

    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl disable ipsec.service
    /usr/bin/systemctl stop ipsec.service
    /usr/bin/systemctl enable snmpd.service
    /usr/bin/systemctl restart snmpd.service
    /usr/bin/systemctl enable frr.service
    /usr/bin/systemctl restart frr.service
    /usr/bin/systemctl enable ncubed-$servicename-hub
    /usr/bin/systemctl restart ncubed-$servicename-hub
    ;;
endpoint)
    # It's important to have the link have the same name as the desired service, otherwise the symlink won't work.
    /usr/bin/systemctl stop ncubed-$servicename-hub.service
    /usr/bin/systemctl disable ncubed-$servicename-hub.service
    /usr/bin/systemctl disable ncubed-$servicename-endpoint.service

    /usr/bin/systemctl link /opt/ncubed/$servicename.service/units/ncubed-$servicename-endpoint.service

    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl disable ipsec.service
    /usr/bin/systemctl stop ipsec.service
    /usr/bin/systemctl enable ncubed-$servicename-endpoint
    /usr/bin/systemctl restart ncubed-$servicename-endpoint
    ;;
*)
    echo "Argument should be either 'hub' or 'endpoint'"
esac
