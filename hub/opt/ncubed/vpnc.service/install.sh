#! /bin/bash
servicename=vpnc
servicefile=/etc/systemd/system/ncubed-$servicename.service
if [ -L $servicefile ]; then
  rm $servicefile
fi
ln -s /opt/ncubed/$servicename.service/ncubed-$servicename.service $servicefile
/usr/bin/systemctl disable ipsec.service
/usr/bin/systemctl stop ipsec.service
/usr/bin/systemctl enable ncubed-$servicename
/usr/bin/systemctl restart ncubed-$servicename
