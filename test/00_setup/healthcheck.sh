#! /bin/bash

# Waits until all connections are up or until x tries

((init_count = 90))
((count = init_count))                                              # Maximum number to try.
while [[ $count -ne 0 ]] ; do
    echo -ne "\r"
    echo -ne "Waiting for the env to be ready "
    for ((i=0; i<$((init_count - count)); i++)){
    echo -ne "."
    }
    docker exec clab-vpnc-mgt00 ping -c 1 -q fdcc:0:c:1::172.16.30.254 > /dev/null && \
    docker exec clab-vpnc-mgt01 ping -c 1 -q fdcc:0:c:1::172.16.30.254 > /dev/null && \
    docker exec clab-vpnc-mgt00 ping -c 1 -q 2001:db8:c57::ffff > /dev/null && \
    docker exec clab-vpnc-mgt01 ping -c 1 -q 2001:db8:c57::ffff > /dev/null && \
    docker exec clab-vpnc-mgt00 ping -c 1 -q fd6c:1::ffff > /dev/null && \
    docker exec clab-vpnc-mgt01 ping -c 1 -q fd6c:1::ffff > /dev/null && \
    docker exec clab-vpnc-mgt00 ping -c 1 -q fdcc:0:c:1:1::172.17.31.254 > /dev/null && \
    docker exec clab-vpnc-mgt01 ping -c 1 -q fdcc:0:c:1:1::172.17.31.254 > /dev/null && \
    docker exec clab-vpnc-mgt00 ping -c 1 -q 2001:db8:c58::ffff > /dev/null && \
    docker exec clab-vpnc-mgt01 ping -c 1 -q 2001:db8:c58::ffff > /dev/null && \
    docker exec clab-vpnc-mgt00 ping -c 1 -q fd6c:1:1::ffff > /dev/null && \
    docker exec clab-vpnc-mgt01 ping -c 1 -q fd6c:1:1::ffff > /dev/null
    rc=$?
    if [[ $rc -eq 0 ]] ; then
        ((count = 1))                                       # If okay, flag loop exit.
    else
        sleep 1                                             # Minimise network storm.
    fi
    ((count = count - 1))                                   # So we don't go forever.
done

if [[ $rc -eq 0 ]] ; then                                   # Make final determination.
    echo -e "\n[SUCCESS] VPN and route advertisements are up"
    sleep 3
else
    echo -e "\n[WARNING] Not all connections are functional after ${init_count} tries"
fi
