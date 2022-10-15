#! /bin/bash

if [[ -z "$1" ]]; then
    printf "
Usage: sudo ./prep_host <customer|hub>

"
    exit 1
fi


apt update
apt install strongswan
apt install jool-tools

cp -r $1/etc/* /etc/

# enbale routing
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

ipsec restart
