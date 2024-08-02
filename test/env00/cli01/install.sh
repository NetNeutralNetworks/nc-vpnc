#! /bin/bash

apt update
apt install -y iproute2
ip -4 address add 172.16.31.10/24 dev eth1
ip -6 address add 2001:db8:c58::10/64 dev eth1
ip -6 address add fdff:db8:c58::10/64 dev eth1

while true; do sleep 60; done
