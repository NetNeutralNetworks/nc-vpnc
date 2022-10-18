#! /bin/bash

# https://docs.strongswan.org/docs/5.9/plugins/updown.html
# Connection is the IPsec tunnel name
# if PLUTO_CONNECTION contains c0001-09
NETNS=${PLUTO_CONNECTION:0:5}          # outputs c0001
XFRM="xfrm-${PLUTO_CONNECTION}"        # outputs xfrm-c0001-09
TRUSTED_NETNS="TRUST"                  #
CUST_ID=$((${PLUTO_CONNECTION:1:4}))   # outputs 1
CUST_VPN_ID=$((${PLUTO_CONNECTION:6})) # outputs 9
V6_SEGMENT_3=${PLUTO_CONNECTION:0:1}   # outputs c
V6_SEGMENT_4=${CUST_ID}                # outputs 1
V6_SEGMENT_5=${CUST_VPN_ID}            # outputs 9
# outputs fdcc:0:c:1:0
V6_CUST_SPACE="fdcc:0:${V6_SEGMENT_3}:${V6_SEGMENT_4}:0"
# outputs fdcc:0:c:1:9
V6_CUST_TUNNEL_SPACE="fdcc:0:${V6_SEGMENT_3}:${V6_SEGMENT_4}:${V6_SEGMENT_5}"

printf "${V6_CUST_SPACE}\n\n"
printf "${XFRM}\n\n"

case "${PLUTO_VERB}" in
up-client)
    printf "Creating interface and routing rules\n\n"
    # add routes
    ip -n ${TRUSTED_NETNS} -6 route add ${V6_CUST_TUNNEL_SPACE}::/96 via ${V6_CUST_SPACE}:1:0:1
    ip -n ${NETNS} route add 0.0.0.0/0 dev ${XFRM}
    # start NAT64
    ip netns exec ${NETNS} jool instance add --netfilter --pool6 ${V6_CUST_SPACE}::/96
    ;;
down-client)
    printf "Cleaning up interfaces\n\n"
    ip -n ${NETNS} route del 0.0.0.0/0 dev ${XFRM}
    ip -n ${TRUSTED_NETNS} -6 route del ${V6_CUST_SPACE}::/96
    ;;
up-client-v6) ;;

down-client-v6) ;;

esac
