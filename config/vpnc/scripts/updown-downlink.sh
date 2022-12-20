#! /bin/bash

# https://docs.strongswan.org/docs/5.9/plugins/updown.html
# Connection is the IPsec tunnel name
# if PLUTO_CONNECTION contains c0001-009
NETNS=${PLUTO_CONNECTION}              # outputs c0001-009
XFRM="xfrm-${PLUTO_CONNECTION}"        # outputs xfrm-c0001-009
TRUSTED_NETNS="TRUST"                  #
DOWNLINK_ID=${PLUTO_CONNECTION:1:4}    # outputs 0001
DOWNLINK_VPN_ID=${PLUTO_CONNECTION:6}  # outputs 009
V6_SEGMENT_3=${PLUTO_CONNECTION:0:1}   # outputs c
V6_SEGMENT_4=${DOWNLINK_ID}            # outputs 0001
V6_SEGMENT_5=${DOWNLINK_VPN_ID}        # outputs 009
# outputs fdcc:0:c:0001:009
V6_DOWNLINK_TUNNEL_SPACE="fdcc:0:${V6_SEGMENT_3}:${V6_SEGMENT_4}:${V6_SEGMENT_5}"

printf "${V6_DOWNLINK_TUNNEL_SPACE}\n\n"
printf "${XFRM}\n\n"

case "${PLUTO_VERB}" in
up-client)
    printf "Creating interface and routing rules\n\n"
    # add routes
    ip -n ${TRUSTED_NETNS} -6 route add ${V6_DOWNLINK_TUNNEL_SPACE}::/96 via ${V6_DOWNLINK_TUNNEL_SPACE}:1:0:1
    ip -n ${NETNS} route add 0.0.0.0/0 dev ${XFRM}
    # start NAT64
    ip netns exec ${NETNS} jool instance add ${NETNS} --netfilter --pool6 ${V6_DOWNLINK_TUNNEL_SPACE}::/96
    ;;
down-client)
    printf "Cleaning up interfaces\n\n"
    # remove NAT64
    ip netns exec ${NETNS} jool instance remove ${NETNS}
    # remove default route over VPN
    ip -n ${NETNS} route del 0.0.0.0/0 dev ${XFRM}
    # remmove IPv6 route to VPN tunnel
    ip -n ${TRUSTED_NETNS} -6 route del ${V6_DOWNLINK_TUNNEL_SPACE}::/96
    ;;
up-client-v6) ;;

down-client-v6) ;;

esac
