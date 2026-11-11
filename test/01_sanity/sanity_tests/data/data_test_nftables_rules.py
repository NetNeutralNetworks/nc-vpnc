"""Expected nftables state per network instance (nft list output)."""

# ruff: noqa: E501  (nft prints rules on one line)

ICMPV6_IN_OUT = (
    "\tchain icmpv6-in-out {\n"
    "\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n"
    "\t\tmeta l4proto ipv6-icmp drop\n"
    "\t}"
)

ICMPV6_FORWARD = (
    "\tchain icmpv6-forward {\n"
    "\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply } accept\n"
    "\t\tmeta l4proto ipv6-icmp drop\n"
    "\t}"
)

TABLES = [
    (
        "hub00",
        "EXTERNAL",
        (
            "table inet vpnc {\n"
            "\tset wireguard_ports {\n"
            "\t\ttype inet_service\n"
            "\t\telements = { 51820 }\n"
            "\t}\n"
            "\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\ticmp type destination-unreachable icmp code 4 ct state related accept\n"
            "\t\tudp dport { 500, 4500 } accept\n"
            "\t\tudp dport @wireguard_ports accept\n"
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\tudp sport 500 udp dport 500 accept\n"
            "\t\tudp sport 4500 udp dport 4500 accept\n"
            "\t\tudp sport @wireguard_ports accept\n"
            "\t\tmeta l4proto udp ct state established,related accept\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "}"
        ),
    ),
    (
        "hub00",
        "CORE",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tmeta nfproto ipv6 iifname "xfrm0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "xfrm1" accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t\tmeta nfproto ipv6 jump icmpv6-forward\n"
            '\t\tmeta nfproto ipv6 iifname "xfrm0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "xfrm1" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy accept;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv4 drop\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            f"{ICMPV6_FORWARD}"
            "\n"
            "}"
        ),
    ),
    (
        "hub00",
        "C0001-00",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tiifname "tun1" ct state established,related accept\n'
            '\t\tiifname "xfrm0" ct state established,related accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            '\t\tmeta nfproto ipv6 iifname "C0001-00_D" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            '\t\toifname "tun1" tcp dport 22 accept\n'
            '\t\toifname "xfrm0" tcp dport 22 accept\n'
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            "\tchain prerouting {\n"
            "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1::/52 dnat ip6 prefix to fdff:db8:c57::/52\n'
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1:0:1000::/52 dnat ip6 prefix to fdff:db8:c57:1000::/52\n'
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1:0:2000::/56 dnat ip6 prefix to fdff:db8:c57:2000::/56\n'
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1:0:3000::/52 dnat ip6 prefix to fdff:db8:c57:3000::/52\n'
            "\t}\n"
            "\n"
            "\tchain postrouting {\n"
            "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
            '\t\tmeta nfproto ipv6 oifname "tun1" masquerade\n'
            '\t\tmeta nfproto ipv6 oifname "xfrm0" masquerade\n'
            "\t}\n"
            "}"
        ),
    ),
    (
        "hub00",
        "C0001-01",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tiifname "wg-C0001-01-0" ct state established,related accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            '\t\tmeta nfproto ipv6 iifname "C0001-01_D" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            '\t\toifname "wg-C0001-01-0" tcp dport 22 accept\n'
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            "\tchain prerouting {\n"
            "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1::/52 dnat ip6 prefix to fdff:db8:c58::/52\n'
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1:1000::/52 dnat ip6 prefix to fdff:db8:c58:1000::/52\n'
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1:2000::/56 dnat ip6 prefix to fdff:db8:c58:2000::/56\n'
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1:3000::/52 dnat ip6 prefix to fdff:db8:c58:3000::/52\n'
            "\t}\n"
            "\n"
            "\tchain postrouting {\n"
            "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
            '\t\tmeta nfproto ipv6 oifname "wg-C0001-01-0" masquerade\n'
            "\t}\n"
            "}"
        ),
    ),
    (
        "hub01",
        "EXTERNAL",
        (
            "table inet vpnc {\n"
            "\tset wireguard_ports {\n"
            "\t\ttype inet_service\n"
            "\t\telements = { 51820 }\n"
            "\t}\n"
            "\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\ticmp type destination-unreachable icmp code 4 ct state related accept\n"
            "\t\tudp dport { 500, 4500 } accept\n"
            "\t\tudp dport @wireguard_ports accept\n"
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\tudp sport 500 udp dport 500 accept\n"
            "\t\tudp sport 4500 udp dport 4500 accept\n"
            "\t\tudp sport @wireguard_ports accept\n"
            "\t\tmeta l4proto udp ct state established,related accept\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "}"
        ),
    ),
    (
        "hub01",
        "CORE",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tmeta nfproto ipv6 iifname "xfrm0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "xfrm1" accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t\tmeta nfproto ipv6 jump icmpv6-forward\n"
            '\t\tmeta nfproto ipv6 iifname "xfrm0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "xfrm1" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy accept;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv4 drop\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            f"{ICMPV6_FORWARD}"
            "\n"
            "}"
        ),
    ),
    (
        "hub01",
        "C0001-00",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tiifname "tun1" ct state established,related accept\n'
            '\t\tiifname "xfrm0" ct state established,related accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            '\t\tmeta nfproto ipv6 iifname "C0001-00_D" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            '\t\toifname "tun1" tcp dport 22 accept\n'
            '\t\toifname "xfrm0" tcp dport 22 accept\n'
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            "\tchain prerouting {\n"
            "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1::/52 dnat ip6 prefix to fdff:db8:c57::/52\n'
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1:0:1000::/52 dnat ip6 prefix to fdff:db8:c57:1000::/52\n'
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1:0:2000::/56 dnat ip6 prefix to fdff:db8:c57:2000::/56\n'
            '\t\tiifname "C0001-00_D" ip6 daddr fd6c:1:0:3000::/52 dnat ip6 prefix to fdff:db8:c57:3000::/52\n'
            "\t}\n"
            "\n"
            "\tchain postrouting {\n"
            "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
            '\t\tmeta nfproto ipv6 oifname "tun1" masquerade\n'
            '\t\tmeta nfproto ipv6 oifname "xfrm0" masquerade\n'
            "\t}\n"
            "}"
        ),
    ),
    (
        "hub01",
        "C0001-01",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tiifname "wg-C0001-01-0" ct state established,related accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            '\t\tmeta nfproto ipv6 iifname "C0001-01_D" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            '\t\toifname "wg-C0001-01-0" tcp dport 22 accept\n'
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            "\tchain prerouting {\n"
            "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1::/52 dnat ip6 prefix to fdff:db8:c58::/52\n'
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1:1000::/52 dnat ip6 prefix to fdff:db8:c58:1000::/52\n'
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1:2000::/56 dnat ip6 prefix to fdff:db8:c58:2000::/56\n'
            '\t\tiifname "C0001-01_D" ip6 daddr fd6c:1:1:3000::/52 dnat ip6 prefix to fdff:db8:c58:3000::/52\n'
            "\t}\n"
            "\n"
            "\tchain postrouting {\n"
            "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
            '\t\tmeta nfproto ipv6 oifname "wg-C0001-01-0" masquerade\n'
            "\t}\n"
            "}"
        ),
    ),
    (
        "end00",
        "EXTERNAL",
        (
            "table inet vpnc {\n"
            "\tset wireguard_ports {\n"
            "\t\ttype inet_service\n"
            "\t}\n"
            "\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\ticmp type destination-unreachable icmp code 4 ct state related accept\n"
            "\t\tudp dport { 500, 4500 } accept\n"
            "\t\tudp dport @wireguard_ports accept\n"
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\tudp sport 500 udp dport 500 accept\n"
            "\t\tudp sport 4500 udp dport 4500 accept\n"
            "\t\tudp sport @wireguard_ports accept\n"
            "\t\tmeta l4proto udp ct state established,related accept\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "}"
        ),
    ),
    (
        "end00",
        "CORE",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tmeta nfproto ipv6 iifname "xfrm0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "xfrm1" accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t\tmeta nfproto ipv6 jump icmpv6-forward\n"
            '\t\tmeta nfproto ipv4 iifname "xfrm0" accept\n'
            '\t\tmeta nfproto ipv4 iifname "xfrm1" accept\n'
            "\t\tmeta nfproto ipv4 ct state established,related accept\n"
            '\t\tmeta nfproto ipv6 iifname "xfrm0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "xfrm1" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy accept;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv4 drop\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            f"{ICMPV6_FORWARD}"
            "\n"
            "}"
        ),
    ),
    (
        "end00",
        "ENDPOINT",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto icmp accept\n"
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            '\t\tiifname "ENDPOINT_D" accept\n'
            "\t\tct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tct state established,related accept\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            "\tchain prerouting {\n"
            "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            "\t}\n"
            "\n"
            "\tchain postrouting {\n"
            "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
            '\t\tmeta nfproto ipv4 oifname "eth2" masquerade\n'
            '\t\tmeta nfproto ipv6 oifname "eth2" masquerade\n'
            "\t}\n"
            "}"
        ),
    ),
    (
        "end01",
        "EXTERNAL",
        (
            "table inet vpnc {\n"
            "\tset wireguard_ports {\n"
            "\t\ttype inet_service\n"
            "\t\telements = { 51820, 51821 }\n"
            "\t}\n"
            "\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\ticmp type destination-unreachable icmp code 4 ct state related accept\n"
            "\t\tudp dport { 500, 4500 } accept\n"
            "\t\tudp dport @wireguard_ports accept\n"
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto esp accept\n"
            "\t\tudp sport 500 udp dport 500 accept\n"
            "\t\tudp sport 4500 udp dport 4500 accept\n"
            "\t\tudp sport @wireguard_ports accept\n"
            "\t\tmeta l4proto udp ct state established,related accept\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "}"
        ),
    ),
    (
        "end01",
        "CORE",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            '\t\tmeta nfproto ipv6 iifname "wg-CORE-0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "wg-CORE-1" accept\n'
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t\tmeta nfproto ipv6 jump icmpv6-forward\n"
            '\t\tmeta nfproto ipv4 iifname "wg-CORE-0" accept\n'
            '\t\tmeta nfproto ipv4 iifname "wg-CORE-1" accept\n'
            "\t\tmeta nfproto ipv4 ct state established,related accept\n"
            '\t\tmeta nfproto ipv6 iifname "wg-CORE-0" accept\n'
            '\t\tmeta nfproto ipv6 iifname "wg-CORE-1" accept\n'
            "\t\tmeta nfproto ipv6 ct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy accept;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta nfproto ipv4 drop\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            f"{ICMPV6_FORWARD}"
            "\n"
            "}"
        ),
    ),
    (
        "end01",
        "ENDPOINT",
        (
            "table inet vpnc {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tmeta l4proto icmp accept\n"
            "\t}\n"
            "\n"
            "\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy drop;\n"
            '\t\tiifname "ENDPOINT_D" accept\n'
            "\t\tct state established,related accept\n"
            "\t}\n"
            "\n"
            "\tchain output {\n"
            "\t\ttype filter hook output priority filter; policy drop;\n"
            "\t\tmeta l4proto ipv6-icmp jump icmpv6-in-out\n"
            "\t\tct state established,related accept\n"
            "\t}\n"
            "\n"
            f"{ICMPV6_IN_OUT}"
            "\n"
            "\n"
            "\tchain prerouting {\n"
            "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            "\t}\n"
            "\n"
            "\tchain postrouting {\n"
            "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
            '\t\tmeta nfproto ipv4 oifname "eth2" masquerade\n'
            '\t\tmeta nfproto ipv6 oifname "eth2" masquerade\n'
            "\t}\n"
            "}"
        ),
    ),
]

TABLE_NAMES = [
    ("hub00", "EXTERNAL", ["table inet vpnc"]),
    ("hub00", "CORE", ["table inet vpnc", "table ip6 vpncmangle"]),
    ("hub00", "C0001-00", ["table inet vpnc"]),
    ("hub00", "C0001-01", ["table inet vpnc"]),
    ("hub01", "EXTERNAL", ["table inet vpnc"]),
    ("hub01", "CORE", ["table inet vpnc", "table ip6 vpncmangle"]),
    ("hub01", "C0001-00", ["table inet vpnc"]),
    ("hub01", "C0001-01", ["table inet vpnc"]),
    ("end00", "EXTERNAL", ["table inet vpnc"]),
    ("end00", "CORE", ["table inet vpnc"]),
    ("end00", "ENDPOINT", ["table inet vpnc"]),
    ("end01", "EXTERNAL", ["table inet vpnc"]),
    ("end01", "CORE", ["table inet vpnc"]),
    ("end01", "ENDPOINT", ["table inet vpnc"]),
]
