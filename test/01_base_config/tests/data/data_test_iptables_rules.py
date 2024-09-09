TABLES4_HUB = [
    # By default no IPv4 in external, except for IPSec
    (
        "EXTERNAL",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT"
        ),
    ),
    # No IPv4 in CORE
    ("CORE", ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP")),
    # No IPv4 in C0001-00, even though we do NAT64. These are handled by Jool before
    # iptables forwards traffic
    (
        "C0001-00",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -i tun1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A INPUT -i xfrm0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o tun1 -p tcp -m tcp --dport 22 -j ACCEPT\n"
            "-A OUTPUT -o xfrm0 -p tcp -m tcp --dport 22 -j ACCEPT"
        ),
    ),
    (
        "C0001-01",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -i xfrm0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o xfrm0 -p tcp -m tcp --dport 22 -j ACCEPT"
        ),
    ),
]

TABLES4_END = [
    # By default no IPv4 in external, except for IPSec
    (
        "EXTERNAL",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT"
        ),
    ),
    # No IPv4 in CORE
    (
        "CORE",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A FORWARD -i xfrm0 -j ACCEPT\n"
            "-A FORWARD -i xfrm1 -j ACCEPT\n"
            "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
        ),
    ),
    # No IPv4 in C0001-00, even though we do NAT64. These are handled by Jool before iptables
    # forwards traffic
    (
        "E0001-00",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p icmp -j ACCEPT\n"
            "-A INPUT -i eth2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A FORWARD -i E0001-00_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o eth2 -p tcp -m tcp --dport 22 -j ACCEPT"
        ),
    ),
]

TABLES6_ICMPV6_IN_OUT = (
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 4 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 131 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 132 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j ACCEPT\n"
    "-A icmpv6-in-out -p ipv6-icmp -j DROP"
)

TABLES6_CORE_EXT = [
    # By default no IPv6 in external, except for IPSec AND the required and recommended ICMPv6
    # according to https://www.rfc-editor.org/rfc/rfc4890
    (
        "EXTERNAL",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            # Filter ICMPv6
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            # Allow IPSec
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    # Allow traffic input/output to/from the uplink, as well as related return traffic.
    (
        "CORE",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT ACCEPT\n"
            "-N icmpv6-forward\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i xfrm0 -j ACCEPT\n"
            "-A INPUT -i xfrm1 -j ACCEPT\n"
            "-A FORWARD -j icmpv6-forward\n"
            "-A FORWARD -i xfrm0 -j ACCEPT\n"
            "-A FORWARD -i xfrm1 -j ACCEPT\n"
            "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 4 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j ACCEPT\n"
            "-A icmpv6-forward -p ipv6-icmp -j DROP\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
]


TABLES6_HUB = [
    *TABLES6_CORE_EXT,
    # No IPv6 in C0001-xx, except for traffic from the veth uplink and related traffic.
    (
        "C0001-00",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i tun1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A INPUT -i xfrm0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A FORWARD -i C0001-00_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o tun1 -p tcp -m tcp --dport 22 -j ACCEPT\n"
            "-A OUTPUT -o xfrm0 -p tcp -m tcp --dport 22 -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    (
        "C0001-01",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i xfrm0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A FORWARD -i C0001-01_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o xfrm0 -p tcp -m tcp --dport 22 -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
]

TABLES6_END = [
    *TABLES6_CORE_EXT,
    (
        "E0001-00",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i eth2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A FORWARD -i E0001-00_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o eth2 -p tcp -m tcp --dport 22 -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
]
