TABLES4_HUB = [
    # By default no IPv4 in external, except for IPSec
    (
        "hub00",
        "EXTERNAL",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        ),
    ),
    # No IPv4 in CORE
    ("hub00", "CORE", ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP")),
    # No IPv4 in C0001-00, even though we do NAT64. These are handled by Jool before
    # iptables forwards traffic
    (
        "hub00",
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
        "hub00",
        "C0001-01",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -i wg-C0001-01-0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o wg-C0001-01-0 -p tcp -m tcp --dport 22 -j ACCEPT"
        ),
    ),
    # By default no IPv4 in external, except for IPSec
    (
        "hub01",
        "EXTERNAL",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        ),
    ),
    # No IPv4 in CORE
    ("hub01", "CORE", ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP")),
    # No IPv4 in C0001-00, even though we do NAT64. These are handled by Jool before
    # iptables forwards traffic
    (
        "hub01",
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
        "hub01",
        "C0001-01",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -i wg-C0001-01-0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o wg-C0001-01-0 -p tcp -m tcp --dport 22 -j ACCEPT"
        ),
    ),
]

TABLES4_ENDPOINT = [
    # By default no IPv4 in external, except for IPSec
    (
        "end00",
        "EXTERNAL",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        ),
    ),
    # No IPv4 in CORE
    (
        "end00",
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
        "end00",
        "ENDPOINT",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p icmp -j ACCEPT\n"
            "-A FORWARD -i ENDPOINT_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        ),
    ),
    # By default no IPv4 in external, except for IPSec
    (
        "end01",
        "EXTERNAL",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p esp -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        ),
    ),
    # No IPv4 in CORE
    (
        "end01",
        "CORE",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A FORWARD -i wg-CORE-0 -j ACCEPT\n"
            "-A FORWARD -i wg-CORE-1 -j ACCEPT\n"
            "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
        ),
    ),
    # No IPv4 in C0001-00, even though we do NAT64. These are handled by Jool before iptables
    # forwards traffic
    (
        "end01",
        "ENDPOINT",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-A INPUT -p icmp -j ACCEPT\n"
            "-A FORWARD -i ENDPOINT_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
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


TABLES6_HUB = [
    (
        "hub00",
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
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    # Allow traffic input/output to/from the uplink, as well as related return traffic.
    (
        "hub00",
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
    # No IPv6 in C0001-xx, except for traffic from the veth uplink and related traffic.
    (
        "hub00",
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
        "hub00",
        "C0001-01",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i wg-C0001-01-0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A FORWARD -i C0001-01_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o wg-C0001-01-0 -p tcp -m tcp --dport 22 -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    (
        "hub01",
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
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    # Allow traffic input/output to/from the uplink, as well as related return traffic.
    (
        "hub01",
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
    (
        "hub01",
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
        "hub01",
        "C0001-01",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i wg-C0001-01-0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A FORWARD -i C0001-01_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -o wg-C0001-01-0 -p tcp -m tcp --dport 22 -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
]

TABLES6_ENDPOINT = [
    (
        "end00",
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
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    (
        "end00",
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
    (
        "end00",
        "ENDPOINT",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A FORWARD -i ENDPOINT_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    (
        "end01",
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
            "-A INPUT -p udp -m udp --dport 500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 4500 -j ACCEPT\n"
            "-A INPUT -p udp -m udp --dport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -p esp -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 500 --dport 500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 4500 --dport 4500 -j ACCEPT\n"
            "-A OUTPUT -p udp -m udp --sport 51820:51899 -j ACCEPT\n"
            "-A OUTPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
    (
        "end01",
        "CORE",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT ACCEPT\n"
            "-N icmpv6-forward\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A INPUT -i wg-CORE-0 -j ACCEPT\n"
            "-A INPUT -i wg-CORE-1 -j ACCEPT\n"
            "-A FORWARD -j icmpv6-forward\n"
            "-A FORWARD -i wg-CORE-0 -j ACCEPT\n"
            "-A FORWARD -i wg-CORE-1 -j ACCEPT\n"
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
    (
        "end01",
        "ENDPOINT",
        (
            "-P INPUT DROP\n"
            "-P FORWARD DROP\n"
            "-P OUTPUT DROP\n"
            "-N icmpv6-in-out\n"
            "-A INPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A FORWARD -i ENDPOINT_D -j ACCEPT\n"
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A OUTPUT -p ipv6-icmp -j icmpv6-in-out\n"
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            f"{TABLES6_ICMPV6_IN_OUT}"
        ),
    ),
]
