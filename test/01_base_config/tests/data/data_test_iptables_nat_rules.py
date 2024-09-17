TABLES4_HUB = [
    # No IPv4 NAT for hubs.
    (
        "EXTERNAL",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "CORE",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "C0001-00",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "C0001-01",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
]
TABLES4_END = [
    # Limited IPv4 NAT for endpoints.
    (
        "EXTERNAL",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "CORE",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "ENDPOINT",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
            "-A POSTROUTING -o eth2 -j MASQUERADE"
        ),
    ),
]

TABLES6_HUB = [
    (
        "EXTERNAL",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "CORE",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    # Perform NPTv6 before doing the masquerade. The masquerade always has to be at the
    # end of the chain.
    (
        "C0001-00",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
            "-A PREROUTING -d fd6c:1::/52 -i C0001-00_D -j NETMAP --to fdff:db8:c57::/52\n"
            "-A PREROUTING -d fd6c:1:0:1000::/52 -i C0001-00_D -j NETMAP --to fdff:db8:c57:1000::/52\n"
            "-A PREROUTING -d fd6c:1:0:2000::/56 -i C0001-00_D -j NETMAP --to fdff:db8:c57:2000::/56\n"
            "-A PREROUTING -d fd6c:1:0:3000::/52 -i C0001-00_D -j NETMAP --to fdff:db8:c57:3000::/52\n"
            "-A POSTROUTING -o tun1 -j MASQUERADE\n"
            "-A POSTROUTING -o xfrm0 -j MASQUERADE"
        ),
    ),
    (
        "C0001-01",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
            "-A PREROUTING -d fd6c:1:1::/52 -i C0001-01_D -j NETMAP --to fdff:db8:c58::/52\n"
            "-A PREROUTING -d fd6c:1:1:1000::/52 -i C0001-01_D -j NETMAP --to fdff:db8:c58:1000::/52\n"
            "-A PREROUTING -d fd6c:1:1:2000::/56 -i C0001-01_D -j NETMAP --to fdff:db8:c58:2000::/56\n"
            "-A PREROUTING -d fd6c:1:1:3000::/52 -i C0001-01_D -j NETMAP --to fdff:db8:c58:3000::/52\n"
            "-A POSTROUTING -o xfrm0 -j MASQUERADE"
        ),
    ),
]
TABLES6_END = [
    # Perform NAT66 masquerade at the end.
    (
        "EXTERNAL",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "CORE",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT"
        ),
    ),
    (
        "ENDPOINT",
        (
            "-P PREROUTING ACCEPT\n"
            "-P INPUT ACCEPT\n"
            "-P OUTPUT ACCEPT\n"
            "-P POSTROUTING ACCEPT\n"
            "-A POSTROUTING -o eth2 -j MASQUERADE"
        ),
    ),
]
