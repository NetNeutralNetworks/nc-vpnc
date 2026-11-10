TESTDATA_ROUTES = [
    (
        "hub00",
        "EXTERNAL",
        {
            ("default", "192.0.2.1", "eth1", "vpnc"),
            ("default", "2001:db8::1", "eth1", "vpnc"),
        },
    ),
    (
        "hub00",
        "CORE",
        {
            # Uplink route via BGP, preferred via xfrm0
            ("fd00::/16", None, "xfrm0", "bgp"),
            # routes for C0001-00
            ("2001:db8:c57::/48", "fe80::1", "C0001-00_C", "vpnc"),
            # ("fd6c:1::/48", "fe80::1", "C0001-00_C", None),
            ("fd6c:1::/52", "fe80::1", "C0001-00_C", "vpnc"),
            ("fd6c:1:0:1000::/52", "fe80::1", "C0001-00_C", "vpnc"),
            ("fd6c:1:0:2000::/56", "fe80::1", "C0001-00_C", "vpnc"),
            ("fd6c:1:0:3000::/52", "fe80::1", "C0001-00_C", "vpnc"),
            ("fdcc:0:c:1::/96", "fe80::1", "C0001-00_C", "vpnc"),
            # routes for C0001-01
            ("2001:db8:c58::/48", "fe80::1", "C0001-01_C", "vpnc"),
            # ("fd6c:1:1::/48", "fe80::1", "C0001-01_C", None),
            ("fd6c:1:1::/52", "fe80::1", "C0001-01_C", "vpnc"),
            ("fd6c:1:1:1000::/52", "fe80::1", "C0001-01_C", "vpnc"),
            ("fd6c:1:1:2000::/56", "fe80::1", "C0001-01_C", "vpnc"),
            ("fd6c:1:1:3000::/52", "fe80::1", "C0001-01_C", "vpnc"),
            ("fdcc:0:c:1:1::/96", "fe80::1", "C0001-01_C", "vpnc"),
        },
    ),
    (
        "hub00",
        "C0001-00",
        {
            # Uplink to CORE
            ("fd00::/16", "fe80::", "C0001-00_D", "vpnc"),
            # IPv4 routes
            ("default", None, "tun1", "vpnc"),
            ("172.16.30.1", None, "xfrm0", "vpnc"),
            # IPv6 routes
            ("2001:db8:c57::/48", None, "tun1", "vpnc"),
            ("fdff:db8:c57::/52", None, "tun1", "vpnc"),
            ("fdff:db8:c57:1000::/52", None, "tun1", "vpnc"),
            ("fdff:db8:c57:2000::/56", None, "tun1", "vpnc"),
            ("fdff:db8:c57:3000::/52", None, "tun1", "vpnc"),
        },
    ),
    (
        "hub00",
        "C0001-01",
        {
            # Uplink to CORE
            ("fd00::/16", "fe80::", "C0001-01_D", "vpnc"),
            # IPv4 routes
            ("default", None, "wg-C0001-01-0", "vpnc"),
            # IPv6 routes
            ("2001:db8:c58::/48", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58::/52", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58:2000::/56", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58:1000::/52", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58:3000::/52", None, "wg-C0001-01-0", "vpnc"),
        },
    ),
    (
        "hub01",
        "EXTERNAL",
        {
            ("default", "192.0.2.1", "eth1", "vpnc"),
            ("default", "2001:db8::1", "eth1", "vpnc"),
        },
    ),
    (
        "hub01",
        "CORE",
        {
            # Uplink route via BGP, preferred via xfrm1
            ("fd00::/16", None, "xfrm1", "bgp"),
            # routes for C0001-00
            ("2001:db8:c57::/48", "fe80::1", "C0001-00_C", "vpnc"),
            ("fd6c:1::/52", "fe80::1", "C0001-00_C", "vpnc"),
            ("fd6c:1:0:1000::/52", "fe80::1", "C0001-00_C", "vpnc"),
            ("fd6c:1:0:2000::/56", "fe80::1", "C0001-00_C", "vpnc"),
            ("fd6c:1:0:3000::/52", "fe80::1", "C0001-00_C", "vpnc"),
            ("fdcc:0:c:1::/96", "fe80::1", "C0001-00_C", "vpnc"),
            # routes for C0001-01
            ("2001:db8:c58::/48", "fe80::1", "C0001-01_C", "vpnc"),
            ("fd6c:1:1::/52", "fe80::1", "C0001-01_C", "vpnc"),
            ("fd6c:1:1:1000::/52", "fe80::1", "C0001-01_C", "vpnc"),
            ("fd6c:1:1:2000::/56", "fe80::1", "C0001-01_C", "vpnc"),
            ("fd6c:1:1:3000::/52", "fe80::1", "C0001-01_C", "vpnc"),
            ("fdcc:0:c:1:1::/96", "fe80::1", "C0001-01_C", "vpnc"),
        },
    ),
    (
        "hub01",
        "C0001-00",
        {
            # Uplink to CORE
            ("fd00::/16", "fe80::", "C0001-00_D", "vpnc"),
            # IPv4 routes
            ("default", None, "tun1", "vpnc"),
            ("172.16.30.1", None, "xfrm0", "vpnc"),
            # IPv6 routes
            ("2001:db8:c57::/48", None, "tun1", "vpnc"),
            ("fdff:db8:c57::/52", None, "tun1", "vpnc"),
            ("fdff:db8:c57:1000::/52", None, "tun1", "vpnc"),
            ("fdff:db8:c57:2000::/56", None, "tun1", "vpnc"),
            ("fdff:db8:c57:3000::/52", None, "tun1", "vpnc"),
        },
    ),
    (
        "hub01",
        "C0001-01",
        {
            # Uplink to CORE
            ("fd00::/16", "fe80::", "C0001-01_D", "vpnc"),
            # IPv4 routes
            ("default", None, "wg-C0001-01-0", "vpnc"),
            # IPv6 routes
            ("2001:db8:c58::/48", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58::/52", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58:2000::/56", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58:1000::/52", None, "wg-C0001-01-0", "vpnc"),
            ("fdff:db8:c58:3000::/52", None, "wg-C0001-01-0", "vpnc"),
        },
    ),
    (
        "end00",
        "EXTERNAL",
        {
            ("default", "192.0.2.1", "eth1", "vpnc"),
            ("default", "2001:db8::1", "eth1", "vpnc"),
        },
    ),
    (
        "end00",
        "CORE",
        {
            # Uplink IPv4 routes
            ("100.99.0.0/28", None, "xfrm0", "vpnc"),
            ("100.100.0.0/28", None, "xfrm1", "vpnc"),
            # Uplink IPv6 routes
            ("fdcc:cbf::/64", None, "xfrm1", "vpnc"),
            ("fdcc:cbe::/64", None, "xfrm0", "vpnc"),
            # Downlink routes
            ("default", "169.254.0.2", "ENDPOINT_C", "vpnc"),
            ("default", "fe80::1", "ENDPOINT_C", "vpnc"),
        },
    ),
    (
        "end00",
        "ENDPOINT",
        {
            # IPv4 uplink to CORE
            ("100.99.0.0/28", "169.254.0.1", "ENDPOINT_D", "vpnc"),
            ("100.100.0.0/28", "169.254.0.1", "ENDPOINT_D", "vpnc"),
            # IPv6 uplink to CORE
            ("fdcc:cbe::/64", "fe80::", "ENDPOINT_D", "vpnc"),
            ("fdcc:cbf::/64", "fe80::", "ENDPOINT_D", "vpnc"),
            # IPv4 routes
            ("default", "172.16.30.1", "eth2", "vpnc"),
            # IPv6 routes
            ("default", "fdff:db8:c57::1", "eth2", "vpnc"),
        },
    ),
    (
        "end01",
        "EXTERNAL",
        {
            ("default", "192.0.2.1", "eth1", "vpnc"),
            ("default", "2001:db8::1", "eth1", "vpnc"),
        },
    ),
    (
        "end01",
        "CORE",
        {
            # Uplink IPv4 routes
            ("100.99.1.0/28", None, "wg-CORE-0", "vpnc"),
            ("100.100.1.0/28", None, "wg-CORE-1", "vpnc"),
            # Uplink IPv6 routes
            ("fdcc:cbf:1::/64", None, "wg-CORE-1", "vpnc"),
            ("fdcc:cbe:1::/64", None, "wg-CORE-0", "vpnc"),
            # Downlink routes
            ("default", "169.254.0.2", "ENDPOINT_C", "vpnc"),
            ("default", "fe80::1", "ENDPOINT_C", "vpnc"),
        },
    ),
    (
        "end01",
        "ENDPOINT",
        {
            # IPv4 uplink to CORE
            ("100.99.1.0/28", "169.254.0.1", "ENDPOINT_D", "vpnc"),
            ("100.100.1.0/28", "169.254.0.1", "ENDPOINT_D", "vpnc"),
            # IPv6 uplink to CORE
            ("fdcc:cbe:1::/64", "fe80::", "ENDPOINT_D", "vpnc"),
            ("fdcc:cbf:1::/64", "fe80::", "ENDPOINT_D", "vpnc"),
            # IPv4 routes
            ("default", "172.17.30.1", "eth2", "vpnc"),
            # IPv6 routes
            ("default", "fdff:db8:c58::1", "eth2", "vpnc"),
        },
    ),
]
