
TESTDATA_ROUTES = [
        (
            "hub00",
            "EXTERNAL",
            {
                ("default", "192.0.2.1", "eth1", None),
                ("default", "2001:db8::1", "eth1", None),
            },
        ),
        (
            "hub00",
            "CORE",
            {
                # Uplink route via BGP, preferred via xfrm0
                ("fd00::/16", None, "xfrm0", "bgp"),
                # routes for C0001-00
                ("2001:db8:c57::/48", "fe80::1", "C0001-00_C", None),
                ("fd6c:1::/48", "fe80::1", "C0001-00_C", None),
                ("fdcc:0:c:1::/96", "fe80::1", "C0001-00_C", None),
                # routes for C0001-01
                ("2001:db8:c58::/48", "fe80::1", "C0001-01_C", None),
                ("fd6c:1:1::/48", "fe80::1", "C0001-01_C", None),
                ("fdcc:0:c:1:1::/96", "fe80::1", "C0001-01_C", None),
            },
        ),
        (
            "hub00",
            "C0001-00",
            {
                # Uplink to CORE
                ("fd00::/16", "fe80::", "C0001-00_D", None),
                # IPv4 routes
                ("default", None, "xfrm0", None),
                # IPv6 routes
                ("2001:db8:c57::/48", None, "xfrm0", None),
                ("fdff:db8:c57::/52", None, "xfrm0", None),
                ("fdff:db8:c57:1000::/52", None, "xfrm0", None),
                ("fdff:db8:c57:2000::/56", None, "xfrm0", None),
                ("fdff:db8:c57:3000::/52", None, "xfrm0", None),
            },
        ),
        (
            "hub00",
            "C0001-01",
            {
                # Uplink to CORE
                ("fd00::/16", "fe80::", "C0001-01_D", None),
                # IPv4 routes
                ("default", None, "xfrm0", None),
                # IPv6 routes
                ("2001:db8:c58::/48", None, "xfrm0", None),
                ("fdff:db8:c58::/52", None, "xfrm0", None),
                ("fdff:db8:c58:2000::/56", None, "xfrm0", None),
                ("fdff:db8:c58:1000::/52", None, "xfrm0", None),
                ("fdff:db8:c58:3000::/52", None, "xfrm0", None),
            },
        ),
        (
            "hub01",
            "EXTERNAL",
            {
                ("default", "192.0.2.1", "eth1", None),
                ("default", "2001:db8::1", "eth1", None),
            },
        ),
        (
            "hub01",
            "CORE",
            {
                # Uplink route via BGP, preferred via xfrm1
                ("fd00::/16", None, "xfrm1", "bgp"),
                # routes for C0001-00
                ("2001:db8:c57::/48", "fe80::1", "C0001-00_C", None),
                ("fd6c:1::/48", "fe80::1", "C0001-00_C", None),
                ("fdcc:0:c:1::/96", "fe80::1", "C0001-00_C", None),
                # routes for C0001-01
                ("2001:db8:c58::/48", "fe80::1", "C0001-01_C", None),
                ("fd6c:1:1::/48", "fe80::1", "C0001-01_C", None),
                ("fdcc:0:c:1:1::/96", "fe80::1", "C0001-01_C", None),
            },
        ),
        (
            "hub01",
            "C0001-00",
            {
                # Uplink to CORE
                ("fd00::/16", "fe80::", "C0001-00_D", None),
                # IPv4 routes
                ("default", None, "xfrm0", None),
                # IPv6 routes
                ("2001:db8:c57::/48", None, "xfrm0", None),
                ("fdff:db8:c57::/52", None, "xfrm0", None),
                ("fdff:db8:c57:1000::/52", None, "xfrm0", None),
                ("fdff:db8:c57:2000::/56", None, "xfrm0", None),
                ("fdff:db8:c57:3000::/52", None, "xfrm0", None),
            },
        ),
        (
            "hub01",
            "C0001-01",
            {
                # Uplink to CORE
                ("fd00::/16", "fe80::", "C0001-01_D", None),
                # IPv4 routes
                ("default", None, "xfrm0", None),
                # IPv6 routes
                ("2001:db8:c58::/48", None, "xfrm0", None),
                ("fdff:db8:c58::/52", None, "xfrm0", None),
                ("fdff:db8:c58:2000::/56", None, "xfrm0", None),
                ("fdff:db8:c58:1000::/52", None, "xfrm0", None),
                ("fdff:db8:c58:3000::/52", None, "xfrm0", None),
            },
        ),
        (
            "end00",
            "EXTERNAL",
            {
                ("default", "192.0.2.1", "eth1", None),
                ("default", "2001:db8::1", "eth1", None),
            },
        ),
        (
            "end00",
            "CORE",
            {
                # Uplink IPv4 routes
                ("100.99.0.0/28", None, "xfrm0", None),
                ("100.100.0.0/28", None, "xfrm1", None),
                # Uplink IPv6 routes
                ("fdcc:cbf::/64", None, "xfrm1", None),
                ("fdcc:cbe::/64", None, "xfrm0", None),
                # Downlink routes
                ("default", "169.254.0.2", "E0001-00_C", None),
                ("default", "fe80::1", "E0001-00_C", None),
            },
        ),
        (
            "end00",
            "E0001-00",
            {
                # IPv4 uplink to CORE
                ("100.99.0.0/28", "169.254.0.1", "E0001-00_D", None),
                ("100.100.0.0/28", "169.254.0.1", "E0001-00_D", None),
                # IPv6 uplink to CORE
                ("fdcc:cbe::/64", "fe80::", "E0001-00_D", None),
                ("fdcc:cbf::/64", "fe80::", "E0001-00_D", None),
                # IPv4 routes
                ("default", "172.16.30.1", "eth2", None),
                # IPv6 routes
                ("default", "fdff:db8:c57::1", "eth2", None),
            },
        ),
        (
            "end01",
            "EXTERNAL",
            {
                ("default", "192.0.2.1", "eth1", None),
                ("default", "2001:db8::1", "eth1", None),
            },
        ),
        (
            "end01",
            "CORE",
            {
                # Uplink IPv4 routes
                ("100.99.1.0/28", None, "xfrm0", None),
                ("100.100.1.0/28", None, "xfrm1", None),
                # Uplink IPv6 routes
                ("fdcc:cbf:1::/64", None, "xfrm1", None),
                ("fdcc:cbe:1::/64", None, "xfrm0", None),
                # Downlink routes
                ("default", "169.254.0.2", "E0001-00_C", None),
                ("default", "fe80::1", "E0001-00_C", None),
            },
        ),
        (
            "end01",
            "E0001-00",
            {
                # IPv4 uplink to CORE
                ("100.99.1.0/28", "169.254.0.1", "E0001-00_D", None),
                ("100.100.1.0/28", "169.254.0.1", "E0001-00_D", None),
                # IPv6 uplink to CORE
                ("fdcc:cbe:1::/64", "fe80::", "E0001-00_D", None),
                ("fdcc:cbf:1::/64", "fe80::", "E0001-00_D", None),
                # IPv4 routes
                ("default", "172.17.30.1", "eth2", None),
                # IPv6 routes
                ("default", "fdff:db8:c58::1", "eth2", None),
            },
        ),
    ]
