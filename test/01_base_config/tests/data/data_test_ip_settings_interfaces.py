TESTDATA_INTERFACES = [
    (
        "hub00",
        "EXTERNAL",
        {
            ("lo", "DOWN", frozenset()),
            ("eth1", "UP", frozenset({"2001:db8::5/64", "192.0.2.5/24"})),
        },
    ),
    (
        "hub00",
        "CORE",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset({"fd00:1:2::/127"})),
            ("xfrm1", "UP", frozenset({"fd00:1:2::1:0/127"})),
            ("C0001-00_C", "UP", frozenset({"fe80::/64"})),
            ("C0001-01_C", "UP", frozenset({"fe80::/64"})),
        },
    ),
    (
        "hub00",
        "C0001-00",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset({"100.99.0.1/28", "fdcc:cbe::/64"})),
            ("C0001-00_D", "UP", frozenset({"fe80::1/64"})),
            ("tun1", "UP", frozenset({"100.99.0.17/28", "fdcc:cbe:0:1::/64"})),
        },
    ),
    (
        "hub00",
        "C0001-01",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset({"100.99.1.1/28", "fdcc:cbe:1::/64"})),
            ("C0001-01_D", "UP", frozenset({"fe80::1/64"})),
        },
    ),
    (
        "hub01",
        "EXTERNAL",
        {
            ("lo", "DOWN", frozenset()),
            ("eth1", "UP", frozenset({"2001:db8::6/64", "192.0.2.6/24"})),
        },
    ),
    (
        "hub01",
        "CORE",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset({"fd00:1:2::2/127"})),
            ("xfrm1", "UP", frozenset({"fd00:1:2::1:2/127"})),
            ("C0001-00_C", "UP", frozenset({"fe80::/64"})),
            ("C0001-01_C", "UP", frozenset({"fe80::/64"})),
        },
    ),
    (
        "hub01",
        "C0001-00",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset({"100.100.0.1/28", "fdcc:cbf::/64"})),
            ("C0001-00_D", "UP", frozenset({"fe80::1/64"})),
            ("tun1", "UP", frozenset({"100.100.0.17/28", "fdcc:cbf:0:1::/64"})),
        },
    ),
    (
        "hub01",
        "C0001-01",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset({"100.100.1.1/28", "fdcc:cbf:1::/64"})),
            ("C0001-01_D", "UP", frozenset({"fe80::1/64"})),
        },
    ),
    (
        "end00",
        "EXTERNAL",
        {
            ("lo", "DOWN", frozenset()),
            ("eth1", "UP", frozenset(["2001:db8::7/64", "192.0.2.7/24"])),
        },
    ),
    (
        "end00",
        "CORE",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset()),
            ("xfrm1", "UP", frozenset()),
            ("ENDPOINT_C", "UP", frozenset(["169.254.0.1/30", "fe80::/64"])),
        },
    ),
    (
        "end00",
        "ENDPOINT",
        {
            ("lo", "DOWN", frozenset()),
            (
                "eth2",
                "UP",
                frozenset(
                    {
                        "172.16.30.254/24",
                        "2001:db8:c57::ffff/64",
                        "fdff:db8:c57::ffff/64",
                    },
                ),
            ),
            ("ENDPOINT_D", "UP", frozenset({"169.254.0.2/30", "fe80::1/64"})),
        },
    ),
    (
        "end01",
        "EXTERNAL",
        {
            ("lo", "DOWN", frozenset()),
            ("eth1", "UP", frozenset({"2001:db8::8/64", "192.0.2.8/24"})),
        },
    ),
    (
        "end01",
        "CORE",
        {
            ("lo", "DOWN", frozenset()),
            ("xfrm0", "UP", frozenset()),
            ("xfrm1", "UP", frozenset()),
            ("ENDPOINT_C", "UP", frozenset({"169.254.0.1/30", "fe80::/64"})),
        },
    ),
    (
        "end01",
        "ENDPOINT",
        {
            ("lo", "DOWN", frozenset()),
            (
                "eth2",
                "UP",
                frozenset(
                    {
                        "172.17.30.254/24",
                        "2001:db8:c58::ffff/64",
                        "fdff:db8:c58::ffff/64",
                    },
                ),
            ),
            ("ENDPOINT_D", "UP", frozenset({"169.254.0.2/30", "fe80::1/64"})),
        },
    ),
]
