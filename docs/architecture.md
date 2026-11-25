# Architecture

## Modes

vpnc runs in one of two modes, set in the service configuration:

* **`HUB`:** the concentrator. Terminates tunnels from many tenant sites and routes management traffic to them.
* **`ENDPOINT`:** a VPN endpoint at a tenant site, the other end of a hub's connection.

## Network instances

Each network instance is a Linux network namespace with the same name (`ip netns list`), like a VRF:

| Network instance | Purpose |
|---|---|
| `EXTERNAL` | The internet-facing interface; carries the tunnels (IKE/ESP, WireGuard). |
| `CORE` | The uplinks to the management network, with BGP. |
| `C0001-00`, ... | Downlinks (hub): one per tenant network, named `<tenant>-<nn>`. |
| `ENDPOINT` | The tenant side (endpoint mode). |

A downlink namespace is linked to `CORE` by a veth pair. Tunnel interfaces sit in the downlink namespace; their outer (encrypted) packets go out through `EXTERNAL`.

Connections are numbered per network instance (0-9) and named `<network instance>-<n>`, e.g. `C0001-00-0`. Their interfaces in the namespace:

| Type | Interface |
|---|---|
| IPsec | `xfrm<n>` (XFRM interface, route-based) |
| WireGuard | `wg<n>` |
| SSH | `tun<n>` |
| Physical | the configured `interface_name` |

XFRM and WireGuard interfaces are created in `EXTERNAL` and moved into the downlink namespace, so their outer packets use `EXTERNAL` (a WireGuard interface's UDP socket stays in the namespace it was created in). In `EXTERNAL` they have unique names (`x<if_id>`, `wg-<connection>`); they are renamed to `xfrm<n>` and `wg<n>` as they move.

To look around in a namespace:

```bash
~$ sudo ip netns exec C0001-00 ip -br addr
~$ sudo ip netns exec C0001-00 ip route
~$ sudo ip netns exec C0001-00 nft list ruleset
```

## Addressing (hub)

The service settings carve up these prefixes:

| Setting | Per network instance | Use |
|---|---|---|
| `prefix_downlink_nat64` (/32) | /96 | NAT64: tenant IPv4 as IPv6, e.g. `fdcc:0:c:1::/96` for `C0001-00`. |
| `prefix_downlink_nptv6` (/12) | /48 | NPTv6 for tenant IPv6 routes with `nptv6: true`. |
| `prefix_downlink_interface_v4` | /24, a /28 per connection | Tunnel interface addresses; the same for every tenant. |
| `prefix_downlink_interface_v6` | /48, a /64 per connection | Tunnel interface addresses; the same for every tenant. |

Changing `mode` or any `prefix_downlink_*` needs a restart of vpnc.

### NAT64

NAT64 is stateful (Jool), one instance per downlink. Each network instance gets a /96 of `prefix_downlink_nat64`, built from its name: with `fdcc::/32`, `C0001-00` gets `fdcc:0:c:1::/96`, `C0001-01` gets `fdcc:0:c:1:1::/96` and `C0123-05` gets `fdcc:0:c:123:5::/96`.

The last 32 bits of the address are the tenant's IPv4 address, so you can type it in dotted form after the prefix (IPv6 mixed notation, RFC 4291):

| Tenant address | Type | Same address, native IPv6 |
|---|---|---|
| `10.0.0.1` in `C0001-00` | `fdcc:0:c:1::10.0.0.1` | `fdcc:0:c:1::a00:1` |
| `192.168.1.10` in `C0001-01` | `fdcc:0:c:1:1::192.168.1.10` | `fdcc:0:c:1:1:0:c0a8:10a` |

Both forms are the same address; tools such as `ping`, `ssh` and browsers (`https://[fdcc:0:c:1::10.0.0.1]/`) take either. Output (DNS answers, `ip`, `vpnctl`) shows the native form. `vpnctl translate` converts both ways.

### NPTv6

Tenant IPv6 routes with `nptv6: true` (the default) get a prefix out of the network instance's /48. NPTv6 here maps the destination prefix 1:1 and masquerades the source; it's stateful (conntrack), not RFC 6296. This way there is an extra layer stopping traffic from flowing in the wrong direction.

Global unicast routes with `nptv6: false` are routed as they are.

## Traffic direction

Connections can only be opened from management to tenants: never from a tenant to management, nor between tenants. This is enforced with nftables and conntrack in each namespace; `vpnctl firewall C0001-00` shows the rules and their counters.

## Routing and BGP (hub)

FRR runs BGP in the `CORE` VRF, IPv6 unicast only, with the service's `bgp.neighbors` as one peer group (timers 10/30, optional BFD and TCP MD5).

* **Advertised:** the NAT64 /96s, the NPTv6 prefixes (/48 or longer) and global unicast routes (2000::/3, /32 or longer) of the network instances. Nothing else is let out.
* **Accepted:** only the prefixes in the IPv6 routes of the `CORE` connections (up to /64). These routes are copied into every downlink namespace, toward `CORE`.
* **Down connections:** a connection's routes in its namespace become blackholes while it doesn't pass traffic. In `CORE`, a network instance's prefixes become blackholes unless all its connections pass traffic, and are then advertised with the AS path prepended 10 times, so the other hub wins.
* **Path selection,** per neighbor: `local_pref` (default 100) on the routes received, for traffic from vpnc. On the routes advertised, for traffic to vpnc: `as_path_prepend` (0-9) prepends the AS that many times, and `med` sets the MED (default 1024, the route's metric), which peers only compare between paths from the same AS.

`vpnctl bgp neighbors` and `vpnctl bgp routes` show the state. For HA, run two hubs with the same tenants and let BGP choose.

## DNS doctoring

vpncmangle (hub only, started by vpnc in `CORE`) rewrites DNS answers from tenants on their way to admins:

* A records become AAAA records in the network instance's NAT64 prefix.
* AAAA records get the NPTv6 prefix.

Only over UDP: DNS over TCP to tenants is refused. What a network instance's answers may cost is limited (the service's `dns` settings), so one tenant's DNS server can't stop the others' answers. See [vpncmangle/README.md](../vpncmangle/README.md).

## Daemons

| Daemon | Runs as | Does |
|---|---|---|
| vpnc | root (systemd unit `ncubed-vpnc`) | Reconciles namespaces, interfaces, routes and nftables with the configuration; runs a full check every 30 seconds; serves the API |
| charon (strongSwan) | `vpnc-swan` | IKE; started by vpnc |
| ssh | `vpnc-ssh` | SSH tunnels |
| vpncmangle | `vpnc-mangle` | DNS doctoring (hub) |
| FRR | | BGP (hub) |
| snmpd | | SNMP, with vpnc as AgentX subagent |

charon, ssh and vpncmangle only have the privileges to configure the network. See [Security](security.md).
