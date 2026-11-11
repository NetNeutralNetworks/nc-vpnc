# nc-vpnc

vpnc (VPN concentrator) connects a management network to many tenant networks. Every tenant network gets a unique IPv6 prefix, so overlapping IPv4 space and unique local IPv6 addresses don't clash.

* **One entry point:** admins reach every tenant through vpnc, without a VPN client per tenant.
* **Several networks per tenant:** a tenant has one or more network instances, each with its own connections.
* **IPv6 inside:** tenant IPv4 is reached through NAT64, tenant IPv6 through NPTv6 or as is (global unicast).
* **Connections:** IPsec, WireGuard and physical interfaces. An SSH tunnel can run over another connection.
* **DNS doctoring:** DNS answers from a tenant are rewritten to the addresses that reach it, so nobody has to remember the translated addresses.
* **Routing:** the reachable prefixes are advertised to the management network with BGP.

vpnc is not:

* **A firewall:** it only makes sure that connections are opened from management to tenants, never the other way or between tenants. Put a firewall in front of it for inspection and user-based rules.
* **A client VPN:** admins connect to a firewall or VPN gateway, which routes to vpnc: client > firewall > vpnc > tenant.
* **A general router.**
* **HA by itself:** run two hubs and let BGP choose.

## How it works

vpnc runs in `hub` mode (the concentrator) or `endpoint` mode (a VPN endpoint at a tenant site). Each network instance is a Linux network namespace:

| Network instance | Purpose |
|---|---|
| `EXTERNAL` | The internet-facing interface; carries the tunnels. |
| `CORE` | The uplinks to the management network, with BGP. |
| `C0001-00`, ... | Downlinks (hub): one per tenant network, named `<tenant>-<nn>`. |
| `ENDPOINT` | The tenant side (endpoint mode). |

Connections are numbered per network instance (0-9) and named `<network instance>-<n>`, e.g. `C0001-00-0`.

```
admins ── firewall ── CORE ═══ vpnc ═══ EXTERNAL ── internet ── tenant sites
                      (BGP)    C0001-00, C0001-01, C0002-00 ...
```

Addressing in hub mode, from the service settings:

| Setting | Per network instance | Use |
|---|---|---|
| `prefix_downlink_nat64` (/32) | /96 | NAT64: tenant IPv4 as IPv6, e.g. `fdcc:0:c:1::/96` for `C0001-00`. |
| `prefix_downlink_nptv6` (/12) | /48 | NPTv6 for tenant IPv6 routes with `nptv6: true`. |
| `prefix_downlink_interface_v4` | /24, a /28 per connection | Tunnel interface addresses; the same for every tenant. |
| `prefix_downlink_interface_v6` | /48, a /64 per connection | Tunnel interface addresses; the same for every tenant. |

vpncmangle (started by vpnc) rewrites DNS answers from tenants: A records become AAAA records in the NAT64 prefix, and AAAA records get the NPTv6 prefix. See [vpncmangle/README.md](vpncmangle/README.md).

## Installation

vpnc runs on Ubuntu 24.04 or 26.04 with systemd. As root:

```bash
~$ ./install.sh hub       # or: endpoint
```

This installs vpnc in `/opt/ncubed/vpnc`, `vpnctl` on the PATH and an example service configuration, and starts vpnc. Upgrade by running it again. Then configure the service:

```bash
~$ sudo vpnctl config edit service
~$ sudo vpnctl config commit service
~$ sudo vpnctl service restart
```

## Configuration

The configuration is YAML, one file per tenant plus `service` (the `DEFAULT` file). Change it with `vpnctl` or the API: changes are validated, staged and applied on commit (see [vpnctl](#vpnctl)). Service settings `mode` and `prefix_downlink_*` need a restart; everything else applies right away.

Examples: [config-hub.yaml.example](config/vpnc/config/config-hub.yaml.example), [config-endpoint.yaml.example](config/vpnc/config/config-endpoint.yaml.example) and the tenant [config.yaml.example](config/vpnc/config/config.yaml.example).

### Service

```yaml
version: 0.1.3
id: DEFAULT
name: DEFAULT
mode: hub                     # hub | endpoint
local_id: "%any"              # IKE identity, default for all connections
network_instances:            # EXTERNAL and CORE (and ENDPOINT in endpoint mode)
  EXTERNAL: {...}             # see Network instances
  CORE: {...}
# Hub mode only:
prefix_downlink_interface_v4: 100.64.0.0/10
prefix_downlink_interface_v6: fdcc:cbe::/32
prefix_downlink_nat64: 64:ff9b::/32
prefix_downlink_nptv6: 660::/12
bgp:
  globals:
    asn: 4200000000           # 4200000000-4294967294
    router_id: 192.0.2.1
    bfd: false
  neighbors:
  - neighbor_address: fd00:1:2::1
    neighbor_asn: 4233333333
    priority: 0               # 0-9, lower is preferred for traffic to vpnc
```

### Tenants

```yaml
version: 0.1.3
id: C0001                     # a-f or 2-9, then 4 digits
name: Healthcare inc.
metadata: {}                  # free key-value pairs, also on network instances and connections
network_instances:
  C0001-00:
    id: C0001-00
    type: downlink
    connections:
      0: {...}                # see Connections
```

### Connections

```yaml
0:
  id: 0                       # 0-9
  interface:                  # optional on downlinks in hub mode (calculated)
    ipv4: [100.99.0.1/28]
    ipv6: [fdcc:cbe::1/64]
  routes:
    ipv4:
    - to: 10.0.0.0/8          # or: default
      via: 192.0.2.1          # physical connections only
    ipv6:
    - to: fdff:db8:c57::/52
      nptv6: true             # translate (default); vpnc adds nptv6_prefix
  config: {...}               # one of the types below
```

| `type` | Settings (defaults) |
|---|---|
| `ipsec` | `remote_addrs`, `psk`, `local_id`, `remote_id`, `ike_version` (2), `ike_proposal` and `ipsec_proposal` (`aes256gcm16-prfsha384-ecp384`), `ike_lifetime` (86400), `ipsec_lifetime` (3600), `initiation` (`start`: initiate and respond; `none`: respond only), `traffic_selectors` (`local`, `remote`; empty means route based) |
| `wireguard` | `remote_addrs`, `private_key`, `public_key`, `local_port` and `remote_port` (51820) |
| `ssh` | `remote_addrs`, `username`, `remote_tunnel_id`, `remote_config` (false: also configure the remote end), `remote_config_interface` (masquerade on the remote end) |
| `physical` | `interface_name` |

`psk` and `private_key` are secrets: hidden in output unless asked for (`--reveal-secrets`), and `vpnctl config set` without a value prompts for them.

## vpnctl

`vpnctl` shows vpnc's state and edits its configuration through vpnc's local API (the Unix socket `/run/vpnc/api.sock`, root only). The install script puts it on the PATH with bash and zsh completion; for a running shell:

```bash
~$ source /etc/bash_completion.d/vpnctl      # bash
~$ source <(vpnctl completion zsh)           # zsh, after compinit
```

State, read live:

```bash
~$ sudo vpnctl status                        # mode, connections up, vpncmangle, restart needed
~$ sudo vpnctl tenants list
~$ sudo vpnctl ni list [C0001]               # network instances
~$ sudo vpnctl ni show C0001-00              # with NAT64 and NPTv6 translations
~$ sudo vpnctl connections list [C0001 | C0001-00] [--state down] [--type ipsec]
~$ sudo vpnctl connections show C0001-00-0   # e.g. IKE and child SAs, traffic counters
~$ sudo vpnctl connections logs C0001-00-0 [-n 100] [-f]   # vpnc's, ssh's and charon's lines
~$ sudo vpnctl bgp neighbors                 # hub mode
~$ sudo vpnctl bgp neighbor fd00:1:2::1      # in detail
~$ sudo vpnctl bgp routes [--received-from|--advertised-to NEIGHBOR]
~$ sudo vpnctl logs [--source vpnc|vpncmangle|charon | --ni C0001-00] [--level warning] [-n 50] [-f]
~$ sudo vpnctl version
```

Troubleshooting inside a network instance (destinations are IP addresses):

```bash
~$ sudo vpnctl routes C0001-00 [-4|-6]       # installed, blackhole etc.
~$ sudo vpnctl ping C0001-00 10.0.0.1 [-c 5] [-s 56]
~$ sudo vpnctl traceroute C0001-00 10.0.0.1
~$ sudo vpnctl tcp C0001-00 10.0.0.1 443     # a TCP connection test
```

VPN connections (IPsec, WireGuard, SSH) can be stopped until they're started again or vpnc restarts, and reset (a new IKE SA, WireGuard or SSH session):

```bash
~$ sudo vpnctl connections stop|start|reset|restart C0001-00-0 [C0001-01 ...]   # network instance/tenant: its VPN connections
~$ sudo vpnctl service restart|stop                                            # vpnc itself (systemd)
```

Configuration, per tenant (e.g. `C0001`) or `service` (the DEFAULT file). Changes are staged in the candidate configuration; a commit makes them active, and vpnc applies them. Service changes may need a restart. Paths are dotted, with list items by index; values are YAML.

```bash
~$ sudo vpnctl config list                   # tenants and their staged changes
~$ sudo vpnctl config show C0001 [PATH] [--candidate] [--reveal-secrets]
~$ sudo vpnctl config edit C0001 [PATH]      # in $EDITOR, validated; a new id creates a tenant
~$ sudo vpnctl config set C0001 network_instances.C0001-00.connections.0.routes.ipv4.0.to 10.0.0.0/24
~$ sudo vpnctl config set C0001 network_instances.C0001-00.connections.0.config.psk   # prompts, e.g. for a secret
~$ sudo vpnctl config delete C0001 [PATH]    # without a path: the tenant
~$ sudo vpnctl config diff C0001
~$ sudo vpnctl config commit C0001|--all [--confirm 5m]   # rolled back unless confirmed in time
~$ sudo vpnctl config confirm C0001|--all
~$ sudo vpnctl config discard C0001|--all
~$ sudo vpnctl config history C0001 [REVISION]     # the last 5 replaced configurations
~$ sudo vpnctl config restore C0001 REVISION       # stages it; commit to apply
```

Every command takes `-o table|wide|json|yaml`.

## API

vpnctl uses vpnc's local REST API on the Unix socket `/run/vpnc/api.sock` (root only). The OpenAPI schema is at `/openapi.json`; errors are RFC 9457 problem details.

```bash
~$ sudo curl --unix-socket /run/vpnc/api.sock http://localhost/v1/status
~$ sudo curl --unix-socket /run/vpnc/api.sock http://localhost/openapi.json
```

| Path | |
|---|---|
| `/v1/status`, `/v1/version` | State and versions |
| `/v1/tenants`, `/v1/network-instances`, `/v1/connections` | Live state; connections also `stop`, `start`, `reset` and `logs` |
| `/v1/config/tenants/{id}`, `/v1/config/service` | Configuration: `GET`, `PUT`, `PATCH` (merge patch), `DELETE`, `diff`, `commit`, `confirm`, `discard`, `history` |
| `/v1/bgp/...` | Neighbors and routes |
| `/v1/network-instances/{id}/routes`, `ping`, `traceroute`, `tcp` | Troubleshooting |
| `/v1/logs` | Logs |

## Files

| Path | |
|---|---|
| `/opt/ncubed/vpnc/` | The installation (virtualenv); `vpnctl` is linked to `/usr/local/bin` |
| `/opt/ncubed/config/vpnc/` | Configuration: `active`, `candidate` (staged) and `history` |
| `/var/log/ncubed/vpnc/` | `vpnc.log`, `vpncmangle.log` and `charon.log` (strongSwan) |
| `/run/vpnc/api.sock` | The API |

## Development

The lab tests run in containerlab; see [test/README.md](test/README.md).
