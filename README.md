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

NPTv6 here maps the destination prefix 1:1 and masquerades the source; it's stateful (conntrack), not RFC 6296.

vpncmangle (started by vpnc) rewrites DNS answers from tenants: A records become AAAA records in the NAT64 prefix, and AAAA records get the NPTv6 prefix. Only over UDP: DNS over TCP to tenants is refused. It runs as the `vpnc-mangle` account, which can only configure the network. See [vpncmangle/README.md](vpncmangle/README.md).

charon (strongSwan, started by vpnc) runs as the `vpnc-swan` account, which can only configure the network.

## Installation

vpnc runs on Ubuntu 26.04 with systemd. As root, in the repository root:

```bash
~$ apt-get install -y make
~$ make hub               # or: endpoint, addon
```

This upgrades the system packages, installs vpnc in `/opt/ncubed/vpnc`, `vpnctl` on the PATH and an example service configuration, and (re)starts vpnc. Run it again to upgrade everything. To update only vpnc after a `git pull`, without apt:

```bash
~$ make update
```

This reinstalls vpnc (and vpncmangle on a hub) and restarts vpnc only if something changed. Configuration files are only installed when missing, so local edits are kept. The systemd unit is replaced when it changes: put local changes in a drop-in (`systemctl edit ncubed-vpnc`). The Python dependencies are installed at the versions and hashes in the lock files (`requirements*.txt`). Then configure the service:

```bash
~$ sudo vpnctl config edit service
~$ sudo vpnctl config commit service
~$ sudo vpnctl service restart
```

## Configuration

The configuration is YAML, one file per tenant plus `service` (the `DEFAULT` file). Change it with `vpnctl` or the API: changes are validated, staged and applied on commit (see [vpnctl](#vpnctl)). Service settings `mode` and `prefix_downlink_*` need a restart; everything else applies right away. An IPsec connection whose `psk`, PPK or `traffic_selectors` changed is reset (`CONFIG_RESET`): its SAs would keep the old ones, and a wrong value would only show at the next outage. Wider `traffic_selectors` of a responder apply once the initiator is reset too: until then it proposes the ones it had.

Values like `HUB` and `IPSEC` are upper case; lower case is still read. Files have a `version`, currently 0.1.4. vpnc converts files of version 0.1.3 at startup and when they are put in `active/`; the originals are kept in `/opt/ncubed/config/vpnc/backup/`. Other versions are refused.

Examples: [config-hub.yaml.example](config/vpnc/config/config-hub.yaml.example), [config-endpoint.yaml.example](config/vpnc/config/config-endpoint.yaml.example) and the tenant [config.yaml.example](config/vpnc/config/config.yaml.example).

### Service

```yaml
version: 0.1.4
id: DEFAULT
name: DEFAULT
mode: HUB                     # HUB | ENDPOINT
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
version: 0.1.4
id: C0001                     # A-F or 2-9, then 4 digits
name: Healthcare inc.
metadata: {}                  # free key-value pairs, also on network instances and connections
network_instances:
  00:                         # 00-99; the network instance is named C0001-00
    type: DOWNLINK
    connections:
      0: {...}                # see Connections
```

### Connections

```yaml
0:                            # 0-9
  enabled: true               # false: admin down (interface down, VPN not set up)
  mtu: 1400                   # optional; default: the interface's own
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
  probes:                     # optional, downlinks only; see Probes
  - address: 10.0.0.10
    test_type: ICMP           # or TCP, with a port
  config: {...}               # one of the types below
```

| `type` | Settings (defaults) |
|---|---|
| `IPSEC` | `remote_addrs`, `psk`, `local_id`, `remote_id`, `ike_version` (2), `ike_proposal` (`aes256gcm16-prfsha384-ecp384`), `ipsec_proposal` (`aes256gcm16-ecp384`), `ike_lifetime` (86400), `ipsec_lifetime` (3600), `initiation` (`START`: initiate and respond; `NONE`: respond only), `traffic_selectors` (`local`, `remote`; empty means route based), `post_quantum` (see below) |
| `WIREGUARD` | `remote_addrs`, `private_key`, `public_key`, `local_port` and `remote_port` (51820) |
| `SSH` | `remote_addrs`, `username`, `remote_tunnel_id`, `remote_config_interface` (masquerade out of it on the server, in its setup script), `post_quantum` (see below) |
| `PHYSICAL` | `interface_name` |

An SSH connection logs in as `username` and only opens the tunnel: vpnc doesn't configure the server. Set up the server (Ubuntu) once, as root, with the script `vpnctl` makes for the connection:

```bash
~$ sudo vpnctl connections ssh-setup C0001-00-1 [--username vpnc] [--interface eth0] | ssh root@server sh
```

It adds the account with the connection's key, the tunnel's interface and routes, the firewall rules (masquerading out of `--interface`, by default `remote_config_interface`) and an sshd configuration in which the account can only open the tunnel. The script isn't for root: give another account with `--username` and make it the connection's `username`.

ssh runs as the `vpnc-ssh` account, without privileges. Every connection logs in with its own key, which vpnc makes (`/var/lib/vpnc-ssh/.ssh/C0001-00-1`) and the script adds to the account on the server. Run the script again on a server that was set up before connections had their own key: ssh no longer offers the shared keys (`id_*` in that directory, copied from root by earlier versions of `make`), which can be deleted.

`psk`, `private_key` and the PPK `key` are secrets: hidden in output unless asked for (`--reveal-secrets`), and `vpnctl config set` without a value prompts for them.

`EXTERNAL` only accepts IKE and ESP from the `remote_addrs` of IPsec connections, and WireGuard from the `remote_addrs` of WireGuard connections, on their `local_port`. Peers of disabled connections aren't accepted, nor is a WireGuard peer that moves to another address.

### Probes

A VPN can be up without passing traffic. With `probes`, vpnc tests every 30 seconds whether hosts behind a connection answer, while the connection is up:

```yaml
probes:                       # 8 at most
- description: file server    # optional
  address: 10.0.0.10          # in the connection's routes
  test_type: ICMP             # an echo request
- address: 2001:db8:c57::10
  test_type: TCP              # a connection that's opened and closed; refused counts as answered
  port: 443
```

A connection is reset, like `vpnctl connections reset`, when none of its probes is answered for 3 minutes. Each reset that doesn't help doubles the wait, up to 30 minutes. With probes on hosts in different networks, one host that's down doesn't reset the connection.

- Probes are only for the VPN connections of `DOWNLINK` network instances. A connection without probes isn't tested.
- A probe is sent out of the connection's interface, from that interface's IPv4 or IPv6 address, so the other side needs a route back to it. Only the host's own answer through that interface counts.
- The network instance's firewall only lets out what its probes send.
- `vpnctl connections probes` shows each probe's last six tests (3 minutes) with their response time, `vpnctl connections show` the last test, and `vpnctl connections list -o wide` the number answered. `oper_status` isn't affected.

### Post-quantum cryptography

`post_quantum` adds a hybrid ML-KEM key exchange to the classical one, against traffic recorded now and decrypted later with a quantum computer. It requires Ubuntu 26.04 (strongSwan 6, OpenSSH 10): vpnc refuses it, and doesn't set up the connection, where charon or OpenSSH lacks the ML-KEM.

```yaml
post_quantum:
  enabled: true             # default false
  ml_kem: ML_KEM_768        # or ML_KEM_1024 (IPsec only)
  ppk:                      # IPsec only, optional
    id: C0001-00-0-hub00    # sent to the peer: the same on both sides, unique per node;
                            # default: the connection's name and this node's hostname,
                            # written into the configuration on commit
    key: "0x..."            # at least 32 bytes: text, 0x hex or 0s base64; quote it
```

- IPsec: ML-KEM is added to `ike_proposal` and `ipsec_proposal` (RFC 9370), which need a classical key exchange (e.g. `ecp384`); ML-KEM in the proposals themselves is refused. The optional PPK (RFC 8784) is mixed into the keys and required by both sides.
- SSH: only the hybrid `mlkem768x25519-sha256` key exchange is allowed, so a server without it is refused instead of falling back to a classical one.

## vpnctl

`vpnctl` shows vpnc's state and edits its configuration through vpnc's local API (the Unix socket `/run/vpnc/api.sock`, root only). `make` puts it on the PATH with bash and zsh completion; for a running shell:

```bash
~$ source /etc/bash_completion.d/vpnctl      # bash
~$ source <(vpnctl completion zsh)           # zsh, after compinit
```

State, read live:

```bash
~$ sudo vpnctl status                        # mode, connections up, vpncmangle and its DNS answers, restart needed
~$ sudo vpnctl tenants list
~$ sudo vpnctl ni list [C0001]               # network instances
~$ sudo vpnctl ni show C0001-00              # with NAT64 and NPTv6 translations, sessions, firewall drops, DNS answers
~$ sudo vpnctl connections list [C0001 | C0001-00] [--oper-status DOWN] [--admin-status DOWN] [--type IPSEC]   # -o wide: MTU, traffic and its rate, probes answered
~$ sudo vpnctl connections show C0001-00-0   # e.g. last change, session (see below), probes, traffic counters and rates
~$ sudo vpnctl connections probes C0001-00-0 # per probe its tests of the last 3 minutes: result and response time
~$ sudo vpnctl connections diagnose C0001-00-0   # what's wrong: the problem, its details, what was checked
~$ sudo vpnctl connections events C0001-00-0 [--since 6h] [-n 50] [-f]   # its history; also ni events, tenants events
~$ sudo vpnctl events [C0001 | C0001-00 | C0001-00-0 | service] [--event OPER_DOWN]   # of everything, or one subject
~$ sudo vpnctl connections logs C0001-00-0 [-n 100] [-f]   # vpnc's, ssh's and charon's lines
~$ sudo vpnctl connections ssh-setup C0001-00-1 [--username vpnc] [--interface eth0]   # a script that sets up the SSH server for an account
~$ sudo vpnctl bgp neighbors                 # hub mode; per address family
~$ sudo vpnctl bgp neighbor fd00:1:2::1      # in detail
~$ sudo vpnctl bgp routes [--received-from|--advertised-to NEIGHBOR]
~$ sudo vpnctl logs [--source vpnc|vpncmangle|charon | --ni C0001-00] [--level WARNING] [-n 50] [-f]
~$ sudo vpnctl version
```

`connections show` has the same session fields for each VPN type, `-` where the type lacks one or it isn't known: session state and id, local address, identities (IKE ids; WireGuard public keys; the SSH username and the server's host key), encryption, integrity (`-` with an AEAD cipher), key exchange (with ML-KEM and PPK), when it was established and rekeys. Algorithms are as negotiated; WireGuard's are fixed by the protocol. Fields of one type only are shown for that type: PRF and NAT (IPsec), the last handshake and allowed IPs (WireGuard). IPsec adds its child SAs: algorithms, PFS, SPIs, traffic selectors, traffic and rekey time.

Events are what happened to a connection, network instance, tenant or the service: a connection going up or down (`OPER_UP`, `OPER_DOWN`), being enabled, disabled or reset (`ADMIN_UP`, `ADMIN_DOWN`, `RESET` by an administrator, `AUTO_RESET` when stuck, `CONFIG_RESET` for a changed key or traffic selectors), its probes (`PROBES_FAILING`, `PROBES_ANSWERED`), why it failed (see below), a tenant's commits (`CONFIG_COMMITTED`, `CONFIG_CONFIRMED`, `CONFIG_ROLLED_BACK`), a removed network instance (`REMOVED`), a hub's BGP sessions (`BGP_ESTABLISHED`, `BGP_DOWN`, of CORE; noted every full check) and vpnc starting and stopping (`STARTED`, `STOPPED`, of the service). A tenant's events include its network instances', theirs their connections'. They're kept in the journal (also across restarts, as long as the journal keeps them) and show in vpnc's log too.

`connections diagnose` names the problem of a connection, with what's configured next to what the peer sent, what was checked and what charon or ssh reported. Why a connection fails is noted as it happens, from charon's log and ssh's output, and is an event when the reason changes:

| | Reasons |
|---|---|
| IPsec | `NO_RESPONSE`, `NO_RESPONSE_AUTH` (the first exchange is answered, the authentication isn't), `DPD_TIMEOUT`, `CLOSED_BY_PEER`, `AUTH_FAILED_REMOTE` (the peer rejected our PSK, PPK or id), `AUTH_FAILED_LOCAL` (the peer's PSK or PPK is wrong), `AUTH_METHOD_MISMATCH`, `ID_MISMATCH`, `PPK_MISMATCH` (a PPK on one side only, or another id), `IKE_VERSION_MISMATCH`, `IKE_CONFIG_MISMATCH`, `IKE_PROPOSAL_MISMATCH`, `CHILD_PROPOSAL_MISMATCH`, `TS_MISMATCH`, `REJECTED_BY_PEER`, `CHILD_REJECTED_BY_PEER`, `KERNEL_FAILED` |
| SSH | `NO_RESPONSE`, `UNREACHABLE`, `REFUSED`, `PERMISSION_DENIED`, `HOST_KEY_MISMATCH`, `NEGOTIATION_FAILED`, `TUNNEL_REFUSED`, `CLOSED_BY_PEER`, `EXITED` |
| From its state | `ADMIN_DOWN`, `NO_INTERFACE`, `NOT_LOADED`, `ML_KEM_UNSUPPORTED`, `NOT_IN_FIREWALL`, `NO_ROUTE`, `WAITING_FOR_PEER` (a responder the peer doesn't set up), `CONNECTING`, `KEY_MISMATCH` (WireGuard: the peer sends, but no handshake completes), `NO_CARRIER`, and while up: `PROBES_FAILING`, `ONE_WAY_TRAFFIC`, `FLAPPING` |

EXTERNAL's firewall counts the packets of each IPsec and WireGuard peer, so a silent peer is told apart from one whose packets are refused. WireGuard itself never says why a handshake fails.

Troubleshooting inside a network instance (destinations are IP addresses):

```bash
~$ sudo vpnctl routes C0001-00 [-4|-6]       # installed, blackhole etc.
~$ sudo vpnctl ping C0001-00 10.0.0.1 [-c 5] [-s 56]
~$ sudo vpnctl traceroute C0001-00 10.0.0.1
~$ sudo vpnctl tcp C0001-00 10.0.0.1 443     # a TCP connection test
~$ sudo vpnctl sessions C0001-00 [10.0.0.1] [-p tcp]   # NAT64, NPTv6 and routed sessions, as translated
~$ sudo vpnctl firewall C0001-00 [--hits]    # vpnc's rules with their counters, since the firewall last changed
~$ sudo vpnctl translate C0001-00 10.0.0.1   # an address in the tenant as admins reach it
~$ sudo vpnctl translate fdcc:0:c:1::a00:1   # and back: tenant, network instance and address
~$ sudo vpnctl capture C0001-00-0 [-c 20] [-w FILE] [-e -X port 443]   # tcpdump on the connection's interface, with its options and filter
~$ sudo vpnctl capture EXTERNAL esp          # or on all interfaces of a network instance
```

Connections can be stopped and started: this sets `enabled` in their configuration right away, so it lasts until they're started again. VPN connections (IPsec, WireGuard, SSH) can be reset (a new IKE SA, WireGuard or SSH session):

```bash
~$ sudo vpnctl connections stop|start C0001-00-0 [C0001-01 ...]      # network instance/tenant: its VPN connections
~$ sudo vpnctl connections reset|restart C0001-00-0 [C0001-01 ...]
~$ sudo vpnctl service restart|stop                                            # vpnc itself (systemd)
```

Configuration, per tenant (e.g. `C0001`) or `service` (the DEFAULT file). Changes are staged in the candidate configuration; a commit makes them active, and vpnc applies them. Service changes may need a restart. Paths are dotted, with list items by index; values are YAML. Tab completes a path a level at a time (for `set`, also the next item to add) and a value's choices; zsh also shows each key's value, type and default.

```bash
~$ sudo vpnctl config list                   # tenants and their staged changes
~$ sudo vpnctl config show C0001 [PATH] [--candidate] [--reveal-secrets]
~$ sudo vpnctl config edit C0001 [PATH]      # in $EDITOR, validated; a new id creates a tenant
~$ sudo vpnctl config set C0001 network_instances.00.connections.0.routes.ipv4.0.to 10.0.0.0/24
~$ sudo vpnctl config set C0001 network_instances.00.connections.0.config.psk   # prompts, e.g. for a secret
~$ sudo vpnctl config delete C0001 [PATH]    # without a path: the tenant
~$ sudo vpnctl config diff C0001
~$ sudo vpnctl config commit C0001|--all [--confirm 5m]   # rolled back unless confirmed in time
~$ sudo vpnctl config confirm C0001|--all
~$ sudo vpnctl config discard C0001|--all
~$ sudo vpnctl config history C0001 [REVISION]     # the last 5 replaced configurations
~$ sudo vpnctl config restore C0001 REVISION       # stages it; commit to apply
```

Every command takes `-o table|wide|json|yaml`.

State is named as in OpenConfig where it has a term, with upper case values (lower case is accepted in options):

| | |
|---|---|
| `admin_status` | `UP`, or `DOWN`: disabled in the configuration (`enabled: false`) |
| `oper_status` | `UP`, `DOWN`, or `DORMANT`: being set up (an IKE SA that isn't established) |
| `last_change`, `interface_transitions` | when `oper_status` last changed, and how often since vpnc started; seen at least every full check (30 seconds) |
| `counters` | `in_octets`, `in_pkts`, `in_errors`, `in_discards` and the same for `out` |
| `rates` | `in_bits_rate` and `out_bits_rate` in bits per second, the average over `load_interval` seconds |
| `probes` | per probe `description`, `address`, `test_type`, `port`, and of its last test `failed` (empty while the connection isn't up) and `last_test_timestamp`; in its `history` per test `timestamp`, `failed` and `avg_delay` in microseconds |
| BGP | `neighbor_address`, `peer_as`, `session_state`, `last_established`, `established_transitions`, and per `afi_safi_name` the `prefixes` `received` and `sent` (after policy) |
| Routes | `prefix`, `next_hops` |

## API

vpnctl uses vpnc's local REST API on the Unix socket `/run/vpnc/api.sock` (root only). The OpenAPI schema is at `/openapi.json`; errors are RFC 9457 problem details.

```bash
~$ sudo curl --unix-socket /run/vpnc/api.sock http://localhost/v1/status
~$ sudo curl --unix-socket /run/vpnc/api.sock http://localhost/openapi.json
```

| Path | |
|---|---|
| `/v1/status`, `/v1/version` | State and versions |
| `/v1/tenants`, `/v1/network-instances`, `/v1/connections` | Live state; connections also `stop`, `start`, `reset`, `probes`, `diagnosis`, `logs` and `ssh-setup` |
| `/v1/events` | The event history, optionally of a `tenant`, `network_instance` or `connection`; `event`, `since` (seconds), `limit`, `follow` |
| `/v1/config/tenants/{id}`, `/v1/config/service` | Configuration: `GET`, `PUT`, `PATCH` (merge patch), `DELETE`, `diff`, `schema` (JSON Schema), `commit`, `confirm`, `discard`, `history` |
| `/v1/bgp/...` | Neighbors and routes |
| `/v1/network-instances/{id}/routes`, `ping`, `traceroute`, `tcp` | Troubleshooting |
| `/v1/logs` | Logs; with `follow=true` a stream of new lines (JSON lines) |
| `/v1/ids` | The ids of tenants, network instances and connections, without state |

## SNMP

`make hub` and `make endpoint` install snmpd; vpnc adds its connections and routes to it (over AgentX), in standard MIBs. It only adds: snmpd keeps answering for everything it already did. Create a user as the installation prints.

| MIB | Table | |
|---|---|---|
| IF-MIB | `ifTable`, `ifXTable` | A row per connection, named like it (`ifName` `C0001-00-0`): admin and oper status, last change, MTU and counters. `ifOperStatus` is the state of the tunnel: `up`, `down` or `dormant` (being set up). |
| MPLS-L3VPN-STD-MIB | `mplsL3VpnVrfTable` | Every network instance as a VRF, by its name, described by its tenant's name. Up when one of its connections is up. No route distinguisher. |
| | `mplsL3VpnIfConfTable` | The connections of each VRF, by `ifIndex`. |
| | `mplsL3VpnVrfPerfTable` | The number of routes of each VRF (`mplsL3VpnVrfPerfCurrNumRoutes` only). |
| | `mplsL3VpnVrfRteTable` | The routes of every network instance. `mplsL3VpnVrfRteInetCidrIfIndex` is the connection's `ifIndex`, or 0. Routes without a gateway have the zero address as next hop, as in snmpd's `inetCidrRouteTable`. |
| BGP4V2-MIB | `bgp4V2PeerTable` and others | From FRR (hubs), under `1.3.6.1.3.5.1`: the BGP neighbours of the `CORE` VRF, IPv6 included. BGP4-MIB stays empty: FRR fills it only for the default BGP instance, and it holds no IPv6 neighbours. |

A connection's `ifIndex` is derived from its name, so it doesn't change: 1000000000 + tenant × 1000 + network instance × 10 + connection, with the tenant's letter as a hex digit (`C0001-00-0` is 1120001000). `EXTERNAL`, `CORE` and `ENDPOINT` count as network instances 0, 1 and 2 of tenant 0 (`CORE-1` is 1000000011).

The values are refreshed every 30 seconds.

LibreNMS reads BGP4V2-MIB only for VyOS; for Linux it reads BGP4-MIB, so it shows no BGP neighbours for vpnc.

## Files

| Path | |
|---|---|
| `/opt/ncubed/vpnc/` | The installation (virtualenv); `vpnctl` is linked to `/usr/local/bin` |
| `/opt/ncubed/config/vpnc/` | Configuration: `active`, `candidate` (staged) and `history` |
| `/opt/ncubed/config/vpnc/known_hosts/` | The host key of each SSH connection's server, accepted when first connecting. Delete a connection's file to accept a new key. |
| `/var/lib/vpnc-ssh/.ssh/` | The key of each SSH connection, named like it |
| `/run/vpnc/api.sock` | The API |

vpnc, vpncmangle and charon log to the journal: `vpnctl logs`, or `journalctl -t vpnc -t vpncmangle -t charon`.

## Development

The lab tests run in containerlab; see [test/README.md](test/README.md).

`make lock` (not as root, with the Python version of the installs) locks the dependencies and build tools to their newest versions that match `pyproject.toml` and `requirements-build.in`.
