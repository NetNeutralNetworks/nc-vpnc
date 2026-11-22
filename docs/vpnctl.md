# vpnctl

`vpnctl` shows vpnc's state and edits its configuration through vpnc's local [API](api.md) (the Unix socket `/run/vpnc/api.sock`, root only). `make` puts it on the PATH with bash and zsh completion; for a running shell:

```bash
~$ source /etc/bash_completion.d/vpnctl      # bash
~$ source <(vpnctl completion zsh)           # zsh, after compinit
```

Every command takes `-o table|wide|json|yaml`. Subjects are given by name: a tenant (`C0001`), a network instance (`C0001-00`) or a connection (`C0001-00-0`).

## State

Read live:

```bash
~$ sudo vpnctl status                        # mode, connections up, vpncmangle and its DNS answers, restart needed
~$ sudo vpnctl tenants list
~$ sudo vpnctl ni list [C0001]               # network instances
~$ sudo vpnctl ni show C0001-00              # with NAT64 and NPTv6 translations, sessions, firewall drops, DNS answers
~$ sudo vpnctl connections list [C0001 | C0001-00] [--oper-status DOWN] [--admin-status DOWN] [--type IPSEC]   # -o wide: MTU, traffic and its rate, probes answered
~$ sudo vpnctl connections show C0001-00-0   # last change, session, probes, traffic counters and rates
~$ sudo vpnctl connections probes C0001-00-0 # per probe its tests of the last 3 minutes
~$ sudo vpnctl bgp neighbors                 # hub mode; per address family
~$ sudo vpnctl bgp neighbor fd00:1:2::1      # in detail
~$ sudo vpnctl bgp routes [--received-from|--advertised-to NEIGHBOR]
~$ sudo vpnctl version
```

`connections show` has the same session fields for each VPN type, `-` where the type lacks one or it isn't known:

| Field | |
|---|---|
| State, id | of the IKE SA, WireGuard peer or SSH session |
| Local address | |
| Identities | IKE ids; WireGuard public keys; the SSH username and the server's host key |
| Encryption, integrity | as negotiated; integrity is `-` with an AEAD cipher. WireGuard's are fixed by the protocol. |
| Key exchange | with ML-KEM and PPK |
| Established, rekey | when |
| IPsec only | PRF, NAT, and the child SAs: algorithms, PFS, SPIs, traffic selectors, traffic and rekey time |
| WireGuard only | the last handshake and allowed IPs |

Events, logs, diagnosis and the troubleshooting commands are in [Troubleshooting](troubleshooting.md).

## Operations

Connections can be stopped and started: this sets `enabled` in their configuration right away, so it lasts until they're started again. VPN connections (IPsec, WireGuard, SSH) can be reset: a new IKE SA, WireGuard or SSH session.

```bash
~$ sudo vpnctl connections stop|start C0001-00-0 [C0001-01 ...]      # network instance/tenant: its VPN connections
~$ sudo vpnctl connections reset|restart C0001-00-0 [C0001-01 ...]
~$ sudo vpnctl service restart|stop                                  # vpnc itself (systemd); stops every tunnel
```

## Configuration

Per tenant (e.g. `C0001`) or `service` (the DEFAULT file). Changes are staged in the candidate configuration; a commit makes them active, and vpnc applies them (see [Configuration](configuration.md#how-changes-are-applied)).

```bash
~$ sudo vpnctl config list                   # tenants and their staged changes
~$ sudo vpnctl config add C0002 "Customer name"   # a new tenant; set the rest, then commit
~$ sudo vpnctl config show C0001 [PATH] [--candidate] [--reveal-secrets]
~$ sudo vpnctl config edit C0001 [PATH]      # in $EDITOR, validated; a new id creates a tenant
~$ sudo vpnctl config set C0001 network_instances.00.connections.0.routes.ipv4.0.to 10.0.0.0/24
~$ sudo vpnctl config set C0001 network_instances.00.connections.0.config.psk   # prompts, e.g. for a secret
~$ sudo vpnctl config delete C0001 [PATH]    # without a path: the tenant
~$ sudo vpnctl config diff C0001
~$ sudo vpnctl config commit C0001|--all [--confirm 5m]   # rolled back unless confirmed in time
~$ sudo vpnctl config commit C0001 --allow-weak    # also a short PSK, IKEv1 or weak algorithms
~$ sudo vpnctl config confirm C0001|--all
~$ sudo vpnctl config discard C0001|--all
~$ sudo vpnctl config history C0001 [REVISION]     # the last 5 replaced configurations
~$ sudo vpnctl config restore C0001 REVISION       # stages it; commit to apply
~$ vpnctl generate psk                             # a random PSK (256 bits)
~$ vpnctl generate ppk                             # a random PPK (256 bits, base64), e.g. for WireGuard
```

* **Paths** are dotted, with list items by index; values are YAML.
* **Tab** completes a path a level at a time (for `set`, also the next item to add), a value's choices and a proposal's next keyword (of the algorithms charon has). zsh also shows each key's value, type and default.
* **Proposals** are checked as strongSwan does when they're staged.

## Output fields

State is named as in OpenConfig where it has a term, with upper case values (lower case is accepted in options):

| Field | |
|---|---|
| `admin_status` | `UP`, or `DOWN`: disabled in the configuration (`enabled: false`) |
| `oper_status` | `UP`, `DOWN`, or `DORMANT`: being set up (an IKE SA that isn't established) |
| `last_change`, `interface_transitions` | when `oper_status` last changed, and how often since vpnc started; seen at least every full check (30 seconds) |
| `counters` | `in_octets`, `in_pkts`, `in_errors`, `in_discards` and the same for `out` |
| `rates` | `in_bits_rate` and `out_bits_rate` in bits per second, the average over `load_interval` seconds |
| `probes` | per probe `description`, `address`, `test_type`, `port`, and of its last test `failed` (empty while the connection isn't up) and `last_test_timestamp`; in its `history` per test `timestamp`, `failed` and `avg_delay` in microseconds |
| BGP | `neighbor_address`, `peer_as`, `session_state`, `last_established`, `established_transitions`, and per `afi_safi_name` the `prefixes` `received` and `sent` (after policy) |
| Routes | `prefix`, `next_hops` |
