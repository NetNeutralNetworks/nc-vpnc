# Configuration

The configuration is YAML: one file per tenant, plus `service` (the `DEFAULT` file) for the node itself. Examples: [config-hub.yaml.example](../config/vpnc/config/config-hub.yaml.example), [config-endpoint.yaml.example](../config/vpnc/config/config-endpoint.yaml.example) and the tenant [config.yaml.example](../config/vpnc/config/config.yaml.example).

## How changes are applied

The workflow is candidate/commit, as on a router:

1. Change the candidate configuration with `vpnctl config set|edit|delete` or the [API](api.md). Changes are validated when they're staged.
2. Review with `vpnctl config diff`.
3. `vpnctl config commit` makes the candidate active, and vpnc applies it right away. With `--confirm 5m` it's rolled back unless confirmed in time (`vpnctl config confirm`), as with `commit confirmed`.

The last 5 replaced configurations are kept (`vpnctl config history`, `vpnctl config restore`). See [vpnctl](vpnctl.md#configuration) for all commands.

What runs is in `/opt/ncubed/config/vpnc/active/`, loaded at startup:

* **Restart needed:** service settings `mode` and `prefix_downlink_*`. Everything else applies on commit. `vpnctl status` says when a restart is needed.
* **Hand edits:** an active file changed otherwise (e.g. by hand) runs if a commit would accept it. If it can't be loaded, or a commit would refuse it, the tenant keeps running what it ran; `vpnctl config list` and the event `CONFIG_NOT_LOADED` say why. A commit (also without changes) replaces such a file.
* **IPsec resets:** an IPsec connection whose `psk`, PPK or `traffic_selectors` changed is reset (event `CONFIG_RESET`): its SAs would keep the old values, and a wrong value would only show at the next outage. Wider `traffic_selectors` of a responder apply once the initiator is reset too: until then it proposes the ones it had.
* **Weak cryptography** is refused unless committed with `--allow-weak`; see [Security](security.md#weak-cryptography).

Values like `HUB` and `IPSEC` are upper case; lower case is still read. Files have a `version`, currently 0.1.4 (see [upgrade notes](installation.md#upgrade-notes)).

## Service

```yaml
version: 0.1.4
id: DEFAULT
name: DEFAULT
mode: HUB                     # HUB | ENDPOINT; needs a restart
local_id: "%any"              # IKE identity, default for all connections
network_instances:            # EXTERNAL and CORE (and ENDPOINT in endpoint mode)
  EXTERNAL: {...}             # connections as in Connections, usually one PHYSICAL
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
    password: "..."           # optional, TCP MD5
dns:                          # optional; limits per network instance on DNS doctoring
  rate_limit: 50              # kbytes per second
  max_size: 4096              # bytes per answer
  max_records: 100            # records per answer
```

The addressing prefixes are explained in [Architecture](architecture.md#addressing-hub), BGP in [Routing and BGP](architecture.md#routing-and-bgp-hub), the `dns` limits in [vpncmangle](../vpncmangle/README.md).

## Tenants

```yaml
version: 0.1.4
id: C0001                     # A-F or 2-9, then 4 digits
name: Healthcare inc.
metadata: {}                  # free key-value pairs, also on network instances and connections
network_instances:
  00:                         # 00-99; the network instance is named C0001-00
    type: DOWNLINK
    connections:
      0: {...}                # 0-9; see Connections
```

Connections and their settings are in [Connections](connections.md).

## A first tenant

A tenant with one network instance and an IPsec connection to a site at 192.0.2.7, behind which are 10.0.0.0/8 and a ULA /52:

```bash
~$ sudo vpnctl config add C0002 "Customer name"
~$ sudo vpnctl config edit C0002
```

```yaml
version: 0.1.4
id: C0002
name: Customer name
network_instances:
  00:
    type: DOWNLINK
    connections:
      0:
        routes:
          ipv4:
          - to: 10.0.0.0/8
          ipv6:
          - to: fdff:db8:c57::/52
        probes:
        - address: 10.0.0.10
          test_type: ICMP
        config:
          type: IPSEC
          remote_addrs: [192.0.2.7]
          psk: "..."            # vpnctl generate psk text
```

Commit it with a rollback timer, check that it works, then confirm:

```bash
~$ sudo vpnctl config diff C0002
~$ sudo vpnctl config commit C0002 --confirm 5m
~$ sudo vpnctl connections show C0002-00-0       # oper_status UP?
~$ sudo vpnctl translate C0002-00 10.0.0.10      # the address admins use
~$ sudo vpnctl ping C0002-00 10.0.0.10
~$ sudo vpnctl config confirm C0002
```

If the connection doesn't come up, see [Troubleshooting](troubleshooting.md).
