# nc-vpnc

vpnc (VPN concentrator) connects a management network to many tenant networks. Each tenant network lives in its own Linux network namespace (a VRF, in effect) and gets a unique IPv6 prefix toward management, so overlapping RFC 1918 space and ULAs don't clash.

* **One entry point:** admins reach every tenant through vpnc, without a VPN client per tenant.
* **Several networks per tenant:** a tenant has one or more network instances, each with its own connections.
* **IPv6 inside:** tenant IPv4 is reached through NAT64, tenant IPv6 through NPTv6 or as is (global unicast).
* **Connections:** route-based IPsec (strongSwan, XFRM interfaces), WireGuard and physical interfaces. An SSH tunnel can run over another connection.
* **DNS doctoring:** DNS answers from a tenant are rewritten to the addresses that reach it, so nobody has to remember the translated addresses.
* **Routing:** the reachable prefixes are advertised to the management network with BGP (FRR, IPv6 unicast).

vpnc is not:

* **A firewall:** it only makes sure that connections are opened from management to tenants, never the other way or between tenants. Put a firewall in front of it for inspection and user-based rules.
* **A client VPN:** admins connect to a firewall or VPN gateway, which routes to vpnc: client > firewall > vpnc > tenant.
* **A general router.**
* **HA by itself:** run two hubs and let BGP choose.

```
admins ── firewall ── CORE ═══ vpnc ═══ EXTERNAL ── internet ── tenant sites
                      (BGP)    C0001-00, C0001-01, C0002-00 ...
```

## Quick start

On Ubuntu 26.04, as root, in the repository root:

```bash
~$ apt-get install -y make
~$ make hub                               # or: endpoint, addon
~$ vpnctl config edit service             # mode, uplinks, BGP
~$ vpnctl config commit service
~$ systemctl restart ncubed-vpnc
~$ vpnctl config add C0001 "Customer name"   # then add its network instances and connections
```

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | Network instances, addressing, NAT64/NPTv6, BGP, DNS doctoring, the daemons |
| [Installation](docs/installation.md) | Install, update, upgrade notes, file locations |
| [Configuration](docs/configuration.md) | The commit workflow, service and tenant settings, a first tenant step by step |
| [Connections](docs/connections.md) | IPsec, WireGuard, SSH, physical; probes; post-quantum cryptography |
| [vpnctl](docs/vpnctl.md) | The command line: state, configuration, output fields |
| [Troubleshooting](docs/troubleshooting.md) | A connection that's down, failure reasons, events, logs, packet captures |
| [Security](docs/security.md) | What's exposed, accounts and confinement, secrets, weak cryptography, updates |
| [API](docs/api.md) | The local REST API |
| [SNMP](docs/snmp.md) | IF-MIB, MPLS-L3VPN-STD-MIB and BGP4V2-MIB |
| [vpncmangle](vpncmangle/README.md) | The DNS rewriter in detail |

## Development

The lab tests run in containerlab; see [test/README.md](test/README.md).

`make lock` (not as root, on Ubuntu 26.04 with the Python packages of `make hub` installed) locks the dependencies to their newest versions that match `pyproject.toml` and the versions of Ubuntu's packages, which it leaves out.
