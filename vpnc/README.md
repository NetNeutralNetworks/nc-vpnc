# vpnc

The vpnc daemon and `vpnctl`, its command line client. vpnc connects a management network to many tenant networks over IPsec, WireGuard, SSH and physical connections, with NAT64, NPTv6 and BGP.

Install with `make` in the repository root. See the [nc-vpnc README](../README.md) for how it works, the configuration, vpnctl and the API.

| Package | |
|---|---|
| `vpnc.api` | The local REST API on `/run/vpnc/api.sock` |
| `vpnc.cli` | `vpnctl`, a client of the API (standard library only) |
| `vpnc.models` | The configuration models (pydantic) |
| `vpnc.network` | Namespaces, interfaces, routes and nftables |
| `vpnc.services` | Applying the configuration: reconciler, strongSwan, WireGuard, SSH, FRR, vpncmangle |
