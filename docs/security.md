# Security

## What's exposed

* **`EXTERNAL`** only accepts IKE and ESP from the `remote_addrs` of IPsec connections, and WireGuard from the `remote_addrs` of WireGuard connections, on their `local_port`. Peers of disabled connections aren't accepted, nor is a WireGuard peer that moves to another address.
* **`CORE`** carries BGP and admin traffic toward the tenants. Connections are only opened from management to tenants, never the other way or between tenants. DNS over TCP to tenants is refused, so a tenant can't answer with addresses vpncmangle doesn't rewrite.
* **Downlinks:** a network instance's firewall only lets out what its probes send.
* **The API** is a Unix socket, `/run/vpnc/api.sock`, for root only. There's no network API.

vpnc is not a firewall: put one in front of `CORE` for inspection and user-based rules.

## Accounts and confinement

| Daemon | Account | |
|---|---|---|
| charon | `vpnc-swan` | Can only configure the network. AppArmor profile in enforce mode. |
| ssh | `vpnc-ssh` | No privileges. |
| vpncmangle | `vpnc-mangle` | Can only configure the network. |
| FRR | `frr` | AppArmor profiles in enforce mode. |

charon only loads the plugins that connections with a PSK need (`/etc/strongswan.d/vpnc.conf`).

vpnc's unit (`ncubed-vpnc.service`) confines vpnc and every daemon it starts: no privileges gained through setuid programs, a system call filter, only Unix, IP and netlink sockets, and a capability bounding set. It can't load kernel modules: hubs load Jool at boot (`/etc/modules-load.d/vpnc.conf`). There are no file system restrictions: vpnc runs as root, and the network namespaces it mounts must be seen outside it.

## Secrets

`psk`, `private_key` and the PPKs are hidden in output unless asked for (`--reveal-secrets`); `vpnctl config set` without a value prompts for them. They're stored in the configuration files under `/opt/ncubed/config/vpnc/`.

Every SSH connection has its own key (`/var/lib/vpnc-ssh/.ssh/<connection>`), and only accepts the server host key in its `host_key`; see [SSH](connections.md#ssh).

A hub's BGP neighbors can have a `password` (TCP MD5), set on the neighbor too: the uplink tunnel's key alone then doesn't give a BGP session.

## Weak cryptography

Weak cryptography of an IPsec connection is only committed with `--allow-weak`:

* a `psk` of fewer than 32 characters: whoever answers the connection as its peer can try PSKs offline. `vpnctl generate psk text` makes a random one.
* `ike_version` 1;
* proposals with DES, 3DES, no encryption, MD5, or a Diffie-Hellman group under 2048 bits.

What a connection has already stays as it is: vpnc logs it when it loads the configuration, and `vpnctl connections diagnose` shows it.

For post-quantum key exchange, see [Connections](connections.md#post-quantum-cryptography).

## Updates

An update of strongSwan only replaces its files: the running charon is the old one until vpnc restarts, which stops every tunnel. Restart it (`vpnctl service restart`) in a maintenance window after a security update.
