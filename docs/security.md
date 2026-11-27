# Security

## What's exposed

* **`EXTERNAL`** only accepts IKE and ESP from the `remote_addrs` of IPsec connections, and WireGuard from the `remote_addrs` of WireGuard connections, on their `local_port`. Peers of disabled connections aren't accepted, nor is a WireGuard peer that moves to another address.
* **`CORE`** carries BGP and admin traffic toward the tenants. Connections are only opened from management to tenants, never the other way or between tenants. DNS over TCP to tenants is refused, so a tenant can't answer with addresses vpncmangle doesn't rewrite.
* **Downlinks:** a network instance's firewall only lets out what its probes send.
* **Every network instance** ignores ICMP redirects and router advertisements, and sends no redirects: routes are configured.
* **The API** is a Unix socket, `/run/vpnc/api.sock`, for root only. There's no network API.

vpnc is not a firewall: put one in front of `CORE` for inspection and user-based rules.

## Accounts and confinement

| Daemon | Account | |
|---|---|---|
| vpnc | root | AppArmor profile `ncubed-vpnc`. |
| charon | `vpnc-swan` | Can only configure the network. Its own AppArmor profile too. |
| ssh | `vpnc-ssh` | No privileges. |
| vpncmangle | `vpnc-mangle` | Can only configure the network. Its own AppArmor profile too (`ncubed-vpncmangle`). |
| FRR | `frr` | bgpd, bfdd and staticd: their own AppArmor profiles too. |

charon only loads the plugins that connections with a PSK need (`/etc/strongswan.d/vpnc.conf`).

vpnc's unit (`ncubed-vpnc.service`) confines vpnc and every daemon it starts: no privileges gained through setuid programs, a system call filter, only Unix, IP and netlink sockets, and a capability bounding set. It can't load kernel modules: hubs load Jool at boot (`/etc/modules-load.d/vpnc.conf`).

Its AppArmor profile (`/etc/apparmor.d/ncubed-vpnc`) limits what vpnc and everything it starts may read, write and run, even as root: no mounts but its network namespaces, no systemd (which could start anything unconfined), and not its own code. Of `/opt/ncubed/config/` it may only write its own configuration and vpncmangle's, not its unit nor make's `make.conf`, which run as root. vpnc doesn't start without it. A daemon with a profile of its own runs under both. charon's and FRR's profiles take vpnc's signals through their `local/` include (`/etc/apparmor.d/ncubed-vpnc.d/`).

## Secrets

`psk`, `private_key` and the PPKs are hidden in output unless asked for (`--reveal-secrets`); `vpnctl config set` without a value prompts for them. They're stored in the configuration files under `/opt/ncubed/config/vpnc/`.

No process dumps core, so keys in memory don't end up on disk: vpnc's unit sets `LimitCORE=0`, `fs.suid_dumpable` is 0 (`/etc/sysctl.d/60-ncubed-vpnc.conf`) and apport is masked (its crash reports hold the core whatever the limit).

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

vpnc starts charon, FRR, vpncmangle and ssh itself, so an update of one of them, or of a library they use (OpenSSL, Python), makes needrestart restart vpnc after apt or unattended-upgrades. That stops every tunnel until vpnc has started them again.

unattended-upgrades runs daily at the install's `UPDATE_TIME`, and reboots right after an update that needs it (a new kernel); see [Installation](installation.md#updates-and-reboots). Give the hubs different times, so they're never down together.
