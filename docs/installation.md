# Installation

vpnc runs on Ubuntu 26.04 with systemd. Everything below runs as root, in the repository root.

## Install

```bash
~$ apt-get install -y make
~$ make hub               # or: endpoint, addon
```

| Target | Installs |
|---|---|
| `hub` | vpnc, vpncmangle, FRR, snmpd, the `vpnc-mangle` and `vpnc-ssh` accounts, a hub service configuration |
| `endpoint` | vpnc and snmpd, an endpoint service configuration |
| `addon` | vpnc only (no FRR, vpncmangle or snmpd), a hub service configuration |

A full install:

* upgrades the system packages (`apt upgrade`);
* installs vpnc in `/opt/ncubed/vpnc` (a virtualenv), with `vpnctl` on the PATH;
* installs an example service configuration;
* (re)starts vpnc.

Run it again to upgrade everything.

Then configure the service (see [Configuration](configuration.md#service)):

```bash
~$ vpnctl config edit service
~$ vpnctl config commit service
~$ systemctl restart ncubed-vpnc
```

For SNMP, create a user as the installation prints; see [SNMP](snmp.md).

## Update

To update only vpnc after a `git pull`:

```bash
~$ make update
```

* Reinstalls vpnc (and vpncmangle on a hub) and restarts vpnc only if something changed.
* apt only installs Ubuntu's Python packages vpnc uses, if missing; nothing else is upgraded.
* Configuration files are only installed when missing, so local edits are kept.
* The systemd unit is replaced when it changes: put local changes in a drop-in (`systemctl edit ncubed-vpnc`).

A restart of vpnc stops every tunnel; plan it in a maintenance window.

## Dependencies

vpnc uses Ubuntu's FRR, Jinja2, packaging, pydantic, PyYAML, watchdog and NetfilterQueue (system site packages). The other Python dependencies are installed at the versions and hashes in the lock files (`requirements.txt`).

## Upgrade notes

* **FRR:** a full install removes FRR's own apt repository, which older installs added, and downgrades its FRR to Ubuntu's.
* **Configuration version:** files have a `version`, currently 0.1.5. vpnc converts files of versions 0.1.3 and 0.1.4 at startup and when they are put in `active/`; the originals are kept in `/opt/ncubed/config/vpnc/backup/<version>/`, and the folders of older versions are deleted. Other versions are refused.
* **BGP `priority`:** replaced by `local_pref` and `as_path_prepend` (0.1.5). The conversion keeps what a priority did: `local_pref: 100 - 10 × priority` and `as_path_prepend: priority`.
* **WireGuard:** interfaces are named `wg<n>` in their network instance, and their files in `/etc/wireguard/` after the connection (`C0001-01-0.conf`). vpnc empties `/etc/wireguard/` when it starts, so keep no other files there. The upgrade recreates every WireGuard interface: those tunnels go down briefly.
* **SSH keys:** earlier versions of `make` copied root's keys to `/var/lib/vpnc-ssh/.ssh/id_*` and used them for every SSH connection. Now each connection has its own key: run the server setup script again on servers set up before that (see [Connections](connections.md#ssh)). Then the `id_*` files can be deleted.

## Files

| Path | |
|---|---|
| `/opt/ncubed/vpnc/` | The installation (virtualenv); `vpnctl` is linked to `/usr/local/bin` |
| `/opt/ncubed/config/vpnc/` | Configuration: `active`, `candidate` (staged), `history` and `backup` |
| `/opt/ncubed/config/vpnc/known_hosts/` | ssh's copy of each SSH connection's `host_key` |
| `/opt/ncubed/config/vpncmangle/` | vpncmangle's translations and limits, written by vpnc |
| `/var/lib/vpnc-ssh/.ssh/` | The key of each SSH connection, named like it |
| `/etc/wireguard/` | Each WireGuard connection's settings (`C0001-01-0.conf`), for operators; emptied when vpnc starts |
| `/etc/strongswan.d/vpnc.conf` | The charon plugins vpnc loads |
| `/run/vpnc/api.sock` | The API |

vpnc, vpncmangle and charon log to the journal: `vpnctl logs`, or `journalctl -t vpnc -t vpncmangle -t charon`.
