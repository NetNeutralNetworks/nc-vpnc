# Connections

A connection is an interface in a network instance with routes over it: a VPN tunnel (IPsec, WireGuard, SSH) or a physical interface.

```yaml
0:                            # 0-9; named <network instance>-<n>, e.g. C0001-00-0
  enabled: true               # false: admin down (interface down, VPN not set up)
  mtu: 1400                   # optional, 1280 or more; default: the interface's own
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

Routes over a connection that doesn't pass traffic are blackholes, so traffic isn't sent elsewhere; see [Routing and BGP](architecture.md#routing-and-bgp-hub).

## Types

| `type` | Settings (defaults) |
|---|---|
| `IPSEC` | `remote_addrs`, `psk`, `local_id`, `remote_id`, `ike_version` (2), `ike_proposal` (`aes256gcm16-prfsha384-ecp384`), `ipsec_proposal` (`aes256gcm16-ecp384`), `ike_lifetime` (86400), `ipsec_lifetime` (3600), `initiation` (`START`: initiate and respond; `NONE`: respond only), `traffic_selectors` (`local`, `remote`; empty means route based), `post_quantum` |
| `WIREGUARD` | `remote_addrs`, `private_key`, `public_key`, `local_port` and `remote_port` (51820), `post_quantum` |
| `SSH` | `remote_addrs`, `username`, `remote_tunnel_id`, `remote_config_interface`, `host_key`, `post_quantum` |
| `PHYSICAL` | `interface_name` |

`psk`, `private_key` and the PPKs are secrets: hidden in output unless asked for (`--reveal-secrets`), and `vpnctl config set` without a value prompts for them.

### IPsec

charon (strongSwan) with XFRM interfaces: route based, so traffic selectors are `0.0.0.0/0, ::/0` unless `traffic_selectors` are set (for peers that need policy-based selectors).

* Proposals use strongSwan syntax. They're checked as strongSwan does when staged, and tab completion offers the algorithms charon has.
* `local_id` defaults to the service's `local_id`; `remote_id` to the first of `remote_addrs`.* `initiation: NONE` makes vpnc responder only: the peer has to set up the tunnel.
* PSK authentication only.

The peer side needs matching proposals, lifetimes of its own choice, and the same PSK; with `traffic_selectors`, the mirrored selectors.

### WireGuard

`private_key` is this side's key, `public_key` the peer's. `EXTERNAL` only accepts WireGuard from the `remote_addrs`, on `local_port`; a peer that moves to another address isn't accepted.

### SSH

An SSH connection is a layer 3 tunnel (`ssh -w`, a `tun` interface) to an Ubuntu server, which can be reached over another connection. vpnc logs in as `username` and only opens the tunnel: it doesn't configure the server.

Set up the server once, as root, with the script `vpnctl` makes for the connection:

```bash
~$ sudo vpnctl connections ssh-setup C0001-00-1 [--username vpnc] [--interface eth0] | ssh root@server sh
```

The script adds:

* the account, with the connection's key;
* the tunnel's interface (`tun<remote_tunnel_id>`) and routes;
* firewall rules, masquerading out of `--interface` (default: `remote_config_interface`);
* an sshd configuration in which the account can only open the tunnel.

The script isn't for root: give another account with `--username` and make it the connection's `username`.

**Host key.** The key the server presents when vpnc first connects is accepted and written to the connection's `host_key` (event `HOST_KEY_ACCEPTED`); only that key is accepted after. Delete `host_key` to accept a new one, e.g. of a replaced server. To leave nothing to the first connection, set it beforehand to the server's public host key (a line of its `/etc/ssh/ssh_host_*_key.pub`, without the comment): the script prints the command for it.

**Client keys.** ssh runs as the `vpnc-ssh` account, without privileges. Every connection logs in with its own key, which vpnc makes (`/var/lib/vpnc-ssh/.ssh/C0001-00-1`) and the script adds to the account on the server.

### Physical

An interface of the host, moved into the network instance. `via` in routes gives the next hop. Typically the uplinks in `EXTERNAL` and `CORE`.

## Automatic resets

After an outage a tunnel can get stuck halfway, e.g. with a half-open IKE SA. vpnc resets a VPN connection, like `vpnctl connections reset`, that isn't up for 3 minutes (event `AUTO_RESET`). Each reset that doesn't help doubles the wait, up to 30 minutes.

* An IPsec responder (`initiation: NONE`) that isn't up is only reset when it has an SA (a half-state): only its peer can set it up.
* An SSH connection isn't reset while the connection its server is routed via is down.
* A connection that's up while none of its probes answers is reset the same way; see below.

## Probes

A VPN can be up without passing traffic: a stale SA, a peer whose inside interface is down, a routing problem behind it. With `probes`, vpnc tests every 30 seconds whether hosts behind a connection answer, while the connection is up:

```yaml
probes:                       # 8 at most
- description: file server    # optional
  address: 10.0.0.10          # in the connection's routes
  test_type: ICMP             # an echo request
- address: 2001:db8:c57::10
  test_type: TCP              # a connection that's opened and closed; refused counts as answered
  port: 443
```

* **Reset:** the connection is reset, like `vpnctl connections reset`, when none of its probes is answered for 3 minutes. Each reset that doesn't help doubles the wait, up to 30 minutes. With probes on hosts in different networks, one host that's down doesn't reset the connection.
* **Scope:** only the VPN connections of `DOWNLINK` network instances. A connection without probes isn't tested.
* **Source:** a probe is sent out of the connection's interface, from that interface's IPv4 or IPv6 address, so the other side needs a route back to it. Only the host's own answer through that interface counts.
* **Firewall:** the network instance's firewall only lets out what its probes send.
* **State:** `vpnctl connections probes` shows each probe's last six tests (3 minutes) with their response time, `vpnctl connections show` the last test, and `vpnctl connections list -o wide` the number answered. `oper_status` isn't affected.

## Post-quantum cryptography

`post_quantum` protects against traffic recorded now and decrypted later with a quantum computer. IPsec and SSH add a hybrid ML-KEM key exchange to the classical one; WireGuard mixes a PPK into its handshake. ML-KEM requires Ubuntu 26.04 (strongSwan 6, OpenSSH 10): vpnc refuses it, and doesn't set up the connection, where charon or OpenSSH lacks it.

IPsec and SSH:

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

* **IPsec:** ML-KEM is added to `ike_proposal` and `ipsec_proposal` as an additional key exchange (RFC 9370, e.g. `ke1_mlkem768`), so they need a classical one (e.g. `ecp384`); ML-KEM in the proposals themselves is refused. The optional PPK (RFC 8784) is mixed into the keys and required by both sides.
* **SSH:** only the hybrid `mlkem768x25519-sha256` key exchange is allowed, so a server without it is refused instead of falling back to a classical one.

WireGuard:

```yaml
post_quantum:
  enabled: true             # default false
  ppk: "..."                # 32 bytes in base64, the same on both sides: vpnctl generate ppk
```

* The PPK is WireGuard's preshared key (`PresharedKey` on other implementations), so any WireGuard peer can use it. It's required when `enabled` is true.
* A changed PPK drops the session (`CONFIG_RESET`), so a wrong one shows right away: no handshake completes (`KEY_MISMATCH`).
* It protects as long as the PPK stays secret: there's no post-quantum forward secrecy. Use a PPK per connection.
* `vpnctl connections show` shows the key exchange as `CURVE_25519 + PPK`.
