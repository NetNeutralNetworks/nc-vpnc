# Troubleshooting

## A connection that's down

Work from vpnc's own view down to the packets:

1. **What does vpnc say?** `diagnose` names the problem, with what's configured next to what the peer sent:
   ```bash
   ~$ sudo vpnctl connections diagnose C0001-00-0
   ```
2. **What happened, and when?** The connection's events: when it went down, why, resets.
   ```bash
   ~$ sudo vpnctl connections events C0001-00-0 --since 6h
   ```
3. **What did the daemons say?** vpnc's, ssh's and charon's log lines of the connection:
   ```bash
   ~$ sudo vpnctl connections logs C0001-00-0 -n 100
   ```
4. **Is anything arriving?** Capture the outer packets in `EXTERNAL`, or the inner ones on the tunnel:
   ```bash
   ~$ sudo vpnctl capture EXTERNAL host 192.0.2.7
   ~$ sudo vpnctl capture C0001-00-0 -c 20
   ```

If the tunnel is up but hosts don't answer:

1. `vpnctl translate C0001-00 10.0.0.1`: the address admins should use.
2. `vpnctl routes C0001-00`: is there a route, or a blackhole?
3. `vpnctl ping C0001-00 10.0.0.1` (from inside the network instance, so it tests the tunnel without NAT64).
4. `vpnctl sessions C0001-00 10.0.0.1`: do admin sessions arrive, as translated?
5. `vpnctl firewall C0001-00 --hits`: what's dropped.
6. On the hub's upstream: `vpnctl bgp routes --advertised-to NEIGHBOR`.

A tunnel that's up while nothing answers is what [probes](connections.md#probes) are for: they reset it.

## Failure reasons

Why a connection fails is noted as it happens, from charon's log and ssh's output, and is an event when the reason changes. `diagnose` shows it with its details, what was checked and what charon or ssh reported.

| | Reasons |
|---|---|
| IPsec | `NO_RESPONSE`, `NO_RESPONSE_AUTH` (IKE_SA_INIT is answered, IKE_AUTH isn't), `DPD_TIMEOUT`, `CLOSED_BY_PEER`, `AUTH_FAILED_REMOTE` (the peer rejected our PSK, PPK or id), `AUTH_FAILED_LOCAL` (the peer's PSK or PPK is wrong), `AUTH_METHOD_MISMATCH`, `ID_MISMATCH`, `PPK_MISMATCH` (a PPK on one side only, or another id), `IKE_VERSION_MISMATCH`, `IKE_CONFIG_MISMATCH`, `IKE_PROPOSAL_MISMATCH`, `CHILD_PROPOSAL_MISMATCH`, `TS_MISMATCH`, `REJECTED_BY_PEER`, `CHILD_REJECTED_BY_PEER`, `KERNEL_FAILED` |
| SSH | `NO_RESPONSE`, `UNREACHABLE`, `REFUSED`, `PERMISSION_DENIED`, `HOST_KEY_MISMATCH`, `NEGOTIATION_FAILED`, `TUNNEL_REFUSED`, `CLOSED_BY_PEER`, `EXITED` |
| From its state | `ADMIN_DOWN`, `NO_INTERFACE`, `NOT_LOADED`, `ML_KEM_UNSUPPORTED`, `NOT_IN_FIREWALL`, `NO_ROUTE`, `WAITING_FOR_PEER` (a responder the peer doesn't set up), `CONNECTING`, `KEY_MISMATCH` (WireGuard: the peer sends, but no handshake completes: keys or PPK), `NO_CARRIER`, and while up: `PROBES_FAILING`, `ONE_WAY_TRAFFIC`, `FLAPPING` |

EXTERNAL's firewall counts the packets of each IPsec and WireGuard peer, so a silent peer is told apart from one whose packets are refused. WireGuard itself never says why a handshake fails.

## Events

Events are what happened to a connection, network instance, tenant or the service. They're kept in the journal (also across restarts, as long as the journal keeps them) and show in vpnc's log too. A tenant's events include those of its network instances, and a network instance's those of its connections.

```bash
~$ sudo vpnctl connections events C0001-00-0 [--since 6h] [-n 50] [-f]   # also: ni events, tenants events
~$ sudo vpnctl events [C0001 | C0001-00 | C0001-00-0 | service] [--event OPER_DOWN]
```

| Subject | Event | |
|---|---|---|
| Connection | `OPER_UP`, `OPER_DOWN` | Up or down |
| | `ADMIN_UP`, `ADMIN_DOWN` | Started or stopped |
| | `RESET` | Reset by an administrator |
| | `AUTO_RESET` | Reset by vpnc: down for too long, or no probe answered (see [automatic resets](connections.md#automatic-resets)) |
| | `CONFIG_RESET` | Reset for a changed PSK, PPK or traffic selectors (IPsec), or PPK (WireGuard) |
| | `PROBES_FAILING`, `PROBES_ANSWERED` | Its probes |
| | a [failure reason](#failure-reasons) | Why it fails, when that changes |
| | `HOST_KEY_ACCEPTED` | An SSH server's host key accepted |
| Network instance | `REMOVED` | Removed |
| Tenant | `CONFIG_COMMITTED`, `CONFIG_CONFIRMED`, `CONFIG_ROLLED_BACK` | Its commits |
| | `CONFIG_NOT_LOADED`, `CONFIG_LOADED` | An active file that isn't loaded, and once it is |
| CORE (hub) | `BGP_ESTABLISHED`, `BGP_DOWN` | BGP sessions; noted every full check |
| Service | `STARTED`, `STOPPED` | vpnc starting and stopping |

The events are journal entries with their own fields (`VPNC_EVENT`, `VPNC_TENANT`, `VPNC_NETWORK_INSTANCE`, `VPNC_CONNECTION`), so `journalctl VPNC_EVENT=OPER_DOWN` works too.

## Inside a network instance

Destinations are IP addresses, as in the tenant network:

```bash
~$ sudo vpnctl routes C0001-00 [-4|-6]       # installed, blackhole etc.
~$ sudo vpnctl ping C0001-00 10.0.0.1 [-c 5] [-s 56]
~$ sudo vpnctl traceroute C0001-00 10.0.0.1
~$ sudo vpnctl tcp C0001-00 10.0.0.1 443     # a TCP connection test
~$ sudo vpnctl sessions C0001-00 [10.0.0.1] [-p tcp]   # NAT64, NPTv6 and routed sessions, as translated
~$ sudo vpnctl firewall C0001-00 [--hits]    # vpnc's rules with their counters, since the firewall last changed
~$ sudo vpnctl translate C0001-00 10.0.0.1   # an address in the tenant as admins reach it
~$ sudo vpnctl translate fdcc:0:c:1::a00:1   # and back: tenant, network instance and address (fdcc:0:c:1::10.0.0.1 works too)
~$ sudo vpnctl capture C0001-00-0 [-c 20] [-w FILE] [-e -X port 443]   # tcpdump on the connection's interface, with its options and filter
~$ sudo vpnctl capture EXTERNAL esp          # or on all interfaces of a network instance
```

Plain `ip netns exec <network instance> ...` works too; vpnctl adds the translation and the formatting.

## Logs

```bash
~$ sudo vpnctl logs [--source vpnc|vpncmangle|charon | --ni C0001-00] [--level WARNING] [-n 50] [-f]
~$ journalctl -t vpnc -t vpncmangle -t charon
```

charon only loads the plugins vpnc needs, so `ipsec status` doesn't work: use `vpnctl` or `swanctl`.
