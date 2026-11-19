# vpncmangle

Rewrites DNS answers from tenants so admins get addresses that reach the tenant through vpnc. Part of [nc-vpnc](../README.md); hub mode only.

vpnc starts vpncmangle in the `CORE` network instance and restarts it if it stops. vpncmangle queues DNS responses (UDP source port 53) leaving `CORE` with nftables (table `ip6 vpncmangle`) and changes the records in all their sections:

* **A records** become AAAA records in the network instance's NAT64 prefix, e.g. `10.0.0.1` from `C0001-00` becomes `fdcc:0:c:1::a00:1`. Also in answer to an A query.
* **AAAA records** get the NPTv6 prefix of the route they're in. Addresses that aren't routed through the network instance are left out.
* **Other records** (e.g. CNAME) stay as they are.

The network instance is found from the response's source address, i.e. the tenant's DNS server as admins reach it.

vpnc writes the translations to `/opt/ncubed/config/vpncmangle/translations.json` when the configuration changes; vpncmangle reloads it when the file changes. Per network instance:

```json
{"C0001-00": {"dns64": [["fdcc:0:c:1::/96", "0.0.0.0/0"]],
              "dns66": [["fd6c:1::/52", "fdff:db8:c57::/52"]]}}
```

One thread translates every network instance's answers, so what one of them may cost is limited, with the service's `dns` settings (in `limits.json`, next to the translations):

| Setting | Default | Dropped |
| --- | --- | --- |
| `rate_limit` | 50 | A network instance's answers over this many kbytes per second (and twice that at once), by nftables before they're queued (`RATE_LIMITED`). |
| `max_size` | 4096 | An answer of more bytes, as IPv6 packet (`OVERSIZED`). |
| `max_records` | 100 | An answer with more records (`TOO_MANY_RECORDS`). |

An answer of one address takes about 0.4 ms to translate, one of 100 about 9 ms: at these limits one network instance takes about a quarter of the thread.

Logs go to the journal (`journalctl -t vpncmangle`), or `vpnctl logs --source vpncmangle`. `vpnctl status` shows whether it runs and how many answers it translated and dropped since it started, and why; `vpnctl ni show` the same per network instance. vpncmangle writes these counters to `/run/vpncmangle/stats.json` every 30 seconds.

Dropped as well: a packet from port 53 that isn't DNS (`NOT_DNS`), an answer from an address of no network instance (`UNKNOWN_SOURCE`), an answer while no translations are loaded (`NO_TRANSLATIONS`), an answer that fails to translate (`ERROR`), and answers the kernel couldn't queue because vpncmangle didn't keep up (`QUEUE_FULL`).

DNS over TCP isn't translated: `CORE` refuses it, so a tenant can't answer with other addresses.
