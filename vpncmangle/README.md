# vpncmangle

Rewrites DNS answers from tenants so admins get addresses that reach the tenant through vpnc. Part of [nc-vpnc](../README.md); hub mode only.

vpnc starts vpncmangle in the `CORE` network instance and restarts it if it stops. vpncmangle queues DNS responses (UDP source port 53) leaving `CORE` with nftables (table `ip6 vpncmangle`) and changes them:

* **A records** become AAAA records in the network instance's NAT64 prefix, e.g. `10.0.0.1` from `C0001-00` becomes `fdcc:0:c:1::a00:1`. Also in answer to an A query.
* **AAAA records** get the NPTv6 prefix of the route they're in. Addresses that aren't routed through the network instance are left out.
* **Other records** (e.g. CNAME) stay as they are.

The network instance is found from the response's source address, i.e. the tenant's DNS server as admins reach it.

vpnc writes the translations to `/opt/ncubed/config/vpncmangle/translations.json` when the configuration changes; vpncmangle reloads it when the file changes. Per network instance:

```json
{"C0001-00": {"dns64": [["fdcc:0:c:1::/96", "0.0.0.0/0"]],
              "dns66": [["fd6c:1::/52", "fdff:db8:c57::/52"]]}}
```

Logs go to `/var/log/ncubed/vpnc/vpncmangle.log`, or `vpnctl logs --source vpncmangle`. `vpnctl status` shows whether it runs.

Not supported yet: DNS over TCP.
