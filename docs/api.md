# API

vpnctl uses vpnc's local REST API on the Unix socket `/run/vpnc/api.sock` (root only). The OpenAPI schema is at `/openapi.json`; errors are RFC 9457 problem details.

```bash
~$ sudo curl --unix-socket /run/vpnc/api.sock http://localhost/v1/status
~$ sudo curl --unix-socket /run/vpnc/api.sock http://localhost/openapi.json
```

| Path | |
|---|---|
| `/v1/status`, `/v1/version` | State and versions |
| `/v1/tenants`, `/v1/network-instances`, `/v1/connections` | Live state; connections also `stop`, `start`, `reset`, `probes`, `diagnosis`, `logs` and `ssh-setup` |
| `/v1/events` | The event history, optionally of a `tenant`, `network_instance` or `connection`; `event`, `since` (seconds), `limit`, `follow` |
| `/v1/config/tenants` | `GET`: the tenants with configuration; `POST` (`id`, optional `name`): add a tenant |
| `/v1/config/tenants/{id}`, `/v1/config/service` | Configuration: `GET`, `PUT`, `PATCH` (merge patch, of a tenant that has configuration), `DELETE`, `diff`, `schema` (JSON Schema), `commit`, `confirm`, `discard`, `history` |
| `/v1/bgp/...` | Neighbors and routes |
| `/v1/network-instances/{id}/routes`, `ping`, `traceroute`, `tcp` | Troubleshooting |
| `/v1/logs` | Logs; with `follow=true` a stream of new lines (JSON lines) |
| `/v1/ids` | The ids of tenants, network instances and connections, without state |

Field names are those of [vpnctl's output](vpnctl.md#output-fields). Configuration changes follow the same candidate/commit workflow as vpnctl; see [Configuration](configuration.md#how-changes-are-applied).
