# SNMP

`make hub` and `make endpoint` install snmpd; vpnc adds its connections and routes to it over AgentX, in standard MIBs. It only adds: snmpd keeps answering for everything it already did.

The installation comments out Ubuntu's default communities and `agentaddress` in `/etc/snmp/snmpd.conf`. Create a read-only SNMPv3 user, with snmpd stopped, as the installation prints:

```bash
~$ sudo systemctl stop snmpd
~$  sudo net-snmp-create-v3-user -ro -a SHA -A <authpass> -x AES -X <privpass> nc-snmp   # leading space: not in the shell history
~$ sudo systemctl start snmpd
```

## MIBs

| MIB | Table | |
|---|---|---|
| IF-MIB | `ifTable`, `ifXTable` | A row per connection, named like it (`ifName` `C0001-00-0`): admin and oper status, last change, MTU and counters. `ifOperStatus` is the state of the tunnel: `up`, `down` or `dormant` (being set up). |
| MPLS-L3VPN-STD-MIB | `mplsL3VpnVrfTable` | Every network instance as a VRF, by its name, described by its tenant's name. Up when one of its connections is up. No route distinguisher. |
| | `mplsL3VpnIfConfTable` | The connections of each VRF, by `ifIndex`. |
| | `mplsL3VpnVrfPerfTable` | The number of routes of each VRF (`mplsL3VpnVrfPerfCurrNumRoutes` only). |
| | `mplsL3VpnVrfRteTable` | The routes of every network instance. `mplsL3VpnVrfRteInetCidrIfIndex` is the connection's `ifIndex`, or 0. Routes without a gateway have the zero address as next hop, as in snmpd's `inetCidrRouteTable`. |
| BGP4V2-MIB | `bgp4V2PeerTable` and others | From FRR (hubs), under `1.3.6.1.3.5.1`: the BGP neighbours of the `CORE` VRF, IPv6 included. BGP4-MIB stays empty: FRR fills it only for the default BGP instance, and it holds no IPv6 neighbours. |

Monitoring BGP in SNMP requires the monitoring host to support BGP4V2-MIB.

The values are refreshed every 30 seconds.

## ifIndex

A connection's `ifIndex` is derived from its name, so it doesn't change across restarts:

1000000000 + tenant × 1000 + network instance × 10 + connection

with the tenant's letter as a hex digit: `C0001-00-0` is 1120001000. `EXTERNAL`, `CORE` and `ENDPOINT` count as network instances 0, 1 and 2 of tenant 0 (`CORE-1` is 1000000011).
