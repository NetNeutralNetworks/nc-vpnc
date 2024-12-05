# nc-vpnc

vpnc (VPN concentrator) is an application to allow connectivity from a secure management network to multiple tenant networks. The selling point of vpnc is that all tenants and all the connections to a tenant can be uniquely addressed, removing issues with overlapping IP-space in IPv4. As the application also fully supports IPv6, global unicast addresses shouldn't cause any issues either, while unique local addresses can be remapped with NPTv6.

The key features of VPNC are:

* **Single entrypoint to tenants:** By sending all traffic destined to tenant networks via VPNC, the need for multiple VPN clients on admin workstations is removed.
* **Connect to multiple standalone networks:** Multiple network instances can be created per tenant. This means that if a tenant has multiple standalone networks, each of those can have a separate connection.
* **Full IPv6 support:** vpnc mostly runs on IPv6 internally and uses the capabilities it provides to offer full IPv4 reachability for each tenant and each network instance a tenant may have.
* **Flexible tenant connection options:** vpnc supports IPsec, WireGuard and phsyical/logical interface connections to tenants. For tenants with more strict rules, within a network instance, SSH tunnels can be utilized over any other connection to grant access to a network.
* **DNS response doctoring:** DNS responses are automatically doctored so no IP addressed need be remembered.

What it is not:

* **Firewall:** vpnc doesn't perform any fancy firewalling other than to make sure that all connections can only be initiated from an upstream management network to a downlink tenant. All other communication, including communication within a tenant is blocked. Another device should perform traffic inspection, user based firewalling and other desired security functionality.
* **Client VPN:** vpnc doesn't accept client connections directly. It expects an uplink connection, either physical/logical or IPsec/WireGuard, to a device that can accept client connections such as a perimiter firewall. Traffic flows are as follows: client > security device/network > vpnc > tenant security devices > tenant networks.
* **Router:** While vpnc routes traffic, it isn't a router. Its use is to make the connectivity to multiple tenants easy. As such, from a security standpoint, traffic is only allowed to flow from management to a tenant network.
* **Plug and play:** vpnc is made from a network engineering standpoint. It has no built-in HA mechanism. BGP is used to support HA and failover. As such, the proper HA configuration expects some networking knowledge.

## Architecture

Below is an overview of items related to the architecture of vpnc.

### Positioning

vpnc doesn't do any firewalling and isn't meant to accept client VPNs. As such, the recommended position is behind a firewall that accepts client VPNs and performs user based firewalling to allow only the correct identities to access each tenant.

A basic setup looks like this:
**TODO**

## Getting started

### Installation/upgrade

The system where a hub will be installed requires two logical interfaces. One interface is used for IPsec connections.
The other interface is used for management.

The service and command line tools are installed with the included bash script in the root: `install.sh`

The service can be installed in `hub` and `endpoint` mode (see architecture for more information).

`hub` mode deploys the service that connects the management environment to customers and performs all features mentioned.

`endpoint` mode is used purely as a VPN endpoint on a tenant site.

The installation can be run with the following command:

```bash
# Install as hub or endpoint
~$ ./install.sh hub  # or endpoint if desired
```

This installs the vpnc and an example configuration for either the `hub` or `endpoint` service.

<!-- * Uses IPv6 internally to accomodate client IPv4 overlap. Uses NAT64 to map the whole IPv4 address space a clients entire possible IPv4 address space into IPv6.
* DNS64 mangling translates A records resolved in a client network to AAAA records.
* Uses dynamic routing via BGP to exchange routes from established VPNs to the management environment.
* Uses active and candidate config to allow for easier configuration. Configuration updated with the `vpnctl` client validates input.
* Monitors for too many duplicate IKE and IPsec security associations and keeps the youngest. It takes rekeys into account. -->

### Shell configuration

The vpnc configuration can be can be managed by using the `vpnctl` executable installed in `/opt/ncubed/vpnc/bin`. Tab completion is installed by default when using the install script, but can be manually enabled:

```bash
~$ /opt/ncubed/vpnc/bin/vpnctl --install-completion
# restart terminal or run the below command to enable autocompletion:
~$ source ~/.bashrc
```

### vpnctl

While the configuration files can be edited directly, it is strongly recommeded to use `vpnctl` as it validates the configuration before saving. It also supports a very rudimentary commit system. This system doesn't store a commit history. Changes committed to any non "DEFAULT" tenant are automatically applied. DEFAULT tenant changes may require a restart of the service. See architecture for more information about the two tenant types.

`vpnctl` is very basic and hopefully will improve with time.

<!-- The configuration can also be managed by directly modifying the files in `/opt/ncubed/config/vpnc/` directory. 
The files in active are active config. The files in candidate are candidate configuration. 

If you don't want to use `vpnctl` to manage configuration files, edit the candidate configuration and then commit the configuration with `vpnctl`. This is because `vpnctl` validates the configuration before moving it to active. -->

### Service configuration

A default configuration is placed in the candidate configuration directory ('opt/ncubed/config/vpnc/candidate/DEFAULT.yaml'), but not committed. 
Before committing the configuration, edit it to fit your needs by running the following command:

```bash
~$ vpnctl tenants DEFAULT edit
```

vpnc will open the configuration using the default editor. In the editor, edit the following items:

```yaml
network_instances:
  EXTERNAL:
    connections:
      0:
        config:
          interface_name: eth1 # Change to the actual external interface name
          type: physical
        id: 0
        interface:
          ipv4:
          - 192.0.2.6/24 # Assign an IPv4 address to the interface if desired, otherwise leave blank
          ipv6:
          - 2001:db8::6/64 # Assign an IPv6 address to the interface if desired, otherwise leave blank
        metadata: {}
        routes:
          ipv4:
          - to: 0.0.0.0/0 # Add IPv4 routes if needed
            via: 192.0.2.1
          ipv6:
          - nptv6: false
            nptv6_prefix: null
            to: ::/0  # Add IPv6 routes if needed
            via: 2001:db8::1 
    id: EXTERNAL
    metadata: {}
    type: external
```

Edit the default configuration

### Tenants

Below are a few examples on how to configure tenants with `vpnctl`, network instances and connections. See architecture for more information about tenants, network instances and connections.
<!-- 
#### Configuration data structure

The configuration for a remote is just a YAML file with the following structure:

```yaml
version:

id: str                # required, ^[CD]\d{4}$
name: str              # required
metadata: {}           # optional, dictionary containing arbitrary k/v pairs
connections:           # optional, dictionary containing connections
  0:                     # required, connection id, int between 0-255
    type: ipsec | local      # required
    description: str         # required
    metadata: {}             # optional, dictionary containing arbitrary k/v pairs
    interface_ipv4: ip_prefix  # optional, host IP + CIDR mask, defaults to value configured in the service.
    interface_ipv6: ip_prefix  # optional, host IP + CIDR mask, defaults to value configured in the service.
    connection:
      ike_proposal: str        # required, see the allowed values for   strongswan
      ike_version: int         # optional, 1 or 2, defaults to 2
      ipsec_proposal:          # required, see the allowed values for   strongswan
      psk: str                 # required
      local_id: str            # optional, arbitratry, if defined overrides service local id.
      remote_id: str           # optional, arbirary, defaults to  remote_peer_ip
      remote_peer_ip: ip       # required, IPv4 host address
      routes: []               # optional, list of subnets, if defined,   mutually exclusive with traffic_selectors
      traffic_selectors:       # optional, if defined, mutually exclusive   with routes
        local: []                # required, list of subnets
        remote: []               # required, list of subnets
``` -->

#### Tenant management

List the configured tenants:

```bash
~$ vpnctl tenants
tenant    tenant-name    description   
--------  -------------  ------------- 
DEFAULT   DEFAULT                      
C0001     Tenant1        Healthcare inc.
C0002     Tenant2        Steel corp.
```

Show a tenant configuration:

```bash
# Show the tenant (active) configuration
# Full shows the connection configurations when run against the tenant and not a specific network instance.

~$ vpnctl tenants C0001 [network-instances C0001-00 [connections 0]] show [--active] [--full]
---
id: C0001
metadata:
  environment: test
name: Tenant
network_instance_count: 2
version: 0.1.3
...

# full active configuration
~$ vpnctl tenants C0001 show --full --active
---
id: C0001
metadata: 
  description: Healthcare inc.
name: Tenant1
connections:
  0:
    type: ipsec
    description: lab endpoint
    metadata:
      primary: true
    interface_ipv4: null
    interface_ipv6: null
    connection:
      ike_proposal: aes128gcm16-prfsha384-ecp384
      ike_version: 2
      ipsec_proposal: aes128gcm16-ecp384
      psk: superpassword
      local_id: null
      remote_id: 192.0.2.1
      remote_peer_ip: 198.51.100.255
      routes: []
      traffic_selectors:
        local: []
        remote: []
...
```

Show connection status summary

```bash
~$ vpnctl tenants C0001 [network-instances C0001-00 [connections 0]] summary
tenant    network-instance      connection  type       status       interface-name    interface-ip                                                             remote-addr
--------  ------------------  ------------  ---------  -----------  ----------------  -----------------------------------------------------------------------  ------------------
C0001     C0001-00                       0  IPSEC      ESTABLISHED  xfrm0             ['100.99.0.1/28', 'fdcc:cbe::/64', 'fe80::d190:d018:6c78:bc8/64']        192.0.2.7
C0001     C0001-00                       1  SSH        ACTIVE       tun1              ['100.99.0.17/28', 'fdcc:cbe:0:1::/64', 'fe80::5486:da3e:2cce:68ad/64']  172.16.30.1
C0001     C0001-01                       0  WIREGUARD  ACTIVE       wg-C0001-01-0     ['100.99.1.1/28', 'fdcc:cbe:1::/64']                                     b'192.0.2.8:51820'
```

Show used NAT translations

```bash
~$ vpnctl tenants C0001 nat
tenant    network-instance    type    local               remote
--------  ------------------  ------  ------------------  ----------------------
C0001     C0001-00            NAT64   fdcc:0:c:1::/96     0.0.0.0/0
C0001     C0001-00            NPTv6   fd6c:1::/52         fdff:db8:c57::/52
```

Add or delete a tenant

```bash
~$ vpnctl tenants C0001 (add|delete)
```

Open the default editor to edit the tenant configuration.
The edited configuration is validated.
Invalid configurations cannot be applied and will be rolled back.

```bash
~$ vpnctl tenants C0001 edit
```

Copy the candidate configuration to the active configuration
Reverting the candidate configuration, dry-runs and diffs are possible

```bash
~$ vpnctl tenants C0001 commit [--dry-run] [--diff] [--revert]
```

Show the BGP configuration

```bash
~$ vpnctl bgp show
---
globals:
  asn: 4255555555
  bfd: true
  router_id: 5.5.5.5
neighbors:
- neighbor_address: fd00:1:2::1
  neighbor_asn: 4233333333
  priority: 0
- neighbor_address: fd00:1:2::1:1
  neighbor_asn: 4244444444
  priority: 1
...
```

Show the BGP status summary

```bash
~$ vpnctl bgp summary
neighbor       hostname      remote-as  address-family    state        uptime    peer-state      pfx-rcvd    pfx-sent    msg-rcvd    msg-sent    con-estb    con-drop
-------------  ----------  -----------  ----------------  -----------  --------  ------------  ----------  ----------  ----------  ----------  ----------  ----------
fd00:1:2::1    mgt00        4233333333  ipv4Unicast       Established  02:52:18  Policy                 0           0        1518        1517           3           2
fd00:1:2::1:1  mgt01        4244444444  ipv4Unicast       Established  02:52:18  Policy                 0           0        1520        1516           3           2
fd00:1:2::1    mgt00        4233333333  ipv6Unicast       Established  02:52:18  OK                     1          12        1518        1517           3           2
fd00:1:2::1:1  mgt01        4244444444  ipv6Unicast       Established  02:52:18  OK                     1          12        1520        1516           3           2
```
