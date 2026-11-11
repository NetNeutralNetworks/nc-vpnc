# nc-vpnc

A VPN service that has the following features:
* A bridge between management environment and clients.
* Uses IPv6 internally to accomodate client IPv4 overlap. Uses NAT64 to map a clients entire possible IPv4 address space into IPv6.
* DNS64 mangling translates A records resolved in a client network to AAAA records.
* Uses dynamic routing via BGP to exchange routes from established VPNs to the management environment.
* Uses active and candidate config to allow for easier configuration. Configuration updated with the `vpnctl` client validates input.
* Monitors for too many duplicate IKE and IPsec security associations and keeps the youngest. It takes rekeys into account.

## Usage

The VPNC daemon can be can be managed by using `vpnctl` client installed in `/opt/ncubed/vpnc/bin`. This application has tab completion. 

The configuration can also be managed by directly modifying the files in `/opt/ncubed/config/vpnc/` directory. The files in active are active config. The files in candidate are candidate configuration. 

If you don't want to use `vpnctl` to manage configuration files, edit the candidate configuration and then commit the configuration with `vpnctl`. This is because `vpnctl` validates the configuration before moving it to active.

The configuration is split into two sections: remote and service.

Remote contains customers and customer connections. Service contains the service configuration.

Changes committed to remote are automatically applied. Service changes require a restart.

### Remotes

Below are a few examples on how to add remotes (customers) and connections (VPN connections to a customer) as well as the data structure of a remote configuration

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
```

#### Remote configuration

List the configured remotes:
```bash
~$ vpnctl remote
id     name
------ ----
D0002  Lab-test-2
D0001  Lab-test-1
C0001  Rebucks
C0002  NSD
```

Show a specific remote configuration:
```bash
# candidate configuration
~$ vpnctl remote D0001 show
# active configuration
~$ vpnctl remote D0001 show --active 
---
id: D0001
metadata: {}
name: Lab-test
connection_count: 1
...

# full candidate configuration
~$ vpnctl remote D0001 show --full
# full active configuration
~$ vpnctl remote D0001 show --full --active
---
id: D0001
metadata: {}
name: Lab-test-1
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

Edit the configuration file in your favorite editor (vim by default, requires sudo/root):
```bash
# Open the configuration in vim/nano
# after saving and exiting, the changes are validated.
# if wrong, your changes will be discarded.
~$ sudo vpnctl remote D0001 edit
```

Add a new remote (requires sudo/root):
```bash
~$ sudo vpnctl remote D0010 add "Customer Inc."
---
id: D0010
metadata: {}
name: Customer Inc.
connection_count: 0
...
```

Edit a remote (requires sudo/root):
```bash
~$ sudo vpnctl remote D0010 set --metadata '{"location": "Europe"}'
---
id: D0010
metadata:
  location: Europe
name: Lab-test
connection_count: 1
...
```

Delete a remote (requires sudo/root):
```bash
~$ sudo vpnctl remote D0010 delete
---
id: D0010
metadata: {}
name: test
connections: {}
...

Are you sure you want to delete remote 'D0010' [y/N]:
```

#### Connection configuration

List connections for a specific remote:
```bash
~$ vpnctl remote D0001 connection list
tunnel description
------ -----------
0      lab endpoint
```

Show a connection configuration for a specific remote:
```bash
~$ vpnctl remote D0001 connection 0 show
---
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

Add a new connection to a remote (requires sudo/root):
> **NOTE:** Use https://docs.strongswan.org/docs/5.9/config/IKEv2CipherSuites.html as a reference to check the configurable IKE and IPsec proposals:  
> **IKE:** <(authenticated) encryption algorithm>-<pseudo-random function/integrity algorithm>-<dh group/key exchange>  
> **IPsec:** <(authenticated) encryption algorithm>[-<pseudo-random function/integrity algorithm>]-<dh group/key exchange>
```bash
~$ sudo vpnctl remote D0001 connection 1 add --description "lab 1 connection test" --ike-proposal aes128gcm16-prfsha384-ecp384 --ipsec-proposal aes128gcm16-ecp384 --remote-peer-ip 192.0.2.128 --pre-shared-key "welcome01!"
---
1:
  description: lab 1 connection test
  metadata: {}
  interface_ipv4: null
  interface_ipv6: null
  connection:
    ike_proposal: aes128gcm16-prfsha384-ecp384
    ike_version: 2
    ipsec_proposal: aes128gcm16-ecp384
    psk: welcome01!
    local_id: null
    remote_id: 192.0.2.128
    remote_peer_ip: 192.0.2.128
    routes: []
    traffic_selectors:
      local: []
      remote: []
...
```

Update the configuration of an existing connection on a remote (requires sudo/root):
```bash
~$ sudo vpnctl remote D0001 connection 1 set --ike-proposal aes256gcm16-prfsha384-ecp384 --ipsec-proposal aes256gcm16-ecp384 --tunnel-ip 172.16.0.1 --routes 10.0.0.0/24 --routes 10.0.1.0/24
---
1:
  description: lab 1 connection test
  metadata: {}
  interface_ipv4: 172.16.0.1
  interface_ipv6: null
  connection:
    ike_proposal: aes256gcm16-prfsha384-ecp384
    ike_version: 2
    ipsec_proposal: aes256gcm16-ecp384
    psk: welcome01!
    local_id: null
    remote_id: 192.0.2.128
    remote_peer_ip: 192.0.2.128
    routes:
    - 10.0.0.0/24
    - 10.0.1.0/24
    traffic_selectors:
      local: []
      remote: []
...
```

Remove configuration from an existing connection on a remote (requires sudo/root):
```bash
~$ sudo vpnctl remote D0001 connection 0 unset --routes 10.0.0.0/24 --routes 10.0.1.0/24   
---
1:
  description: lab 1 connection test
  metadata: {}
  interface_ipv4: 172.16.0.1
  interface_ipv6: null
  connection:
    ike_proposal: aes256gcm16-prfsha384-ecp384
    ike_version: 2
    ipsec_proposal: aes256gcm16-ecp384
    psk: welcome01!
    local_id: null
    remote_id: 192.0.2.128
    remote_peer_ip: 192.0.2.128
    routes: []
    traffic_selectors:
      local: []
      remote: []
...
```

Delete a connection from a remote (requires sudo/root):
```bash
~$ sudo vpnctl remote D0001 connection 1 delete
1:
  description: lab 1 connection test
  metadata: {}
  interface_ipv4: 172.16.0.1
  interface_ipv6: null
  connection:
    ike_proposal: aes256gcm16-prfsha384-ecp384
    ike_version: 2
    ipsec_proposal: aes256gcm16-ecp384
    psk: welcome01!
    local_id: null
    remote_id: 192.0.2.128
    remote_peer_ip: 192.0.2.128
    routes: []
    traffic_selectors:
      local: []
      remote: []

Are you sure you want to delete remote 'D0001' connection '1' [y/N]:
```

#### Commit or revert configuration

Commit changes (requires sudo/root):
```bash
# simulate a run, show diff
~$ sudo vpnctl remote D0001 commit --dry-run --diff 
# commit and show diff
~$ sudo vpnctl remote D0001 commit --diff 
# commit without showing diff
~$ sudo vpnctl remote D0001 commit
# the same as the examples above, except revert the candidate changes.
~$ sudo vpnctl remote D0001 commit --revert --dry-run --diff 
~$ sudo vpnctl remote D0001 commit --revert --diff
~$ sudo vpnctl remote D0001 commit --revert
```

## Installation

The service and command line tools are installed with thge included bash script in the root: `install.sh` 

The service can be installed in `hub` and `endpoint` mode.

`hub` mode deploys the service that connects the management environment to customers and performs all features mentioned.

`endpoint` mode is used purely as a VPN endpoint on a remote. Only does VPN.

The installation can be run with the following command:
```bash
sudo install.sh hub  # or endpoint if desired
```

The `install.sh` script calls the `migrate.sh` script to perform migration/cleanup operations between versions.
