alias _ip='ip -br -c addr | sort'
alias _ip4='ip -4 -br -c addr | sort'
alias _ip6='ip -6 -br -c addr | sort'
alias _eth='ip -br -c link | sort'
alias _bridge='bridge -color link | sort'
alias _vlan='bridge -color -compress vlan'
alias _fdb='bridge -color fdb | sort'
alias _dhcpleases='cat /var/lib/misc/dnsmasq.leases'

print_service_state () {
  state=$(systemctl is-active $1)
  case $state in
    active)
      color="\e[32m"
    ;;
    *)
      color="\e[31m"
    ;;
  esac
  printf "\e[1m$1: $color\t$state\e[0m\n"
}

# Enable autocomplete
vpnctl --install-completion > /dev/null

printf "\n"
print_service_state "ncubed-vpnc"

printf "\e[1m
                   _               _
                  | |             | |
 ____   ____ _   _| |__  _____  __| |
|  _ \ / ___) | | |  _ \| ___ |/ _  |
| | | ( (___| |_| | |_) ) ____( (_| |
|_| |_|\____)____/|____/|_____)\____|
\e[0m

VPNC configuration is stored in /opt/ncubed/config/vpnc
This directory contains the active and candidate configuration directories.

Manage the configuration by using the 'vpnctl' command. This binary has autocompletion.

> vpnctl remote
shows a list of all configured remote VPNs

> vpnctl remote C0001 show (--active) (--full)
shows the C0001 (active) remote VPN configuration without the VPN tunnel configuration
full shows the tunnel configurations as well

> vpnctl remote C0001 add/delete/set/unset
add a new remote
delete a remote
set a remote property
remove a remote property

> vpnctl remote C0001 edit
opens the default editor for editing the remote configuration. These edits are validated. Invalid
configurations cannot be applied and will be rolled back.

> vpnctl remote C0001 connection
shows a list of all configured tunnels for a remote

> vpnctl remote C0001 connection 0 show
shows the C0001 remote tunnel 0 VPN configuration

> vpnctl remote C0001 connection 0 add/delete/set/unset
add a new connection
delete a connection
set a connection property
remove a connection property

> vpnctl remote C0001 commit
copy the candidate configuration to the active configuration
reverting the candidate configuration, dry-runs and diffs are possible

> vpnctl service show (--active)
shows the (active) service configuration

> vpnctl service bgp show
shows the bgp configuration

> vpnctl service uplink
shows all provider/management connections

> vpnctl service edit
opens the default editor for editing the service configuration. These edits are validated. Invalid
configurations cannot be applied and will be rolled back.

> vpnctl service commit
copy the candidate configuration to the active configuration
reverting the candidate configuration, dry-runs and diffs are possible

"
