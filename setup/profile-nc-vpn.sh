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

DEFAULT="\e[0m"
BOLD="\e[1m"
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

$BOLD> vpnctl tenants$DEFAULT
List the configured tenants

$BOLD> vpnctl tenants C0001 [network-instances C0001-00 [connections 0]] show [--active] [--full]$DEFAULT
Show a tenant configuration
Full shows the connection configurations when run against the tenant and not a specific network instance.

$BOLD> vpnctl tenants C0001 [network-instances C0001-00 [connections 0]] summary$DEFAULT
Show connection status summary

$BOLD> vpnctl tenants C0001 nat$DEFAULT
Show used NAT translations

$BOLD> vpnctl tenants C0001 (add|delete)$DEFAULT
Add or delete a tenant

$BOLD> vpnctl tenants C0001 edit$DEFAULT
Open the default editor to edit the tenant configuration.
The edited configuration is validated.
Invalid configurations cannot be applied and will be rolled back.

$BOLD> vpnctl tenants C0001 commit [--dry-run] [--diff] [--revert]$DEFAULT
Copy the candidate configuration to the active configuration
Reverting the candidate configuration, dry-runs and diffs are possible

$BOLD> vpnctl bgp show$DEFAULT
Show the BGP configuration

$BOLD> vpnctl bgp summary$DEFAULT
Show the BGP status summary


"
