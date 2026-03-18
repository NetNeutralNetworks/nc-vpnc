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

printf "$BOLD
                   _               _
                  | |             | |
 ____   ____ _   _| |__  _____  __| |
|  _ \ / ___) | | |  _ \| ___ |/ _  |
| | | ( (___| |_| | |_) ) ____( (_| |
|_| |_|\____)____/|____/|_____)\____|
$DEFAULT

VPNC configuration is stored in /opt/ncubed/config/vpnc
This directory contains the active and candidate configuration directories.

Manage the configuration by using the 'vpnctl' command. This binary has autocompletion.

$BOLD> vpnctl tenants$DEFAULT
shows a list of all configured tenants VPNs

$BOLD> vpnctl tenants <TENANTID> show (--active) (--full)$DEFAULT
shows the <TENANTID> (active) tenant VPN configuration without the VPN tunnel configuration
full shows the tunnel configurations as well

$BOLD> vpnctl tenants <TENANTID> add --name <Customer name>
add a new tenant

$BOLD> vpnctl tenants <TENANTID> delete/set/unset$DEFAULT
delete a tenant
set a tenant property
remove a tenant property

$BOLD> vpnctl tenants <TENANTID> edit$DEFAULT
opens the default editor for editing the tenants configuration. These edits are validated. Invalid
configurations cannot be applied and will be rolled back.

$BOLD> vpnctl tenants <TENANTID> connection$DEFAULT
shows a list of all configured tunnels for a tenants

$BOLD> vpnctl tenants <TENANTID> connection 0 show$DEFAULT
shows the <TENANTID> tenant tunnel 0 VPN configuration

$BOLD> vpnctl tenants <TENANTID> connection 0 add/delete/set/unset$DEFAULT
add a new connection
delete a connection
set a connection property
remove a connection property

$BOLD> vpnctl tenants <TENANTID> commit$DEFAULT
copy the candidate configuration to the active configuration
reverting the candidate configuration, dry-runs and diffs are possible

$BOLD> vpnctl bgp show$DEFAULT
shows the bgp configuration

$BOLD> vpnctl bgp summary$DEFAULT
shows the active bgp state summary
"
