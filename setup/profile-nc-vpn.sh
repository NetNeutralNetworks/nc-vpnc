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
Manage vpnc with 'vpnctl' (as root, with tab completion; -h for help):

$BOLD  vpnctl status$DEFAULT                                     mode, connections up, restart needed
$BOLD  vpnctl tenants|ni list$DEFAULT                            tenants, network instances
$BOLD  vpnctl connections list [--state down]$DEFAULT
$BOLD  vpnctl connections show|logs ID$DEFAULT
$BOLD  vpnctl connections reset ID ...$DEFAULT                   also stop, start
$BOLD  vpnctl bgp neighbors|routes$DEFAULT                       hub mode
$BOLD  vpnctl routes|ping|traceroute|tcp NI ...$DEFAULT          inside a network instance
$BOLD  vpnctl logs [--ni NI] [-f]$DEFAULT

$BOLD  vpnctl config show|edit|set|delete C0001 [PATH]$DEFAULT   staged in the candidate
$BOLD  vpnctl config diff|commit|discard C0001$DEFAULT           'service' for DEFAULT.yaml
$BOLD  vpnctl config commit C0001 --confirm 5m$DEFAULT           rolled back unless confirmed

"
