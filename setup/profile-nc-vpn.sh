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
Manage vpnc with 'vpnctl' (as root; tab completes; -h for help; -o wide|json|yaml):

State
$BOLD  vpnctl status$DEFAULT                                     mode, connections up, restart needed
$BOLD  vpnctl tenants list$DEFAULT                               tenants and their connections up
$BOLD  vpnctl ni list [C0001]$DEFAULT                            network instances
$BOLD  vpnctl ni show C0001-00$DEFAULT                           with its NAT64 and NPTv6 translations
$BOLD  vpnctl connections list [C0001|C0001-00]$DEFAULT          -o wide: MTU, traffic and rates
$BOLD  vpnctl connections list --oper-status DOWN$DEFAULT        what's down; also --admin-status, --type
$BOLD  vpnctl connections show C0001-00-0$DEFAULT                status, last change, SAs, counters
$BOLD  vpnctl bgp neighbors$DEFAULT                              hub mode; in detail: bgp neighbor ADDRESS
$BOLD  vpnctl bgp routes [--received-from ADDRESS]$DEFAULT       also --advertised-to
$BOLD  vpnctl version$DEFAULT                                    vpnc, kernel, strongSwan, FRR

Troubleshooting
$BOLD  vpnctl connections logs C0001-00-0 [-f]$DEFAULT           vpnc's, ssh's and charon's lines
$BOLD  vpnctl logs --ni C0001-00 [-f]$DEFAULT                    a network instance and its connections
$BOLD  vpnctl logs --level WARNING -n 100$DEFAULT                also --source vpncmangle|charon
$BOLD  vpnctl routes C0001-00 [-4|-6]$DEFAULT                    installed, blackhole etc.
$BOLD  vpnctl ping C0001-00 10.0.0.1 [-c 5] [-s 1400]$DEFAULT    from the network instance
$BOLD  vpnctl traceroute C0001-00 10.0.0.1$DEFAULT
$BOLD  vpnctl tcp C0001-00 10.0.0.1 443$DEFAULT                  a TCP connection test
$BOLD  vpnctl capture C0001-00-0 [port 443] [-c 20]$DEFAULT      tcpdump, with its options; -w FILE: pcap
$BOLD  vpnctl capture EXTERNAL esp$DEFAULT                       a network instance; IKE: port 500 or 4500
$BOLD  vpnctl connections reset C0001-00-0$DEFAULT               new IKE SA, WireGuard or SSH session
$BOLD  vpnctl connections stop|start C0001-00-0$DEFAULT          sets enabled in the configuration
$BOLD  vpnctl connections reset C0001$DEFAULT                    all VPN connections of a tenant

Configuration: staged in the candidate, 'service' for DEFAULT.yaml
$BOLD  vpnctl config list$DEFAULT                                tenants and their staged changes
$BOLD  vpnctl config show C0001 [PATH] [--candidate]$DEFAULT     also --reveal-secrets
$BOLD  vpnctl config edit C0001 [PATH]$DEFAULT                   in \$EDITOR; a new id creates a tenant
$BOLD  vpnctl config set C0001 PATH VALUE$DEFAULT                without VALUE: prompts (secrets)
$BOLD  vpnctl config delete C0001 [PATH]$DEFAULT                 without PATH: the tenant
$BOLD  vpnctl config diff C0001$DEFAULT                          the staged changes
$BOLD  vpnctl config commit C0001|--all [--confirm 5m]$DEFAULT   rolled back unless confirmed
$BOLD  vpnctl config confirm|discard C0001|--all$DEFAULT
$BOLD  vpnctl config history C0001 [REVISION]$DEFAULT            restore with: config restore C0001 REVISION
$BOLD  vpnctl service restart$DEFAULT                            vpnc itself, e.g. after changing the mode

Underneath
$BOLD  journalctl -u ncubed-vpnc -f$DEFAULT                      the service's output
$BOLD  ip -n C0001-00 -br addr$DEFAULT                           a network instance is a namespace
$BOLD  ip netns exec C0001-00 wg show$DEFAULT                    WireGuard's own view
$BOLD  swanctl --list-sas --ike C0001-00-0$DEFAULT               strongSwan's own view
$BOLD  vtysh -c 'show bgp vrf CORE summary'$DEFAULT              FRR's own view (hub mode)

"
