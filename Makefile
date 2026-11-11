# Install vpnc on Ubuntu, as root, from the repository root:
#   make hub | make endpoint | make addon   full install (apt upgrade included)
#   make update                             vpnc and vpnctl only; restarts on change
# Config files are only installed when missing, so local edits are kept.
# The Dockerfiles use the step targets.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
.NOTPARALLEL:

BASEDIR := /opt/ncubed
VENV    := $(BASEDIR)/vpnc
CONFDIR := $(BASEDIR)/config/vpnc
LOGDIR  := /var/log/ncubed/vpnc
STAMP   := $(VENV)/.installed
UNIT    := ncubed-vpnc.service
FRRVER  := frr-stable

APT := DEBIAN_FRONTEND=noninteractive apt-get
# No systemd in Docker builds: skip systemctl there.
SYSTEMD   := $(wildcard /run/systemd/system)
SYSTEMCTL := $(if $(SYSTEMD),/usr/bin/systemctl,: skip systemctl)
# System site packages fail with systemd; Docker relies on them.
VENV_OPTS := $(if $(SYSTEMD),,--system-site-packages)

# hub, endpoint or addon; set by the install targets.
MODE ?= hub
# The example service configuration: endpoint, or hub (also for addon).
CONFIG_MODE = $(if $(filter endpoint,$(MODE)),endpoint,hub)

VPNC_SRC       := $(shell find vpnc -type f ! -path '*/build/*' ! -path '*.egg-info/*' ! -name '*.pyc' 2>/dev/null)
VPNCMANGLE_SRC := $(shell find vpncmangle -type f ! -path '*/build/*' ! -path '*.egg-info/*' ! -name '*.pyc' 2>/dev/null)

MISC_CONF := /etc/strongswan.d/vpnc.conf /etc/iproute2/rt_protos.d/vpnc.conf \
	$(if $(wildcard /etc/logrotate.d),/etc/logrotate.d/vpnc)
SNMP_CONF := /etc/snmp/snmpd.conf.d/vpnc.conf
VPNCTL    := /usr/local/bin/vpnctl /etc/bash_completion.d/vpnctl \
	/usr/share/zsh/vendor-completions/_vpnctl

.PHONY: help hub endpoint addon update root apt-update packages python-packages \
	build-packages hub-packages frr snmpd config misc-config venv pip-vpnc \
	pip-vpncmangle vpnctl service start

help:
	@echo "As root: make hub | make endpoint | make addon | make update"

# Full installs.

hub: MODE := hub
hub: root packages python-packages build-packages frr hub-packages snmpd \
	config misc-config pip-vpnc pip-vpncmangle vpnctl service start

endpoint: MODE := endpoint
endpoint: root packages python-packages snmpd \
	config misc-config pip-vpnc vpnctl service start

addon: MODE := addon
addon: root packages python-packages \
	config misc-config pip-vpnc vpnctl service start

# vpncmangle only where it's installed (hub).
update: root pip-vpnc $(if $(wildcard $(VENV)/bin/vpncmangle),pip-vpncmangle) \
	misc-config $(if $(wildcard /etc/snmp/snmpd.conf.d),$(SNMP_CONF)) vpnctl \
	$(if $(SYSTEMD),$(STAMP)/started)

root:
	@[ "$$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }

# Packages.

apt-update:
	apt-get update

# strongswan-starter/-charon: vpnc uses "ipsec start"; from 26.04 the
# strongswan metapackage installs charon-systemd instead.
# python3-packaging: the Docker venv uses system site packages, pip relies on it.
# kmod: vpnc runs modinfo and modprobe.
# iputils-ping, traceroute: vpnctl ping and traceroute.
packages: apt-update
	$(if $(SYSTEMD),$(APT) upgrade -y)
	$(APT) install -y nftables iproute2 kmod \
		strongswan strongswan-swanctl strongswan-starter strongswan-charon \
		python3-packaging ssh wireguard iputils-ping traceroute
	$(SYSTEMCTL) mask ipsec.service strongswan-starter.service
	$(SYSTEMCTL) stop ipsec.service strongswan-starter.service || true
	getent group swan > /dev/null || groupadd swan
	id swan > /dev/null 2>&1 || useradd -g swan swan
	chown -R swan:swan /etc/swanctl

python-packages: apt-update
	$(APT) install -y python3 python3-pip python3-venv

# To build the Python packages (vpncmangle's netfilterqueue).
build-packages: apt-update
	$(APT) install -y build-essential libnetfilter-queue-dev \
		python3 python3-dev python3-pip python3-setuptools python3-wheel python3-venv

hub-packages: apt-update
	$(APT) install -y jool-tools kmod libnetfilter-queue-dev
	mkdir -p $(BASEDIR)/config/vpncmangle

# FRR runs under vpnc: the frr service is masked.
frr: apt-update
	$(APT) install -y curl
	curl -fsS https://deb.frrouting.org/frr/keys.gpg -o /usr/share/keyrings/frrouting.gpg
	. /etc/os-release && echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg]" \
		"https://deb.frrouting.org/frr $$VERSION_CODENAME $(FRRVER)" > /etc/apt/sources.list.d/frr.list
	apt-get update
	$(APT) install -y frr frr-pythontools frr-snmp
	sed -i 's/^bgpd=no$$/bgpd=yes/; s/^bfdd=no$$/bfdd=yes/' /etc/frr/daemons
	sed -i 's/^zebra_options="  -A 127.0.0.1 -s 90000000.*"$$/zebra_options="  -A 127.0.0.1 -s 90000000 -n -M snmp"/' /etc/frr/daemons
	sed -i 's/^bgpd_options="   -A 127.0.0.1.*"$$/bgpd_options="   -A 127.0.0.1 -M snmp"/' /etc/frr/daemons
	$(SYSTEMCTL) mask frr.service
	$(SYSTEMCTL) stop frr.service || true

snmpd: apt-update
	$(APT) install -y snmpd
	sed -i -E 's/^(rocommunity6? .*)/#\1/; s/^(agentaddress.*)/#\1/' /etc/snmp/snmpd.conf
	sed -i 's/^rouser authPrivUser authpriv -V systemonly$$/#&/' /etc/snmp/snmpd.conf
	[ -e $(SNMP_CONF) ] || install -D -m 644 config/snmp/vpnc.conf $(SNMP_CONF)
	$(SYSTEMCTL) enable snmpd.service
	$(SYSTEMCTL) restart snmpd.service
	@echo "Configure SNMP with the following command (if not already configured) after stopping the snmpd service."
	@echo "The space in front of the command makes sure it isn't logged into the Bash history."
	@echo " net-snmp-create-v3-user -ro -a SHA -A <authpass> -x AES -X <privpass> nc-snmp"

# Configuration. File targets without prerequisites: created when missing, never overwritten.

config: $(CONFDIR)/candidate/DEFAULT.yaml $(CONFDIR)/active/DEFAULT.yaml \
	$(if $(SYSTEMD),$(CONFDIR)/units/$(UNIT))
	$(if $(filter endpoint,$(MODE)),,[ -e $(CONFDIR)/candidate/config.yaml.example ] || \
		install -m 600 config/vpnc/config/config.yaml.example $(CONFDIR)/candidate/)
	chmod 700 $(CONFDIR)/candidate $(CONFDIR)/active $(CONFDIR)/history
	mkdir -p $(LOGDIR)

# These hold pre-shared and private keys.
$(CONFDIR)/candidate $(CONFDIR)/active $(CONFDIR)/history:
	install -d -m 700 $@

$(CONFDIR)/candidate/DEFAULT.yaml $(CONFDIR)/active/DEFAULT.yaml: | $(CONFDIR)/candidate $(CONFDIR)/active $(CONFDIR)/history
	install -m 600 config/vpnc/config/config-$(CONFIG_MODE).yaml.example $@

$(CONFDIR)/units/$(UNIT):
	install -D -m 644 config/vpnc/units/$(UNIT) $@

misc-config: $(MISC_CONF)

/etc/strongswan.d/vpnc.conf:
	install -D -m 644 config/strongswan/vpnc.conf $@

/etc/iproute2/rt_protos.d/vpnc.conf:
	install -D -m 644 config/iproute2/vpnc.conf $@

/etc/logrotate.d/vpnc:
	install -D -m 644 config/logrotate/vpnc $@

$(SNMP_CONF):
	install -D -m 644 config/snmp/vpnc.conf $@
	$(SYSTEMCTL) try-restart snmpd.service

# Python packages. Stamps live in the venv, so a new venv reinstalls them.

# Recreate a missing or broken venv (e.g. Python changed in a release upgrade).
ifneq ($(shell $(VENV)/bin/python3 -c pass 2>/dev/null && echo ok),ok)
.PHONY: $(VENV)/pyvenv.cfg
endif
$(VENV)/pyvenv.cfg:
	python3 -m venv --clear $(VENV_OPTS) $(VENV)

venv: $(VENV)/pyvenv.cfg

pip-vpnc: $(STAMP)/vpnc
pip-vpncmangle: $(STAMP)/vpncmangle

$(STAMP)/vpnc: $(VPNC_SRC) | $(VENV)/pyvenv.cfg
	$(VENV)/bin/python3 -m pip install --upgrade ./vpnc
	mkdir -p $(@D) && touch $@

$(STAMP)/vpncmangle: $(VPNCMANGLE_SRC) | $(VENV)/pyvenv.cfg
	$(VENV)/bin/python3 -m pip install --upgrade ./vpncmangle
	mkdir -p $(@D) && touch $@

# vpnctl on the PATH, with bash and zsh completion.
vpnctl: $(VPNCTL)

/usr/local/bin/vpnctl:
	ln -sf $(VENV)/bin/vpnctl $@

/etc/bash_completion.d/vpnctl: $(STAMP)/vpnc
	mkdir -p $(@D) && $(VENV)/bin/vpnctl completion bash > $@

/usr/share/zsh/vendor-completions/_vpnctl: $(STAMP)/vpnc
	mkdir -p $(@D) && $(VENV)/bin/vpnctl completion zsh > $@

# Service.

service:
	$(SYSTEMCTL) link $(CONFDIR)/units/$(UNIT)
	$(SYSTEMCTL) daemon-reload
	$(SYSTEMCTL) enable $(UNIT)

# A full install always restarts, e.g. for upgraded strongSwan or FRR.
start:
	$(SYSTEMCTL) restart $(UNIT)
	$(if $(SYSTEMD),mkdir -p $(STAMP) && touch $(STAMP)/started)

# make update restarts only when vpnc or vpncmangle changed.
$(STAMP)/started: $(STAMP)/vpnc $(wildcard $(STAMP)/vpncmangle)
	$(SYSTEMCTL) restart $(UNIT)
	touch $@
