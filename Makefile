# Install vpnc on Ubuntu, as root, from the repository root:
#   make hub | make endpoint   full install (apt upgrade included)
#   make upgrade               the full install again, of the installed type
#   make update                vpnc and vpnctl only; restarts on change
# Config files are only installed when missing, so local edits are kept.
# make.conf holds the install type and the time of the daily update, followed
# by a reboot if it needs one: make asks for what's missing in it and not given
# (make update UPDATE_TIME=02:00). make hub|endpoint refuse the other type.
# The Dockerfiles use the step targets.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
.NOTPARALLEL:

BASEDIR := /opt/ncubed
VENV    := $(BASEDIR)/vpnc
CONFDIR := $(BASEDIR)/config/vpnc
STAMP   := $(VENV)/.installed
UNIT    := ncubed-vpnc.service

APT := DEBIAN_FRONTEND=noninteractive apt-get
# No systemd running in image builds: units are set up (UNITCTL), but nothing
# is started, stopped or reloaded there.
SYSTEMD   := $(wildcard /run/systemd/system)
SYSTEMCTL := $(if $(SYSTEMD),/usr/bin/systemctl,: skip systemctl)
UNITCTL   := /usr/bin/systemctl
# Nor is AppArmor policy loaded there.
AA_PARSER := $(if $(wildcard /sys/kernel/security/apparmor/profiles),/usr/sbin/apparmor_parser,: skip apparmor_parser)

# Ubuntu's Python packages, which the venv uses (system site packages), and
# their names on PyPI: the lock leaves those out. Not dnspython: vpncmangle needs
# 2.9, which refuses compressed names where RFCs forbid them; the venv's copy is
# in front of Ubuntu's 2.8 (a dependency of python3-email-validator).
PYTHON_DEBS := python3-idna python3-jinja2 python3-packaging python3-pydantic \
	python3-yaml python3-watchdog
MANGLE_DEBS := python3-netfilterqueue
SYSTEM_PYPI := annotated-types idna jinja2 markupsafe netfilterqueue packaging \
	pydantic pydantic-core pyyaml typing-extensions typing-inspection watchdog

# Valid values from make.conf (vpnc can't write it): never code.
MAKE_CONF := $(BASEDIR)/config/make.conf
conf = $(lastword $(shell sed -nE 's/^$(1)=($(2))$$/\1/p' $(MAKE_CONF) 2> /dev/null))
TIME := ([01][0-9]|2[0-3]):[0-5][0-9]

# hub or endpoint, also the example service configuration: only from make.conf
# (re-read when used), or set by the install targets.
MODE ?= $(call conf,MODE,hub|endpoint)
UPDATE_TIME ?= $(call conf,UPDATE_TIME,$(TIME))

VPNC_SRC       := $(shell find vpnc -type f ! -path '*/build/*' ! -path '*.egg-info/*' ! -name '*.pyc' 2>/dev/null)
VPNCMANGLE_SRC := $(shell find vpncmangle -type f ! -path '*/build/*' ! -path '*.egg-info/*' ! -name '*.pyc' 2>/dev/null)

MISC_CONF := /etc/strongswan.d/vpnc.conf /etc/iproute2/rt_protos.d/vpnc.conf
MODULES_CONF := /etc/modules-load.d/vpnc.conf
# vpnc's AppArmor profile, and what the profiles of the daemons it starts need.
APPARMOR := /etc/apparmor.d/ncubed-vpnc /etc/apparmor.d/ncubed-vpncmangle
AA_LOCAL := usr.lib.ipsec.charon bgpd bfdd staticd
SNMP_CONF := /etc/snmp/snmpd.conf.d/vpnc.conf
FRR_SNMP_CONF := /etc/snmp/frr.conf
# Installed by vpnc before it was renamed vpnc.conf; its TCP sockets override vpnc's.
OLD_SNMP_CONF := /etc/snmp/snmpd.conf.d/frr-snmp.conf
VPNCTL    := /usr/local/bin/vpnctl /etc/bash_completion.d/vpnctl \
	/usr/share/zsh/vendor-completions/_vpnctl /etc/profile.d/profile-nc-vpn.sh

.PHONY: help hub endpoint upgrade update update-steps root apt-update packages python-packages \
	python-debs hub-packages frr snmpd old-snmp-config config misc-config venv \
	pip-vpnc pip-vpncmangle lock vpnctl apparmor service start maintenance \
	maintenance-units

help:
	@echo "As root: make hub | make endpoint | make upgrade | make update"

# Full installs.

hub: override MODE := hub
hub: root maintenance packages python-packages frr hub-packages $(MODULES_CONF) snmpd \
	account-vpnc-mangle account-vpnc-ssh config misc-config pip-vpnc pip-vpncmangle \
	vpnctl apparmor service start

endpoint: override MODE := endpoint
endpoint: root maintenance packages python-packages snmpd \
	config misc-config pip-vpnc vpnctl apparmor service start

# upgrade and update run in a new make, which reads the type from make.conf.

# The full install again, of the type in make.conf.
upgrade: root maintenance
	$(MAKE) --no-print-directory $(MODE)

update: root maintenance
	$(MAKE) --no-print-directory update-steps

# vpncmangle, its accounts, Jool and FRR's SNMP settings only on a hub.
update-steps: python-debs pip-vpnc $(if $(filter hub,$(MODE)),\
	account-vpnc-mangle account-vpnc-ssh pip-vpncmangle $(MODULES_CONF) $(FRR_SNMP_CONF)) \
	misc-config $(SNMP_CONF) old-snmp-config vpnctl apparmor \
	$(if $(SYSTEMD),$(CONFDIR)/units/$(UNIT) $(STAMP)/started)

root:
	@[ "$$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }

# Packages.

apt-update:
	apt-get update

# strongswan-starter/-charon: vpnc uses "ipsec start"; from 26.04 the
# strongswan metapackage installs charon-systemd instead.
# kmod: vpnc runs modinfo.
# apparmor: vpnc's profile, and those of charon and FRR.
# iputils-ping, traceroute, tcpdump: vpnctl ping, traceroute and capture.
# curl: the API from the shell (README).
# unattended-upgrades, update-notifier-common: the daily update, and its
# reboot when /run/reboot-required says one is needed.
packages: apt-update
	$(if $(SYSTEMD),$(APT) upgrade -y)
	$(APT) install -y nftables iproute2 kmod apparmor \
		strongswan strongswan-swanctl strongswan-starter strongswan-charon \
		ssh wireguard iputils-ping traceroute tcpdump curl \
		unattended-upgrades update-notifier-common
	$(UNITCTL) mask ipsec.service strongswan-starter.service strongswan.service
	$(SYSTEMCTL) stop ipsec.service strongswan-starter.service strongswan.service || true

# An account vpnc runs a program as, instead of as root.
account-%:
	id $* > /dev/null 2>&1 || useradd --system --no-create-home \
		--home-dir /nonexistent --shell /usr/sbin/nologin $*

# The account of ssh, with the keys vpnc makes per connection.
SSH_HOME  := /var/lib/vpnc-ssh
SSH_OWNER := -o vpnc-ssh -g "$$(id -gn vpnc-ssh)"

account-vpnc-ssh:
	id vpnc-ssh > /dev/null 2>&1 || useradd --system --no-create-home \
		--home-dir $(SSH_HOME) --shell /usr/sbin/nologin vpnc-ssh
	install -d -m 700 $(SSH_OWNER) $(SSH_HOME) $(SSH_HOME)/.ssh

# python3-setuptools builds vpnc and vpncmangle.
python-packages: apt-update
	$(APT) install -y python3 python3-venv python3-setuptools $(PYTHON_DEBS)

# make update: Ubuntu's Python packages, if missing (older installs lack them).
UPDATE_DEBS := python3-venv python3-setuptools $(PYTHON_DEBS) $(if $(filter hub,$(MODE)),$(MANGLE_DEBS))
python-debs:
	dpkg -s $(UPDATE_DEBS) > /dev/null 2>&1 || { apt-get update && $(APT) install -y $(UPDATE_DEBS); }

hub-packages: apt-update
	$(APT) install -y jool-tools kmod $(MANGLE_DEBS)
	mkdir -p $(BASEDIR)/config/vpncmangle

# Jool, loaded at boot: vpnc's unit can't load modules.
$(MODULES_CONF): config/modules-load/vpnc.conf
	install -D -m 644 $< $@
	$(SYSTEMCTL) restart systemd-modules-load.service

# FRR runs under vpnc: the frr service is masked. Ubuntu's FRR: installs before
# 2026-11 added FRR's own repository, whose newer FRR is downgraded. The
# daemons file is kept; vpnc writes the rest of FRR's configuration.
FRR_REPO := /etc/apt/sources.list.d/frr.list /usr/share/keyrings/frrouting.gpg
frr: apt-update
	if [ -e $(firstword $(FRR_REPO)) ]; then rm -f $(FRR_REPO); apt-get update; fi
	version=$$(apt-cache madison frr | awk '{ print $$3; exit }'); \
	$(APT) install -y --allow-downgrades -o Dpkg::Options::=--force-confold \
		frr=$$version frr-pythontools=$$version frr-snmp=$$version
	install -D -m 644 config/snmp/frr.conf $(FRR_SNMP_CONF)
	sed -i 's/^bgpd=no$$/bgpd=yes/; s/^bfdd=no$$/bfdd=yes/' /etc/frr/daemons
	sed -i 's/^zebra_options="  -A 127.0.0.1 -s 90000000.*"$$/zebra_options="  -A 127.0.0.1 -s 90000000 -n -M snmp"/' /etc/frr/daemons
	sed -i 's/^bgpd_options="   -A 127.0.0.1.*"$$/bgpd_options="   -A 127.0.0.1 -M snmp"/' /etc/frr/daemons
	$(UNITCTL) mask frr.service
	$(SYSTEMCTL) stop frr.service || true

snmpd: apt-update
	$(APT) install -y snmpd
	sed -i -E 's/^(rocommunity6? .*)/#\1/; s/^(agentaddress.*)/#\1/' /etc/snmp/snmpd.conf
	sed -i 's/^rouser authPrivUser authpriv -V systemonly$$/#&/' /etc/snmp/snmpd.conf
	install -D -m 644 config/snmp/vpnc.conf $(SNMP_CONF)
	rm -f $(OLD_SNMP_CONF)
	$(UNITCTL) enable snmpd.service
	$(SYSTEMCTL) restart snmpd.service
	@echo "Configure SNMP with the following command (if not already configured) after stopping the snmpd service."
	@echo "The space in front of the command makes sure it isn't logged into the Bash history."
	@echo " net-snmp-create-v3-user -ro -a SHA -A <authpass> -x AES -X <privpass> nc-snmp"

# Configuration. File targets without prerequisites: created when missing, never overwritten.

config: $(CONFDIR)/candidate/DEFAULT.yaml $(CONFDIR)/active/DEFAULT.yaml
	$(if $(filter endpoint,$(MODE)),,[ -e $(CONFDIR)/candidate/config.yaml.example ] || \
		install -m 600 config/vpnc/config/config.yaml.example $(CONFDIR)/candidate/)
	chmod 700 $(CONFDIR)/candidate $(CONFDIR)/active $(CONFDIR)/history

# These hold pre-shared and private keys.
$(CONFDIR)/candidate $(CONFDIR)/active $(CONFDIR)/history:
	install -d -m 700 $@

$(CONFDIR)/candidate/DEFAULT.yaml $(CONFDIR)/active/DEFAULT.yaml: | $(CONFDIR)/candidate $(CONFDIR)/active $(CONFDIR)/history
	install -m 600 config/vpnc/config/config-$(MODE).yaml.example $@

# vpnc, vpncmangle and charon log to the journal now; this rotated charon's
# old log file.
# Installs before 2024-08 replaced strongswan.conf with one that skips
# strongswan.d, so charon ignored vpnc.conf (and ran as root): Ubuntu's default
# is put back, and vpnc.conf touched so vpnc and charon restart.
misc-config: $(MISC_CONF)
	rm -f /etc/logrotate.d/vpnc
	@if ! grep -qs '^include strongswan.d/\*.conf' /etc/strongswan.conf; then \
		echo "Replacing /etc/strongswan.conf, the old one is strongswan.conf.vpnc-old."; \
		[ ! -e /etc/strongswan.conf ] || \
			mv /etc/strongswan.conf /etc/strongswan.conf.vpnc-old; \
		install -m 644 config/strongswan/strongswan.conf /etc/strongswan.conf; \
		touch /etc/strongswan.d/vpnc.conf; \
	fi

# vpnc's own drop-ins: replaced when they change. charon runs as vpnc-swan.
/etc/strongswan.d/vpnc.conf: config/strongswan/vpnc.conf | account-vpnc-swan
	install -D -m 644 $< $@

/etc/iproute2/rt_protos.d/vpnc.conf: config/iproute2/vpnc.conf
	install -D -m 644 $< $@

# vpnc's own drop-in: replaced when it changes.
$(SNMP_CONF): config/snmp/vpnc.conf
	install -D -m 644 $< $@
	$(SYSTEMCTL) try-restart snmpd.service

old-snmp-config:
	@if [ -e $(OLD_SNMP_CONF) ]; then \
		echo "Removing $(OLD_SNMP_CONF)"; rm -f $(OLD_SNMP_CONF); \
		$(SYSTEMCTL) try-restart snmpd.service; \
	fi

# Read by the FRR daemons when vpnc starts them.
$(FRR_SNMP_CONF): config/snmp/frr.conf
	install -D -m 644 $< $@

# Python packages, at the locked versions (make lock). Stamps live in the venv,
# so a new venv reinstalls them.

# Recreate a missing or broken venv (e.g. Python changed in a release upgrade),
# one without system site packages, or one with an older lock: pip doesn't remove
# packages the lock dropped, which would stay in front of Ubuntu's.
ifneq ($(shell $(VENV)/bin/python3 -c pass 2>/dev/null && \
	grep -qx 'include-system-site-packages = true' $(VENV)/pyvenv.cfg && echo ok),ok)
.PHONY: $(VENV)/pyvenv.cfg
endif
$(VENV)/pyvenv.cfg: $(wildcard vpnc/requirements.txt vpncmangle/requirements.txt)
	python3 -m venv --clear --system-site-packages $(VENV)

venv: $(VENV)/pyvenv.cfg

PIP := $(VENV)/bin/python3 -m pip install

pip-vpnc: $(STAMP)/vpnc
pip-vpncmangle: $(STAMP)/vpncmangle

# Built with Ubuntu's setuptools. A normal prerequisite: a recreated venv (--clear
# removes the stamps) must reinstall them, which an order-only one may skip.
$(STAMP)/vpnc: $(VPNC_SRC) $(VENV)/pyvenv.cfg
	$(PIP) --require-hashes --no-build-isolation -r vpnc/requirements.txt
	$(PIP) --upgrade --no-deps --no-build-isolation ./vpnc
	mkdir -p $(@D) && touch $@

$(STAMP)/vpncmangle: $(VPNCMANGLE_SRC) $(VENV)/pyvenv.cfg
	$(PIP) --require-hashes --no-build-isolation -r vpncmangle/requirements.txt
	$(PIP) --upgrade --no-deps --no-build-isolation ./vpncmangle
	mkdir -p $(@D) && touch $@

# Lock the dependencies to their newest versions, with hashes, against the
# versions of Ubuntu's packages, which are left out. Not as root; run it on the
# Ubuntu release of the installs, with python-packages and hub-packages' Python
# packages installed.
LOCK_VENV := /tmp/vpnc-lock
COMPILE    = CUSTOM_COMPILE_COMMAND="make lock" $(LOCK_VENV)/bin/pip-compile --quiet \
	--upgrade --generate-hashes --strip-extras --constraint $(LOCK_VENV)/system.txt \
	$(addprefix --unsafe-package ,$(SYSTEM_PYPI))

lock:
	python3 -m venv --clear $(LOCK_VENV)
	$(LOCK_VENV)/bin/pip install --quiet pip-tools
	python3 -c 'import sys, importlib.metadata as m; \
		print(*(f"{p}=={m.version(p)}" for p in sys.argv[1:]), sep="\n")' \
		$(SYSTEM_PYPI) > $(LOCK_VENV)/system.txt
	cd vpnc && $(COMPILE) --output-file requirements.txt pyproject.toml
	cd vpncmangle && $(COMPILE) --output-file requirements.txt pyproject.toml

# vpnctl on the PATH, with bash and zsh completion and the login banner.
vpnctl: $(VPNCTL) typer-cleanup

/usr/local/bin/vpnctl:
	ln -sf $(VENV)/bin/vpnctl $@

/etc/bash_completion.d/vpnctl: $(STAMP)/vpnc
	mkdir -p $(@D) && $(VENV)/bin/vpnctl completion bash > $@

/usr/share/zsh/vendor-completions/_vpnctl: $(STAMP)/vpnc
	mkdir -p $(@D) && $(VENV)/bin/vpnctl completion zsh > $@

/etc/profile.d/profile-nc-vpn.sh: setup/profile-nc-vpn.sh
	install -D -m 644 $< $@

# The old typer vpnctl installed its own completion per user, at login; it
# overrides the one above and breaks it.
typer-cleanup:
	for home in /root /home/*; do \
		rm -f $$home/.bash_completions/vpnctl.sh $$home/.zfunc/_vpnctl; \
		[ ! -f $$home/.bashrc ] || \
			sed -i "\\|^source '$$home/.bash_completions/vpnctl.sh'$$|d" $$home/.bashrc; \
	done

# Service.

# AppArmor: vpnc's profile, which its unit needs. charon's and FRR's profiles
# include local/<name>: that includes vpnc's additions, and keeps local changes.
apparmor: $(APPARMOR) $(addprefix /etc/apparmor.d/ncubed-vpnc.d/,$(AA_LOCAL))

/etc/apparmor.d/ncubed-%: config/apparmor/ncubed-%
	install -D -m 644 $< $@
	$(AA_PARSER) -r $@

/etc/apparmor.d/ncubed-vpnc.d/%: config/apparmor/local/%
	install -D -m 644 $< $@
	grep -qsx 'include <ncubed-vpnc.d/$*>' /etc/apparmor.d/local/$* || \
		echo 'include <ncubed-vpnc.d/$*>' >> /etc/apparmor.d/local/$*
	[ ! -e /etc/apparmor.d/$* ] || $(AA_PARSER) -r /etc/apparmor.d/$*

service: $(CONFDIR)/units/$(UNIT)
	$(UNITCTL) link $(CONFDIR)/units/$(UNIT)
	$(SYSTEMCTL) daemon-reload
	$(UNITCTL) enable $(UNIT)

# make.conf, asking for what's missing in it and not given; written only when
# it changed. Refuses another type than the one in it: a hub stays a hub. Then
# unattended-upgrades' timer from it (a new make reads it).
maintenance:
	@mode='$(MODE)' saved='$(call conf,MODE,hub|endpoint)' update='$(UPDATE_TIME)'; \
	if [ -n "$$saved" ] && [ "$$mode" != "$$saved" ]; then \
		echo "This is an install of type $$saved (MODE in $(MAKE_CONF)): change it there to convert it." >&2; \
		exit 1; \
	fi; \
	until [[ $$mode =~ ^(hub|endpoint)$$ ]]; do \
		read -r -p "Install type (hub or endpoint): " mode || { echo "MODE=hub|endpoint is missing." >&2; exit 1; }; \
	done; \
	until [[ $$update =~ ^$(TIME)$$ ]]; do \
		read -r -p "Time of the daily update (HH:MM): " update || { echo "UPDATE_TIME=HH:MM is missing." >&2; exit 1; }; \
	done; \
	install -d $(dir $(MAKE_CONF)); \
	printf '%s\n' '# MODE: change it to convert the install. UPDATE_TIME: make update UPDATE_TIME=HH:MM.' \
		"MODE=$$mode" "UPDATE_TIME=$$update" > $(MAKE_CONF).tmp; \
	if cmp -s $(MAKE_CONF).tmp $(MAKE_CONF); then rm $(MAKE_CONF).tmp; else mv $(MAKE_CONF).tmp $(MAKE_CONF); fi
	$(MAKE) --no-print-directory maintenance-units

UPDATE_TIMER := /etc/systemd/system/apt-daily-upgrade.timer.d/ncubed-vpnc.conf

maintenance-units: $(UPDATE_TIMER) /etc/apt/apt.conf.d/52ncubed-vpnc

$(UPDATE_TIMER): config/systemd/apt-daily-upgrade.timer.d/ncubed-vpnc.conf $(MAKE_CONF)
	install -d $(@D)
	sed 's/@UPDATE_TIME@/$(UPDATE_TIME)/' $< > $@
	$(SYSTEMCTL) daemon-reload

/etc/apt/apt.conf.d/52ncubed-vpnc: config/apt/52ncubed-vpnc
	install -m 644 $< $@

# vpnc's own unit: replaced when it changes. Local changes go in a drop-in.
$(CONFDIR)/units/$(UNIT): config/vpnc/units/$(UNIT)
	install -D -m 644 $< $@
	$(SYSTEMCTL) daemon-reload

# A full install always restarts, e.g. for upgraded strongSwan or FRR.
start:
	$(SYSTEMCTL) restart $(UNIT)
	$(if $(SYSTEMD),mkdir -p $(STAMP) && touch $(STAMP)/started)

# make update restarts only when vpnc, vpncmangle, the unit or charon's settings
# changed; vpnc starts charon, which reads its settings only then.
$(STAMP)/started: $(STAMP)/vpnc $(if $(filter hub,$(MODE)),$(STAMP)/vpncmangle) \
	/etc/strongswan.d/vpnc.conf $(CONFDIR)/units/$(UNIT)
	$(SYSTEMCTL) restart $(UNIT)
	touch $@
