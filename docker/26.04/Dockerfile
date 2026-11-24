FROM ubuntu:resolute-20261024.1 AS build

SHELL ["/bin/bash", "-c"]

RUN --mount=type=bind,source=Makefile,target=/tmp/repo/Makefile            \
    echo "Install Python packages and the venv"                         && \
    apt-get update && apt-get install -y make                           && \
    make -C /tmp/repo python-packages venv

COPY ./ /tmp/repo/

RUN echo "Compile required modules"                                     && \
    make -C /tmp/repo pip-vpnc pip-vpncmangle


# Multi-stage build
FROM ubuntu:resolute-20261024.1 AS vpnc

LABEL maintainer="beheer@ncubed.nl"
LABEL version="0.2.2"
LABEL description="vpnc VPN concentrator"

SHELL ["/bin/bash", "-c"]

RUN --mount=type=bind,source=Makefile,target=/tmp/repo/Makefile            \
    --mount=type=bind,source=./config/,target=/tmp/repo/config/            \
    echo "Install APT packages"                                         && \
    apt-get update && apt-get install -y make                           && \
    make -C /tmp/repo MODE=hub packages python-packages account-vpnc-mangle account-vpnc-ssh hub-packages /etc/modules-load.d/vpnc.conf frr snmpd misc-config config service && \
    rm -rf /var/lib/apt/lists/*

# systemd runs as on the VMs, without what a container has no use for.
RUN systemctl mask getty@.service console-getty.service                    \
    systemd-timesyncd.service systemd-resolved.service apt-daily.timer      \
    apt-daily-upgrade.timer motd-news.timer e2scrub_all.timer fstrim.timer  \
    dpkg-db-backup.timer

COPY --from=build /opt/ncubed/ /opt/ncubed/

RUN --mount=type=bind,source=Makefile,target=/tmp/repo/Makefile            \
    --mount=type=bind,source=./setup/,target=/tmp/repo/setup/              \
    make -C /tmp/repo vpnctl

# Configuration directory.
VOLUME /opt/ncubed/config/vpnc

# systemd as PID 1; the lab nodes' scripts exec it after their setup.
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]


# Lab test nodes (mgt, cli): vpnc image plus test tools, so nodes don't install
# packages at startup.
FROM vpnc AS lab

RUN apt-get update                                                      && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y                      \
    bind9 bind9-dnsutils iproute2 iptables iputils-ping openssh-server     \
    snmp tini                                                           && \
    rm -rf /var/lib/apt/lists/*

# No systemd: a minimal init as PID 1 passes signals on and reaps what daemons
# leave behind.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash"]
