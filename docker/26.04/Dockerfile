FROM ubuntu:resolute-20261024.1 AS build

SHELL ["/bin/bash", "-c"]

RUN --mount=type=bind,source=Makefile,target=/tmp/repo/Makefile            \
    echo "Install APT build packages and the venv"                      && \
    apt-get update && apt-get install -y make                           && \
    make -C /tmp/repo build-packages venv

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
    apt-get update && apt-get install -y make tini                      && \
    make -C /tmp/repo MODE=hub packages account-vpnc-mangle account-vpnc-ssh hub-packages frr snmpd misc-config config && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/ncubed/ /opt/ncubed/

RUN --mount=type=bind,source=Makefile,target=/tmp/repo/Makefile            \
    --mount=type=bind,source=./setup/,target=/tmp/repo/setup/              \
    make -C /tmp/repo vpnctl

# Configuration directory.
VOLUME /opt/ncubed/config/vpnc

# A minimal init as PID 1: passes signals on and reaps what daemons leave behind.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/ncubed/vpnc/bin/vpnc"]


# Lab test nodes (mgt, cli): vpnc image plus test tools, so nodes don't install
# packages at startup.
FROM vpnc AS lab

RUN apt-get update                                                      && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y                      \
    bind9 bind9-dnsutils iproute2 iptables iputils-ping openssh-server     \
    snmp                                                                && \
    rm -rf /var/lib/apt/lists/*
