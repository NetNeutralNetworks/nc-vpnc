FROM ubuntu:noble-20240801 AS build

SHELL ["/bin/bash", "-c"]

RUN --mount=type=bind,source=install.sh,target=/tmp/repo/install.sh        \
    echo "Install APT build packages"                                   && \
    source /tmp/repo/install.sh                                         && \
    install_apt_build

RUN --mount=type=bind,source=./,target=/tmp/repo/                          \
    echo "Preparing configuration files"                                && \
    source /tmp/repo/install.sh                                         && \
    create_dir_vpnc

COPY ./ /tmp/repo/

RUN echo "Compile required modules"                                     && \
    source /tmp/repo/install.sh                                         && \
    install_pip_vpnc && install_pip_vpncmangle


# Multi-stage build
FROM ubuntu:noble-20240801

LABEL maintainer="beheer@ncubed.nl"
LABEL version="0.1.1"
LABEL description="vpnc VPN concentrator"

SHELL ["/bin/bash", "-c"]

# ADD https://deb.frrouting.org/frr/keys.gpg /usr/share/keyrings/frrouting.gpg

RUN --mount=type=bind,source=install.sh,target=/tmp/repo/install.sh        \
    --mount=type=bind,source=./config/,target=/tmp/repo/config/            \
    echo "Install APT packages"                                         && \
    source /tmp/repo/install.sh                                         && \
    install_apt_defaults                                                && \
    install_apt_hub                                                     && \
    install_apt_frr                                                     && \
    create_misc_config && create_vpnc_config

COPY --from=build /opt/ncubed/ /opt/ncubed/

# # Make sure to use the virtualenv:
# ENV PATH="/opt/ncubed/vpnc/bin:$PATH"

# Configuration and logging directories.
VOLUME /opt/ncubed/config/vpnc /var/log/ncubed/vpnc

CMD ["/opt/ncubed/vpnc/bin/vpnc"]
