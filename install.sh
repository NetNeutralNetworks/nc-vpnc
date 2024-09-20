#! /bin/bash

SERVICENAME=vpnc
SCRIPTDIR="$(dirname -- "$BASH_SOURCE")"
BASEDIR=/opt/ncubed
INSTALLDIR=${BASEDIR}/${SERVICENAME}

FRRVER="frr-stable"

function install_apt_defaults () {
    # update and install general packages

    apt-get update
    # If systemd is the init system
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        apt-get upgrade -y
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iptables iproute2 \
    strongswan strongswan-swanctl \
    ssh autossh \
    wireguard

    # Remove cached apt list after install
    if  [ -f /.dockerenv ]; then
        rm -rf /var/lib/apt/lists/*
    fi

    # If systemd is the init system
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        # Disable/Mask the IPsec service
        /usr/bin/systemctl mask ipsec.service
        /usr/bin/systemctl stop ipsec.service
    fi

    groupadd swan
    useradd -g swan swan

    chown -R swan:swan /etc/swanctl
}

function install_apt_python () {
    # update and install python packages

    apt-get update
    apt-get install -y python3 python3-pip python3-venv

    # Remove cached apt list after install
    if  [ -f /.dockerenv ]; then
        rm -rf /var/lib/apt/lists/*
    fi

}

function install_apt_build () {
    # Install packages required to build the Python packages
    apt-get update
    apt-get install -y build-essential libnetfilter-queue-dev \
        python3 python3-dev python3-pip python3-setuptools python3-wheel python3-venv

    # Remove cached apt list after install
    if  [ -f /.dockerenv ]; then
        rm -rf /var/lib/apt/lists/*
    fi
}

function install_apt_hub () {
    # Install hub defaults
    apt-get update
    modprobe -r jool
    apt-get remove -y jool-tools
    apt-get install -y jool-tools kmod libnetfilter-queue-dev

    # Remove cached apt list after install
    if  [ -f /.dockerenv ]; then
        rm -rf /var/lib/apt/lists/*
    fi

    mkdir -p ${BASEDIR}/config/vpncmangle
}

function install_apt_snmpd () {
    # Install and configure snmpd

    apt-get install -y snmpd
    # Configure SNMP daemon
    sed -i -E 's/^rocommunity (.*)/#rocommunity \1/' /etc/snmp/snmpd.conf
    sed -i -E 's/^rocommunity6 (.*)/#rocommunity6 \1/' /etc/snmp/snmpd.conf
    sed -i -E 's/^agentaddress(.*)/#agentaddress\1/' /etc/snmp/snmpd.conf
    sed -i 's/^rouser authPrivUser authpriv -V systemonly$/#rouser authPrivUser authpriv -V systemonly/' /etc/snmp/snmpd.conf

    # If systemd is the init system
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        # Enable the SNMP service
        /usr/bin/systemctl enable snmpd.service
        /usr/bin/systemctl restart snmpd.service
    fi

    echo "Configure SNMP with the following command (if not already configured) after stopping the snmpd service."
    echo "The space in front of the command makes sure it isn't logged into the Bash history."
    echo " net-snmp-create-v3-user -ro -a SHA -A <authpass> -x AES -X <privpass> nc-snmp"
}

function install_apt_frr () {
    # Install and configure FRR service

    # In docker the ADD directive is used.
    apt-get update
    apt-get install -y curl lsb-release
    curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null
    echo deb '[signed-by=/usr/share/keyrings/frrouting.gpg]' https://deb.frrouting.org/frr \
        $(lsb_release -s -c) $FRRVER | tee -a /etc/apt/sources.list.d/frr.list
    apt-get remove -y curl lsb-release

    apt-get update
    apt-get install -y frr frr-pythontools frr-snmp

    # Remove cached apt list after install
    if  [ -f /.dockerenv ]; then
        rm -rf /var/lib/apt/lists/*
    fi

    # Configure FRR daemon
    sed -i 's/^bgpd=no$/bgpd=yes/' /etc/frr/daemons
    sed -i 's/^bfdd=no$/bfdd=yes/' /etc/frr/daemons

    sed -i 's/^zebra_options="  -A 127.0.0.1 -s 90000000.*"$/zebra_options="  -A 127.0.0.1 -s 90000000 -n -M snmp"/' /etc/frr/daemons
    sed -i 's/^bgpd_options="   -A 127.0.0.1.*"$/bgpd_options="   -A 127.0.0.1 -M snmp"/' /etc/frr/daemons

    # If systemd is the init system
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        # Disable/Mask the FRR service
        /usr/bin/systemctl mask frr.service
        /usr/bin/systemctl stop frr.service
    fi
}

function create_misc_config () {
    # Create config for various services

    # Copy configuration files over to the configuration directories.
    cp -rf ${SCRIPTDIR}/config/snmp/vpnc.conf /etc/snmp/snmpd.conf.d/
    cp -rf ${SCRIPTDIR}/config/strongswan/vpnc.conf /etc/strongswan.d/
}

function create_vpnc_config () {
    # Create config directories if not exist
    for i in {candidate,active,units};
    do
        mkdir -p ${BASEDIR}/config/${SERVICENAME}/${i}
        mkdir -p ${BASEDIR}/config/${SERVICENAME}/${i}
    done

    mkdir -p /var/log/ncubed/vpnc

    if [[ -z "${1}" ]]; then
        MODE="hub"
    else
        MODE=${1}
    fi

    if [ "${MODE}" != "hub" ]; then
    cp -n ${SCRIPTDIR}/config/${SERVICENAME}/config/config.yaml.example \
        ${BASEDIR}/config/${SERVICENAME}/candidate/config.yaml.example || true
    fi
    # cp --update=none ${BASEDIR}/config/${SERVICENAME}/candidate/service/config-$1.yaml.example \
    cp -n ${SCRIPTDIR}/config/${SERVICENAME}/config/config-${MODE}.yaml.example \
        ${BASEDIR}/config/${SERVICENAME}/candidate/DEFAULT.yaml || true
    # cp --update=none ${BASEDIR}/config/${SERVICENAME}/candidate/service/config-$1.yaml.example \
    cp -n ${SCRIPTDIR}/config/${SERVICENAME}/config/config-${MODE}.yaml.example \
        ${BASEDIR}/config/${SERVICENAME}/active/DEFAULT.yaml || true
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        cp -n ${SCRIPTDIR}/config/${SERVICENAME}/units/ncubed-${SERVICENAME}.service \
            ${BASEDIR}/config/${SERVICENAME}/units/ncubed-${SERVICENAME}.service || true
    fi

}

function create_dir_vpnc () {
    # Create install directory if not exist
    mkdir -p ${INSTALLDIR}

    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        # system-site packages fails on systemd
        python3 -m venv --clear ${INSTALLDIR}
    else
        # Create Python virtual environment
        python3 -m venv --clear --system-site-packages ${INSTALLDIR}
    fi

}

function install_pip_vpnc () {
    # Install requirements and vpnc
    ${INSTALLDIR}/bin/python3 -m pip install --upgrade ${SCRIPTDIR}/${SERVICENAME}
}

function install_pip_vpncmangle () {
    # Install vpncmangle
    ${INSTALLDIR}/bin/python3 -m pip install --upgrade ${SCRIPTDIR}/vpncmangle
}

function start_service_vpnc () {
    # If systemd is the init system
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        # Enable the VPNC service
        /usr/bin/systemctl restart ncubed-${SERVICENAME}
    fi
}

function register_service_vpnc () {
    # If systemd is the init system
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        # Enable the VPNC service
        /usr/bin/systemctl link ${BASEDIR}/config/vpnc/units/ncubed-${SERVICENAME}.service
        /usr/bin/systemctl daemon-reload
        /usr/bin/systemctl enable ncubed-${SERVICENAME}
    fi
}

function unregister_service_vpnc () {
    # If systemd is the init system
    if [ "$(ps -p 1 -o comm=)" == "systemd" ]; then
        # Make sure the newest unit file is loaded
        /usr/bin/systemctl stop ncubed-${SERVICENAME}.service
        /usr/bin/systemctl disable ncubed-${SERVICENAME}.service
    fi
}

function install_vpnc () {
    case $1 in
    hub)
        echo "Installing in ${1} mode"
        unregister_service_vpnc

        install_apt_defaults
        install_apt_python
        install_apt_build
        install_apt_frr
        install_apt_hub
        install_apt_snmpd

        create_vpnc_config
        create_dir_vpnc
        create_misc_config

        install_pip_vpnc
        install_pip_vpncmangle

        register_service_vpnc
        start_service_vpnc

        ;;
    endpoint)
        echo "Installing in ${1} mode"
        unregister_service_vpnc

        install_apt_defaults
        install_apt_python
        install_apt_snmpd

        create_vpnc_config
        create_dir_vpnc
        create_misc_config

        install_pip_vpnc

        register_service_vpnc
        start_service_vpnc

        ;;
    addon)
        echo "Installing in ${1} mode"
        unregister_service_vpnc

        install_apt_defaults
        install_apt_python

        create_vpnc_config
        create_dir_vpnc
        create_misc_config

        install_pip_vpnc

        register_service_vpnc
        start_service_vpnc

        ;;
    *)
        echo "Argument should be either 'hub', 'endpoint' or 'addon'"
        ;;
    esac
}

# Run migrations to current version
# ${SCRIPTDIR}/setup/migrate.sh
# ${INSTALLDIR}/bin/python3 ${SCRIPTDIR}/setup/migrate.py
