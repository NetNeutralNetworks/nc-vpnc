#!/bin/python3
import time
import json, yaml
import os, sys, glob
import subprocess

TRUSTED_NETNS="TRUST"
UNTRUSTED_NETNS="UNTRUST"
UNTRUSTED_INTERFACE_NAME="ens4"
UNTRUSTED_INTERFACE_IP="192.168.0.151/20"
UNTRUSTED_INTERFACE_GW="192.168.0.1"
TRUSTED_TRANSIT="fd33:2:f"
MGMT_PREFIX="fd33::/16"
CUSTOMER_PREFIX="fdcc::/16"

CUSTOMER_CONNECTIONS_PATH=f"/etc/netns/{UNTRUSTED_NETNS}/ipsec.d/customers"

import logging
from logging.handlers import RotatingFileHandler

# LOGGER
logger = logging.getLogger("ncubed vpnc daemon")
logger.setLevel(level=logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s(File:%(name)s,Line:%(lineno)d, %(funcName)s) - %(levelname)s - %(message)s', 
                                datefmt="%m/%d/%Y %H:%M:%S %p")
rothandler = RotatingFileHandler('/var/log/ncubed.vpnc.log', maxBytes=100000, backupCount=5)
rothandler.setFormatter(formatter)
logger.addHandler(rothandler)
logger.addHandler(logging.StreamHandler(sys.stdout))

def update_customer_netnamespaces():
    logger.info(f"Updating customer namespaces")
    # Get all existing customer namespaces (not the three default namespaces)
    netnamespaces = [ns for ns in os.listdir('/run/netns') if ns not in ['ROOT', TRUSTED_NETNS, UNTRUSTED_NETNS]]
    # Retrieves all customer IDs in IPsec config files
    output = subprocess.run(f'''grep -h conn {CUSTOMER_CONNECTIONS_PATH}/*.conf''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().split('\n')
    config_netns = list(set(i.split()[1] for i in output if i )) # transforms 'conn C0001' to C0001
    # Get the list of not yet configured customer namespaces and configure these.
    # Then start IPsec configuration for the customer in the untrusted namespace
    for netns in set(config_netns).difference(netnamespaces):
        logger.info(f"Creating netns {netns}")
        subprocess.run(f'''
            ip netns add {netns}
            ip netns exec {UNTRUSTED_NETNS} ipsec rereadall
            # is this needed?
            ip netns exec {UNTRUSTED_NETNS} ipsec start
            ip netns exec {UNTRUSTED_NETNS} ipsec start {netns}
        ''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().lower()
    
    # Remove any configured namespace that isn't in the IPsec configuration.
    for netns in set(netnamespaces).difference(config_netns):
        logger.info(f"Removing netns {netns}")
        subprocess.run(f'''
            ip netns exec {UNTRUSTED_NETNS} ipsec stop {netns}
            ip netns del {netns}
        ''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().lower()

# WATCHDOG
from watchdog.observers import Observer
from watchdog.events import (PatternMatchingEventHandler, FileModifiedEvent, 
                             FileCreatedEvent, FileDeletedEvent)

observer = Observer()
# Define what should happen when file is created, modified or deleted.
class Handler(PatternMatchingEventHandler):
    def on_created(self, event: FileCreatedEvent):
        logger.info(f'File {event.event_type}: {event.src_path}')
        #update_customer_netnamespaces()

    def on_modified(self, event: FileModifiedEvent):
        logger.info(f'File {event.event_type}: {event.src_path}')
        update_customer_netnamespaces()

    def on_deleted(self, event: FileDeletedEvent):
        logger.info(f'File {event.event_type}: {event.src_path}')
        update_customer_netnamespaces()

# Configure the event handler that watches directories. This doesn't start the handler.
observer.schedule(event_handler=Handler(patterns=["*.conf"], ignore_patterns=[], ignore_directories=True), 
                  path=CUSTOMER_CONNECTIONS_PATH, 
                  recursive=True)
# The handler will not be running as a thread.
observer.daemon = False

def setup_main():
    """
    Creates the trusted and untrusted namespaces and aliases the default namespace to ROOT.
    """
    # The untrusted namespace has internet connectivity. 
    # After creating this namespace, ipsec is restarted in this namespace.
    # No IPv6 routing is enabled on this namespace.
    # There is no connectivity to other namespaces.
    logger.info(f"Setting up {UNTRUSTED_NETNS} netns")
    subprocess.run(f'''
        ip netns add {UNTRUSTED_NETNS}
        ip link set {UNTRUSTED_INTERFACE_NAME} netns {UNTRUSTED_NETNS}
        ip -n {UNTRUSTED_NETNS} addr add {UNTRUSTED_INTERFACE_IP} dev {UNTRUSTED_INTERFACE_NAME}
        ip -n {UNTRUSTED_NETNS} link set dev {UNTRUSTED_INTERFACE_NAME} up
        ip -n {UNTRUSTED_NETNS} route add default via {UNTRUSTED_INTERFACE_GW}
        ipsec stop
        ip netns exec {UNTRUSTED_NETNS} ipsec start
    ''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().lower()

    logger.info(f"Setting up {TRUSTED_NETNS} netns")
    # The trusted namespace has no internet connectivity. 
    # IPv6 routing is enabled on the namespace.
    # There is a link between the ROOT namespace and the trusted namespace. 
    # The management prefix is reachable from this namespace.
    subprocess.run(f'''
        ip netns add {TRUSTED_NETNS}
        ip netns exec {TRUSTED_NETNS} sysctl -w net.ipv6.conf.all.forwarding=1
        
        ip link add {TRUSTED_NETNS}_I type veth peer name {TRUSTED_NETNS}_E netns {TRUSTED_NETNS}

        # ip link set netns {TRUSTED_NETNS} {TRUSTED_NETNS}_E
        ip -n {TRUSTED_NETNS} link set dev {TRUSTED_NETNS}_E up
        ip -n {TRUSTED_NETNS} addr add {TRUSTED_TRANSIT}::1/127 dev {TRUSTED_NETNS}_E

        ip link set dev {TRUSTED_NETNS}_I up
        ip addr add {TRUSTED_TRANSIT}::0/127 dev {TRUSTED_NETNS}_I

        ip -6 route add {MGMT_PREFIX} via {TRUSTED_TRANSIT}::1
    ''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().lower()
    
    # Test for the customer prefixes.
    logger.warning(f"Added route for testing from localhost, disable in production!!!")
    subprocess.run(f'''
        ip -6 route add {CUSTOMER_PREFIX} via {TRUSTED_TRANSIT}::1
    ''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().lower()

    # Makes the default network namespace available as ROOT. This makes for consistent operation.
    logger.info(f"Mounting default namespace as ROOT")
    subprocess.run(f'''
        touch /var/run/netns/ROOT
        mount --bind /proc/1/ns/net /var/run/netns/ROOT
    ''', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode().lower()

if __name__ == '__main__':
    logger.info(100*'#')
    logger.info(f"Started VPNC daemon")

    setup_main()
    update_customer_netnamespaces()

    # Start the event handler.
    logger.info(f"Monitoring config changes")
    observer.start()
    