#!/bin/bash

set -x

if [ -z "$1" ]; then
    echo "Usage: $0 DEVICE NUM_CORES"
    exit 1
fi

IFACE=$1

if [ -z "$2" ]; then
    echo "Usage: $0 DEVICE NUM_CORES"
    exit 1
fi

NUM_CORES=$2

sudo ifconfig ${IFACE} up promisc

sudo ethtool --features ${IFACE} ntuple off
sudo ethtool --features ${IFACE} ntuple on

#sudo ethtool -L ${IFACE} combined ${NUM_CORES}

if [[ "$NUM_CORES" -gt 10 ]]; then
    echo "Maximum number of supported core is 10"
    exit 1
fi

if [[ "$NUM_CORES" -gt 0 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.1 action 1
fi

if [[ "$NUM_CORES" -gt 1 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.2 action 3
fi

if [[ "$NUM_CORES" -gt 2 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.3 action 5
fi

if [[ "$NUM_CORES" -gt 3 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.4 action 7
fi

if [[ "$NUM_CORES" -gt 4 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.5 action 9
fi

if [[ "$NUM_CORES" -gt 5 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.6 action 11
fi

if [[ "$NUM_CORES" -gt 6 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.7 action 13
fi

if [[ "$NUM_CORES" -gt 7 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.8 action 15
fi

if [[ "$NUM_CORES" -gt 8 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.9 action 17
fi

if [[ "$NUM_CORES" -gt 9 ]]; then
    sudo ethtool -N ${IFACE} flow-type tcp4 dst-ip 192.168.1.10 action 19
fi