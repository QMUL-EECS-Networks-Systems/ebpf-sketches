#!/bin/bash

set -x

sudo ethtool --features ens4f0 ntuple off
sudo ethtool --features ens4f0 ntuple on
sudo ethtool -N ens4f0 flow-type udp4 dst-ip 192.168.1.1 m 255.255.255.255 action 1
sudo ethtool -N ens4f0 flow-type tcp4 dst-ip 192.168.1.1 m 255.255.255.255 action 1
