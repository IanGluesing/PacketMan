#!/usr/bin/env bash

iptables-nft -t filter -I OUTPUT -p icmp -j DROP