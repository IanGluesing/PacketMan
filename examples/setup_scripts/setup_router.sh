#!/usr/bin/env bash

# Add trace for raw table
iptables-nft -t raw -I OUTPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t raw -I PREROUTING ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE

# Add trace for filter table
iptables-nft -t filter -I INPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t filter -I FORWARD ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t filter -I OUTPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE

# Add trace for nat table
iptables-nft -t nat -I PREROUTING ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t nat -I INPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t nat -I OUTPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t nat -I POSTROUTING ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE

# Add trace for mangle table
iptables-nft -t mangle -I PREROUTING ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t mangle -I INPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t mangle -I FORWARD ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t mangle -I OUTPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t mangle -I POSTROUTING ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE

# Add trace for security table
iptables-nft -t security -I INPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t security -I FORWARD ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE
iptables-nft -t security -I OUTPUT ! -s 172.10.1.254 !  -d 172.10.1.254 -j TRACE

if [[ -f "/usr/local/bin/example_specific_helpers.sh" ]]; then
    /usr/local/bin/example_specific_helpers.sh
fi
    
exec "$@"