#!/usr/bin/env bash

ip route add 172.10.2.0/24 via 172.10.1.10

exec "$@"