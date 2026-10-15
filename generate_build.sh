#!/usr/bin/env bash

rm examples/*.deb
rm examples/*.rpm

nfpm package --config package.yaml --packager deb -t examples
nfpm package --config package.yaml --packager rpm -t examples