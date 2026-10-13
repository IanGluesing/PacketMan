#!/usr/bin/env bash

nfpm package --config package.yaml --packager deb
nfpm package --config package.yaml --packager rpm