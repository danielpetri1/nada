#!/usr/bin/env bash

export DEFAULT_PROXY_PORT="4431"
export PROXY_ADDRESS="[::1]:${DEFAULT_PROXY_PORT}"
export PROXY_AUTHORITY="localhost"
export PROXY_CONNECT_PORTS="53,80,443,4433"
export PROXY_CERT="certs/proxy-cert.pem"
export PROXY_KEY="certs/proxy-key.pem"
export TARGET_H3="https://nghttp2.org:4433/"
