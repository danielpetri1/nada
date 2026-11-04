#!/usr/bin/env bash

export DEFAULT_RELAY_PORT="4431"
export RELAY_ADDRESS="[::1]:${DEFAULT_RELAY_PORT}"
export RELAY_AUTHORITY="localhost"
export RELAY_CONNECT_PORTS="53,80,443,4433"
export RELAY_CERT="certs/relay-cert.pem"
export RELAY_KEY="certs/relay-key.pem"
export TLS_CURVES_LIST="X25519:P-256:P-384"
