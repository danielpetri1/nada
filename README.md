<h1 align="center">
  <img src="docs/assets/nada-header.svg" alt="∅ Nada" width="360" height="200">
</h1>

Nada is a MASQUE network relay that tunnels TCP and UDP over HTTP/3.

## Technology stack

[![DOI](https://zenodo.org/badge/doi/10.1145/3822163.3827938.svg)](https://doi.org/10.1145/3822163.3827938)
[![DOI](https://zenodo.org/badge/doi/10.1145/3822163.3827938.svg)](https://doi.org/10.2313/NET-2026-05-1_10)

Nada is a prototype implementation based on:

- [CONNECT-UDP](https://datatracker.ietf.org/doc/rfc9298/) (RFC 9298)
- [CONNECT](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4) (RFC 9114)
- [HTTP/3 prioritization](https://datatracker.ietf.org/doc/rfc9218/) (RFC 9218)
- [HTTP/3 Extended CONNECT](https://www.rfc-editor.org/rfc/rfc9220.html#section-3) (RFC 9220)
- [HTTP Datagrams and the Capsule Protocol](https://datatracker.ietf.org/doc/rfc9297/) (RFC 9297)

Please cite the paper above if you use Nada in your research.

## Setup

```sh
cp env-examples.sh env.sh

# Edit env.sh to match your deployment
source ./env.sh
bash build.sh
```

`build.sh` (re-)installs `nada` from this checkout after sourcing `env.sh` (or
`env-examples.sh` if absent). The separate `source` above keeps runtime settings
in your current shell.

## Run

Applications can connect to Nada's local TCP or UDP listeners at `[::1]:18018` or `127.0.0.1:18018`.
Using the CLI requires specifying a `--target` to which all flows are sent.

```sh
# List available proxy options:
cargo run --release -- proxy --help

# Open a CONNECT-UDP tunnel:
cargo run --release -- connect-udp --target 1.1.1.1:53

# Tunnel a DNS query through the proxy:
dig @127.0.0.1 -p 18018 example.com +notcp +ignore
dig @::1 -p 18018 example.com +notcp +ignore
```

### Sending modes

Nada uses unreliable transmission by default.
Each endpoint selects its preferred substrate for all CONNECT-UDP tunnels. Both endpoints decode
both incoming formats regardless of their outgoing mode.

| Client       | Proxy        | Client → proxy    | Proxy → client    |
|--------------|--------------|-------------------|-------------------|
| default      | default      | QUIC DATAGRAM     | QUIC DATAGRAM     |
| default      | `--reliable` | QUIC DATAGRAM     | DATAGRAM capsules |
| `--reliable` | default      | DATAGRAM capsules | QUIC DATAGRAM     |
| `--reliable` | `--reliable` | DATAGRAM capsules | DATAGRAM capsules |

Reliability covers the client–proxy segment. CONNECT always carries
HTTP/3 DATA frames reliably and is therefore not affected by `--reliable`.

### Encryption

TLS key exchange prefers hybrid post-quantum `X25519MLKEM768` with classical
fallbacks by default. `TLS_CURVES_LIST` is configurable in `env.sh`.

### Library

Nada's Rust library can also be used to open tunnels directly with `connect_udp` or `connect_tcp`.

The [HTTP/3 GET example](examples/get/main.rs) opens a single client-proxy connection and opens concurrent tunnels with potentially
varying origins, paths, and priorities. Each tunnel carries an independent end-to-end HTTP/3 connection.

Run it from the repository root:

```sh
cargo run --release --example get
```

Scenarios can be specified in [scenarios.txt](examples/get/scenarios.txt), c.f. the [example guide](examples/get/README.md). 

Library callers can use `connect_udp_with_priority(target, urgency, incremental)`
to choose each tunnel's priority.

## Tunnel prioritization

CONNECT and CONNECT-UDP requests use HTTP Priority `u=3,i` by default.

## Experimental features

Multipath support with cooperative scheduling extensions is available [here](https://github.com/danielpetri1/quiche/tree/nada). Artifacts of that
legacy version are available [here](https://syncandshare.lrz.de/getlink/fiRPsUcbRK2SHQ7REDcvwv/anrw.zip).
