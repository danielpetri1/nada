# Tunneling end-to-end HTTP/3 connections with Nada 

This example uses the `MasqueClient` to establish independent HTTP/3 connections, each of which GETs the
[HTTP/3-only ngtcp2 interop server](https://github.com/ngtcp2/ngtcp2/wiki/ngtcp2-public-server-for-IETF-quicwg-interop). Every GET uses a QUIC DATAGRAM substrate by default. Add `--reliable` to send
DATAGRAM capsules for all GETs on the shared outer client-proxy connection. The proxy's mode is configured separately.
Inner and outer client connections and the proxy default to BBRv2 (`bbr2_gcongestion`).

## Local testing

Run the proxy and GET example on the same host, in separate terminals from the repository root.
In the first terminal, load the environment, generate the certificate, and start the proxy:

```sh
source ./env.sh
bash certs/generate.sh
cargo run --release -- proxy
```

The certificate uses `PROXY_AUTHORITY`, defaulting to `localhost`. The default`PROXY_CERT` and `PROXY_KEY` paths point
to the generated files.

In the second terminal, run the GET example explicitly trusting that certificate for the outer connection:

```sh
source ./env.sh
cargo run --release --example get -- --proxy-ca certs/proxy-cert.pem
```

Without `--proxy-ca`, the client uses system trust roots.

## Scenarios

Edit [scenarios.txt](scenarios.txt) to define concurrent GETs.

```text
# URL PRIORITY OUTPUT
https://nghttp2.org:4433/ u=0,i results/high.html
https://nghttp2.org:4433/ u=7,i results/low.html
```

Blank lines and those starting with `#` are ignored. Other scenario files can be chosen with:

```sh
cargo run --release --example get -- --scenarios path/to/benchmark.txt
```

Alternatively, repeat `--get URL PRIORITY OUTPUT` to replace the scenario file's GETs.

```sh
cargo run --release --example get -- \
  --get https://nghttp2.org:4433/ 'u=0,i' results/high.html \
  --get https://nghttp2.org:4433/ 'u=7,i' results/low.html
```

`PRIORITY` uses HTTP Priority syntax: urgency `u=0` is highest and `u=7` lowest.
`i` (or `i=?1`) enables incremental delivery, and `i=?0` disables it. If omitted
from a priority field, urgency defaults to 3 and incremental defaults to false.
The priority is sent on both the outer CONNECT-UDP request and the inner GET.
