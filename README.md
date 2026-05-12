# *Nada*

An implementation of [RFC 9298](https://datatracker.ietf.org/doc/rfc9298/) (Proxying UDP in HTTP) with tokio-quiche.

This project also implements [RFC 9297](https://datatracker.ietf.org/doc/rfc9297/) (HTTP Datagrams and the Capsule Protocol) and supports HTTP/3’s Extensible Prioritization Scheme (EPS) as defined in [RFC 9218](https://datatracker.ietf.org/doc/rfc9218/).

## Build

From the repository root:

```
cargo build --release
```

Please regularly format and lint with `cargo fmt` and `cargo clippy`. `cargo test` runs unit tests.

## Example usage

Run the MASQUE client to open a UDP tunnel to a MASQUE proxy that accesses an endpoint using the inner QUIC connection.
Use `--reliable` on the client to use Datagram Capsules as a substrate. Omit it to directly proxy over QUIC datagrams.

Each `--outer-prio` (or `--op`) flag opens one CONNECT-UDP tunnel with the given EPS priority value.
Specify it multiple times to open several tunnels with different priorities.
Each tunnel can target a different endpoint via `--endpoint` (or `--ep`).
The `--inner-prio` option sets the priority for the inner QUIC connections.

### Starting the MASQUE client:

```
cargo run --release --bin masque-client -- \
  --client-address [fd00:0:0:1::1]:0 \
  --proxy-address [fd00:0:0:3::1]:443 \
  --target-ip fd00:0:0:4::1 \
  --target-port 25565 \
  --results-dir /root/results \
  --log-keys \
  --endpoint /index.html \
  --reliable \
  --outer-prio "u=2,i"
```

Multiple tunnels with different priorities and endpoints:

```
cargo run --release --bin masque-client -- \
  --client-address [fd00:0:0:1::1]:0 \
  --proxy-address [fd00:0:0:3::1]:443 \
  --target-ip fd00:0:0:4::1 \
  --target-port 25565 \
  --reliable \
  --op "u=0,i" --ep /index.html \
  --op "u=3,i" --ep /root.html \
```

### Starting the MASQUE proxy:

```
cargo run --release --bin masque-proxy -- \
  --proxy-address [fd00:0:0:3::1]:443 \
  --results-dir /root/results \
  --log-keys
```

### Server

Running the target server yourself is not strictly necessary, as any reachable HTTP/3 server can be used instead.
For testing, you can use Cloudflare's sample HTTP/3 server:

```bash
RUST_LOG=info QLOGDIR=/root/results cargo run --release --bin quiche-server -- \
--listen [fd00:0:0:4::1]:25565 \
--cert /root/nada/src/bin/certs/cert.crt \
--key /root/nada/src/bin/certs/cert.key \
--root /root/nada/apps/src/bin/root \
--no-retry
```

Several other options are listed under `--help` to, e.g., control the log level, certificate verification, and the storing
of secrets and responses.