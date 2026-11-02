# UDP forwarding and library access

- Keep documentation concise. Explain each behavior once in the most relevant
  guide. Link to it elsewhere when needed. Avoid repeated explanations and
  unnecessary detail. Keep README updates limited to essential information
  for users.
- Prefer separate sentences in documentation prose and code comments. Use
  semicolons when they make sense and read naturally.
- Make visual assets respect light and dark mode. Prefer theme-aware SVGs and
  provide light and dark raster variants when needed.
- Use Rust for application code and Bash for scripts and script tests.
- Keep network testing manual with direct commands the user can follow. Do not
  add production test harnesses, test runners or demo orchestration scripts.
- Use an externally built curl with HTTP/3 support for HTTP/3 testing. Do not add
  application or benchmark clients to Nada's source or dependencies.
- Use `cargo run --release --` for Nada and `cargo run --release --example get`
  for the GET example. Do not install commands or add launcher scripts. Keep
  `--locked` for CI and reproducible checks, rather than routine run commands.
- `cargo run --release -- connect-udp --target IP:port` forwards UDP to one fixed
  remote target per process. Default listeners are `[::1]:18018` and
  `127.0.0.1:18018`. Explicit repeatable `--listen` overrides replace both
  defaults; never infer listener families from the outer proxy or silently
  fall back between them.
- Applications send directly to the Nada listener, for example with
  `dig @127.0.0.1 -p 18018`. Reply from that same listener. Library callers use
  `MasqueClient` to choose a destination per tunnel without a local listener.
- Listener sockets, outer proxy connections, and remote targets have independent
  address families. Application sockets match the local listener's family.
- One client owns one outer HTTP/3 connection and a shared flow table keyed by
  source and local listener. Preserve bounded pending queues, global flow limits,
  independent expiry, cancellation, and shutdown on outer failure.
- Each process's `--reliable` configures its own outgoing mode for all tunnels.
  Decode both incoming encodings without changing that mode. Local CONNECT
  requests use uniform `u=3,i` priority.
- Keep the UDP forwarder, transport and proxy portable. Do not reintroduce
  transparent interception, raw sockets, privileged routing, nftables or
  namespace setup. The local forwarder runs as an ordinary user.
- Network tests use the local computer (Linux or macOS) as the client and the
  running production proxy/real origins. Do not add localhost network tests,
  local proxy fixtures, or isolated proxy namespaces. Pure tests without network
  I/O may remain. Production checks are manual and must not run automatically
  in CI.
- Copy `env-examples.sh` to the ignored `env.sh` for local configuration.
  `build.sh` sources `env.sh` when present, otherwise `env-examples.sh`.
  Source either file to replace its configured environment values in the current
  Bash shell. CLI options override environment values, which override the
  built-in defaults.
- Keep examples and tests consistent with dual-stack
  local listeners and the independent `[::1]:4431` outer default. Applications either
  use the library or send to the listener with ordinary UDP sockets. No local
  control protocol is needed.
- Use `TARGET_H3`, defaulting to `https://nghttp2.org:4433/`, for manual HTTP/3
  GET checks. Use port 4432 for illustrative origins and 4431 for illustrative
  proxies. `DEFAULT_PROXY_PORT` supplies the proxy port in environment files.
  Configure TLS paths through `PROXY_CERT` and `PROXY_KEY` in the environment files.
