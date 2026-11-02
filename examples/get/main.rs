use clap::Parser;
use futures::future::try_join_all;
use nada::{args::ConnectionArgs, client::MasqueClient, logging, tunnel::DatagramSender};
use sfv::{Dictionary, FieldType, ListEntry};
use std::{
    collections::HashSet, fs::File, io::Write, net::SocketAddr, path::PathBuf, time::Duration,
};
use tokio::time::{sleep_until, timeout};
use tokio_quiche::quiche::{self, h3, h3::NameValue};
use url::{Host, Position, Url};

type Error = Box<dyn std::error::Error + Send + Sync>;
const INNER_PACKET_SIZE: usize = 1200;
const DEFAULT_TARGET_H3: &str = "https://nghttp2.org:4433/";

#[derive(Parser)]
#[command(
    about = "Fetch files using independent HTTP/3 connections over one Nada proxy connection",
    after_help = "All GETs send QUIC DATAGRAMs by default. Pass --reliable to send DATAGRAM capsules for every GET on the client-proxy connection."
)]
struct Options {
    #[command(flatten)]
    connection: ConnectionArgs,

    /// Repeat for concurrent GETs. URL supplies the HTTPS origin and request path.
    #[arg(long = "get", num_args = 3, value_names = ["URL", "PRIORITY", "OUTPUT"], action = clap::ArgAction::Append)]
    gets: Vec<String>,

    /// Scenario file (default: examples/get/scenarios.txt).
    #[arg(long, value_name = "FILE", conflicts_with = "gets")]
    scenarios: Option<PathBuf>,

    /// HTTPS URL substituted for ${TARGET_H3} in the scenario file.
    #[arg(long, env = "TARGET_H3", default_value = DEFAULT_TARGET_H3)]
    target_h3: String,

    /// Overall deadline in seconds for each GET, including its tunnel and inner TLS handshake.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    request_timeout: u64,
}

#[derive(Debug)]
struct Get {
    priority: String,
    urgency: u8,
    incremental: bool,
    server_name: String,
    port: u16,
    authority: String,
    path: String,
    output: PathBuf,
}

impl Get {
    fn parse(fields: &[String]) -> Result<Self, Error> {
        let [url, priority, output] = fields else {
            return Err("each GET needs URL PRIORITY OUTPUT".into());
        };
        let dict = Dictionary::parse(sfv::Parser::new(priority.as_bytes()))?;
        let urgency = match dict.get("u") {
            None => 3,
            Some(ListEntry::Item(item)) => {
                item.bare_item
                    .as_integer()
                    .map(i64::from)
                    .filter(|u| (0..=7).contains(u))
                    .ok_or("priority u must be an integer from 0 to 7")? as u8
            }
            _ => return Err("priority u must be an integer from 0 to 7".into()),
        };
        let incremental = match dict.get("i") {
            None => false,
            Some(ListEntry::Item(item)) => item
                .bare_item
                .as_boolean()
                .ok_or("priority i must be a boolean")?,
            _ => return Err("priority i must be a boolean".into()),
        };
        if url.bytes().any(|b| b <= 0x20 || b >= 0x7f) || url.contains('\\') {
            return Err("URL must be ASCII; percent-encode spaces and non-ASCII characters".into());
        }
        let url = Url::parse(url)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err("URL must use HTTPS without credentials or a fragment".into());
        }
        let host = url.host().ok_or("URL must include an origin host")?;
        match host {
            Host::Ipv4(ip) if ip.is_unspecified() || ip.is_multicast() => {
                return Err("URL must use a unicast origin address".into());
            }
            Host::Ipv6(ip) if ip.is_unspecified() || ip.is_multicast() => {
                return Err("URL must use a unicast origin address".into());
            }
            _ => (),
        }
        let port = url
            .port_or_known_default()
            .ok_or("URL must include a port")?;
        if port == 0 {
            return Err("URL must use a nonzero port".into());
        }
        let path = url[Position::BeforePath..Position::AfterQuery].to_owned();
        if output.is_empty() {
            return Err("OUTPUT must be a file path".into());
        }
        Ok(Self {
            priority: priority.clone(),
            urgency,
            incremental,
            server_name: match host {
                Host::Domain(name) => name.to_owned(),
                Host::Ipv4(ip) => ip.to_string(),
                Host::Ipv6(ip) => ip.to_string(),
            },
            port,
            authority: url[Position::BeforeHost..Position::AfterPort].to_owned(),
            path,
            output: output.into(),
        })
    }
}

fn requests(fields: &[String]) -> Result<Vec<Get>, Error> {
    let gets = fields
        .chunks(3)
        .map(Get::parse)
        .collect::<Result<Vec<_>, _>>()?;
    validate_requests(gets)
}

fn scenario_requests(contents: &str, target_h3: &str) -> Result<Vec<Get>, Error> {
    let mut gets = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields: Vec<String> = line.split_whitespace().map(String::from).collect();
        if fields.len() != 3 {
            return Err(format!("line {}: each GET needs URL PRIORITY OUTPUT", index + 1).into());
        }
        fields[0] = fields[0].replace("${TARGET_H3}", target_h3);
        gets.push(Get::parse(&fields).map_err(|error| format!("line {}: {error}", index + 1))?);
    }
    validate_requests(gets)
}

fn validate_requests(gets: Vec<Get>) -> Result<Vec<Get>, Error> {
    if gets.is_empty() {
        return Err("at least one GET is required".into());
    }
    if gets.len() > nada::MAX_STREAMS as usize {
        return Err(format!(
            "at most {} concurrent GETs are supported",
            nada::MAX_STREAMS
        )
        .into());
    }
    let mut outputs = HashSet::new();
    for get in &gets {
        if !outputs.insert(&get.output) {
            return Err(format!(
                "GETs must use distinct output files: {}",
                get.output.display()
            )
            .into());
        }
    }
    Ok(gets)
}

fn load_requests(options: &Options) -> Result<Vec<Get>, Error> {
    if !options.gets.is_empty() {
        return requests(&options.gets);
    }
    let default = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/get/scenarios.txt");
    let path = options.scenarios.as_ref().unwrap_or(&default);
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read scenarios {}: {error}", path.display()))?;
    scenario_requests(&contents, &options.target_h3)
        .map_err(|error| format!("{}: {error}", path.display()).into())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options = Options::parse();
    let gets = load_requests(&options)?;
    logging::init(options.connection.common.log_level.clone().into());
    nada::create_results_dir(&options.connection.common.results_dir);
    let client = MasqueClient::connect(&options.connection).await?;
    eprintln!(
        "Outer QUIC connection: {}, sending mode: {:?} (all GETs)",
        client.connection_id(),
        client.sending_mode(),
    );
    let result = tokio::select! {
        result = try_join_all(gets.iter().map(|get| async {
            timeout(Duration::from_secs(options.request_timeout), fetch(&client, get, &options))
                .await
                .map_err(|_| -> Error { format!("GET {} timed out", get.path).into() })?
        })) => result.map(|_| ()),
        error = client.closed() => Err(error.into()),
        result = tokio::signal::ctrl_c() => result.map_err(Error::from),
    };
    client.shutdown().await;
    result
}

async fn fetch(client: &MasqueClient, get: &Get, options: &Options) -> Result<(), Error> {
    let target = tokio::net::lookup_host((get.server_name.as_str(), get.port))
        .await?
        .next()
        .ok_or_else(|| format!("no address found for {}", get.server_name))?;
    if target.ip().is_unspecified() || target.ip().is_multicast() {
        return Err(format!("origin resolved to a non-unicast address: {target}").into());
    }
    let tunnel = client
        .connect_udp_with_priority(target, get.urgency, get.incremental)
        .await?;
    if tunnel.max_payload_size() < INNER_PACKET_SIZE {
        return Err("tunnel payload limit is smaller than QUIC's 1200-byte minimum".into());
    }
    let local: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_cc_algorithm_name(&options.connection.common.cc_algorithm)?;
    config.enable_pacing(true);
    config.verify_peer(true);
    config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(options.request_timeout.saturating_mul(1000));
    config.set_max_send_udp_payload_size(INNER_PACKET_SIZE);
    config.set_max_recv_udp_payload_size(INNER_PACKET_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_uni(10);
    config.set_disable_active_migration(true);
    let mut id = [0; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut id)?;
    let mut connection = quiche::connect(
        Some(&get.server_name),
        &quiche::ConnectionId::from_ref(&id),
        local,
        target,
        &mut config,
    )?;
    eprintln!(
        "outer={} tunnel={} inner={:?} priority={} GET https://{}{} target={} -> {}",
        client.connection_id(),
        tunnel.stream_id(),
        connection.source_id(),
        get.priority,
        get.authority,
        get.path,
        target,
        get.output.display(),
    );
    let headers = [
        h3::Header::new(b":method", b"GET"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", get.authority.as_bytes()),
        h3::Header::new(b":path", get.path.as_bytes()),
        h3::Header::new(b"priority", get.priority.as_bytes()),
    ];
    let (sender, mut receiver) = tunnel.split();
    let mut http = None;
    let mut request_stream = None;
    let mut status = None;
    let mut bytes = 0;
    let mut file = None;
    let mut body = [0; 16_384];
    let mut packet = [0; INNER_PACKET_SIZE];
    loop {
        if connection.is_closed() {
            return Err(format!(
                "inner QUIC closed before GET completed: {:?}",
                connection.peer_error()
            )
            .into());
        }
        if connection.is_established() && http.is_none() {
            http = Some(h3::Connection::with_transport(
                &mut connection,
                &h3::Config::new()?,
            )?);
        }
        if let Some(http) = &mut http {
            if request_stream.is_none() {
                match http.send_request(&mut connection, &headers, true) {
                    Ok(id) => request_stream = Some(id),
                    Err(
                        h3::Error::StreamBlocked
                        | h3::Error::TransportError(quiche::Error::StreamLimit),
                    ) => (),
                    Err(error) => return Err(error.into()),
                }
            }
            loop {
                let (stream, event) = match http.poll(&mut connection) {
                    Ok(event) => event,
                    Err(h3::Error::Done) => break,
                    Err(error) => return Err(error.into()),
                };
                if Some(stream) != request_stream {
                    continue;
                }
                match event {
                    h3::Event::Headers { list, .. } => {
                        if let Some(value) = list.iter().find(|h| h.name() == b":status") {
                            let code: u16 = std::str::from_utf8(value.value())?.parse()?;
                            if code >= 200 {
                                if !(200..300).contains(&code) {
                                    return Err(
                                        format!("GET {} returned HTTP {code}", get.path).into()
                                    );
                                }
                                status = Some(code);
                                if let Some(parent) =
                                    get.output.parent().filter(|p| !p.as_os_str().is_empty())
                                {
                                    std::fs::create_dir_all(parent)?;
                                }
                                file = Some(File::create(&get.output)?);
                            }
                        }
                    }
                    h3::Event::Data => loop {
                        match http.recv_body(&mut connection, stream, &mut body) {
                            Ok(0) | Err(h3::Error::Done) => break,
                            Ok(n) => {
                                file.as_mut()
                                    .ok_or("response body preceded final status")?
                                    .write_all(&body[..n])?;
                                bytes += n;
                            }
                            Err(error) => return Err(error.into()),
                        }
                    },
                    h3::Event::Finished => {
                        let status =
                            status.ok_or("response finished without a final HTTP status")?;
                        file.as_mut().ok_or("missing output file")?.flush()?;
                        connection.close(true, 0x100, b"GET complete")?;
                        flush_packets(&mut connection, &sender, &mut packet).await?;
                        eprintln!(
                            "Saved {}: HTTP {status}, {bytes} bytes",
                            get.output.display()
                        );
                        return Ok(());
                    }
                    h3::Event::Reset(code) => {
                        return Err(format!("GET stream reset: {code}").into())
                    }
                    _ => (),
                }
            }
        }
        flush_packets(&mut connection, &sender, &mut packet).await?;
        // Honour QUIC loss-recovery timers even when the tunnel has no replies.
        // Cancellation of recv is safe; an outer failure also ends this request.
        match timeout(
            connection.timeout().unwrap_or(Duration::from_secs(1)),
            receiver.recv(),
        )
        .await
        {
            Ok(Ok(Some(mut payload))) => {
                match connection.recv(
                    &mut payload,
                    quiche::RecvInfo {
                        from: target,
                        to: local,
                    },
                ) {
                    Ok(_) | Err(quiche::Error::Done) => (),
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(Ok(None)) => return Err("UDP tunnel closed before GET completed".into()),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => connection.on_timeout(),
        }
    }
}

async fn flush_packets(
    connection: &mut quiche::Connection,
    sender: &DatagramSender,
    packet: &mut [u8],
) -> Result<(), Error> {
    loop {
        match connection.send(packet) {
            Ok((n, info)) => {
                // Honour inner QUIC pacing before handing the packet to the tunnel.
                if info.at > std::time::Instant::now() {
                    sleep_until(info.at.into()).await;
                }
                sender.send(&packet[..n]).await?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(priority: &str, url: &str, output: &str) -> Vec<String> {
        [url, priority, output].map(String::from).to_vec()
    }

    #[test]
    fn reliable_selects_the_shared_mode_for_all_gets() {
        use nada::tunnel::Substrate;

        for reliable in [false, true] {
            for requests in [
                vec![],
                vec!["--scenarios", "benchmark.txt"],
                vec![
                    "--get",
                    "https://origin.example.org:4432/high",
                    "u=0,i",
                    "high.html",
                    "--get",
                    "https://origin.example.org:4432/low",
                    "u=7,i",
                    "low.html",
                ],
            ] {
                let mut args = vec!["get"];
                args.extend(requests);
                if reliable {
                    args.push("--reliable");
                }
                let options = Options::try_parse_from(args).unwrap();
                assert_eq!(options.connection.reliable, reliable);
                assert_eq!(
                    Substrate::from_reliable(options.connection.reliable),
                    if reliable {
                        Substrate::Capsule
                    } else {
                        Substrate::Datagram
                    },
                );
            }
        }
    }

    #[test]
    fn repeated_gets_preserve_independent_scenarios() {
        let options = Options::try_parse_from([
            "get",
            "--get",
            "https://[2001:db8::1]:4432/index.html",
            "u=0,i",
            "high.html",
            "--get",
            "https://example.org/other.txt?size=2",
            "u=7,i=?0",
            "low.txt",
        ])
        .unwrap();
        let gets = load_requests(&options).unwrap();
        assert_eq!(gets.len(), 2);
        assert_eq!((gets[0].urgency, gets[0].incremental), (0, true));
        assert_eq!(gets[0].server_name, "2001:db8::1");
        assert_eq!(gets[0].authority, "[2001:db8::1]:4432");
        assert_eq!(gets[0].port, 4432);
        assert_eq!((gets[1].urgency, gets[1].incremental), (7, false));
        assert_eq!(gets[1].port, 443);
        assert_eq!(gets[1].server_name, "example.org");
        assert_eq!(gets[1].path, "/other.txt?size=2");
        assert_eq!(gets[1].output, PathBuf::from("low.txt"));
        // Target families never select the outer proxy's address family.
        assert!(options.connection.proxy_address.is_ipv6());
    }

    #[test]
    fn scenario_files_preserve_requests_and_expand_origin() {
        let gets = scenario_requests(
            "# URL PRIORITY OUTPUT\n\n\
             ${TARGET_H3} u=0,i  high.html\n\
             https://example.org/other.txt?size=2 u=7,i=?0  low.txt\n",
            "https://origin.example.org:4432/?size=2",
        )
        .unwrap();
        assert_eq!(gets.len(), 2);
        assert_eq!((gets[0].urgency, gets[0].incremental), (0, true));
        assert_eq!(gets[0].server_name, "origin.example.org");
        assert_eq!(gets[0].port, 4432);
        assert_eq!(gets[0].path, "/?size=2");
        assert_eq!((gets[1].urgency, gets[1].incremental), (7, false));
        assert_eq!(gets[1].server_name, "example.org");
        assert_eq!(gets[1].path, "/other.txt?size=2");
        assert_eq!(gets[1].output, PathBuf::from("low.txt"));
    }

    #[test]
    fn scenario_files_reject_empty_invalid_duplicate_and_excessive_requests() {
        assert!(scenario_requests("\n # no requests\n", DEFAULT_TARGET_H3).is_err());
        for row in [
            "${TARGET_H3} u=3,i",
            "${TARGET_H3} u=8 out",
            "bad-target u=3,i out",
            "${TARGET_H3} u=3,i out extra",
            "u=3,i ${TARGET_H3} out",
        ] {
            let error =
                scenario_requests(&format!("# comment\n\n{row}\n"), DEFAULT_TARGET_H3).unwrap_err();
            assert!(error.to_string().starts_with("line 3:"), "{error}");
        }
        let row = "${TARGET_H3} u=3,i same.html\n";
        let error = scenario_requests(&row.repeat(2), DEFAULT_TARGET_H3).unwrap_err();
        assert!(error.to_string().contains("distinct output files"));

        let rows: String = (0..=nada::MAX_STREAMS)
            .map(|n| format!("${{TARGET_H3}} u=3,i out{n}.html\n"))
            .collect();
        let error = scenario_requests(&rows, DEFAULT_TARGET_H3).unwrap_err();
        assert!(error.to_string().contains("concurrent GETs"));
    }

    #[test]
    fn scenario_file_option_conflicts_with_inline_gets() {
        let options = Options::try_parse_from(["get", "--scenarios", "benchmark.txt"]).unwrap();
        assert_eq!(options.scenarios, Some(PathBuf::from("benchmark.txt")));
        assert!(Options::try_parse_from([
            "get",
            "--scenarios",
            "benchmark.txt",
            "--get",
            DEFAULT_TARGET_H3,
            "u=3,i",
            "out.html",
        ])
        .is_err());
    }

    #[test]
    fn rejects_invalid_scenarios_before_connecting() {
        for priority in ["u=8", "u=-1", "u=\"3\"", "i=5", "u=3,broken=="] {
            assert!(Get::parse(&fields(priority, DEFAULT_TARGET_H3, "out")).is_err());
        }
        for url in [
            "https://0.0.0.0:443/",
            "https://[::]:443/",
            "https://224.0.0.1/",
            "https://[ff02::1]/",
            "https://nghttp2.org:0/",
            "origin.example.org:4432",
            "http://nghttp2.org/",
            "https://user:password@nghttp2.org/",
            "https://nghttp2.org/a b",
            "https://nghttp2.org/a\r\nheader",
            "https://nghttp2.org/#fragment",
            "https://nghttp2.org/\\path",
        ] {
            assert!(Get::parse(&fields("u=3,i", url, "out")).is_err(), "{url}");
        }
        let mut values = fields("u=0,i", DEFAULT_TARGET_H3, "same.html");
        values.extend(fields("u=7,i", "https://[2001:db8::1]:4432/", "same.html"));
        assert!(requests(&values).is_err());
        assert!(requests(&values[..2]).is_err());
    }

    #[test]
    fn target_url_override_is_expanded_without_network_io() {
        for target in [DEFAULT_TARGET_H3, "https://example.org:4432/file?size=2"] {
            let options = Options::try_parse_from(["get", "--target-h3", target]).unwrap();
            let gets =
                scenario_requests("${TARGET_H3} u=3,i results/index.html", &options.target_h3)
                    .unwrap();
            assert_eq!(gets.len(), 1);
            assert_eq!(
                format!("https://{}{}", gets[0].authority, gets[0].path),
                target
            );
        }
    }
}
