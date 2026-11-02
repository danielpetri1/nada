use crate::args::{ConnectPort, ProxyArgs};
use crate::capsules::{dgram_capsule_from_udp_payload, CapsuleDeframer};
use crate::dgrams::{decode_dgram, proxied_dgram};
use crate::helpers::dest_addr_from_masque_uri;
use crate::prios::parse_raw_priority;
use crate::tcp_tunnel::TcpTunnel;
use crate::tunnel::{Substrate, TunnelChannels, TunnelState, MAX_UDP_PAYLOAD};
use crate::{
    write_connection_stats, MAX_OUTER_QUIC_PACKET_SIZE, MAX_STREAMS, SETTINGS_H3_DATAGRAM,
};
use foundations::telemetry::log;
use futures::{SinkExt, StreamExt};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{oneshot, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_quiche::http3::driver::{
    H3Command, H3Event, InboundFrame, IncomingH3Headers, OutboundFrame, OutboundFrameSender,
    ServerH3Event, StreamShutdown,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::QuicCommand;
use tokio_quiche::quiche::h3::{Header, NameValue, WireErrorCode};
use tokio_quiche::settings::{CertificateKind, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{listen, ConnectionParams, ServerH3Controller, ServerH3Driver};

type ProxyResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct TcpTarget {
    socket: TcpStream,
    finished: bool,
}

impl Drop for TcpTarget {
    #[allow(deprecated)]
    fn drop(&mut self) {
        // RFC 9114 §4.4: cancellation or failure aborts the target connection.
        if !self.finished {
            if let Err(error) = self.socket.set_linger(Some(Duration::ZERO)) {
                log::warn!("Could not configure TCP reset on close"; "error" => %error);
            }
        }
    }
}

pub async fn serve(args: ProxyArgs) -> ProxyResult {
    let socket = UdpSocket::bind(args.listen).await?;
    serve_socket(socket, args).await
}

pub(crate) async fn serve_socket(socket: UdpSocket, args: ProxyArgs) -> ProxyResult {
    let address = socket.local_addr()?;
    let mut settings = QuicSettings::default();
    settings.enable_dgram = true;
    settings.enable_pacing = true;
    settings.max_idle_timeout = Some(Duration::ZERO);
    settings.cc_algorithm = args.common.cc_algorithm;
    settings.initial_max_streams_uni = MAX_STREAMS;
    settings.initial_max_streams_bidi = MAX_STREAMS;
    settings.max_send_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;
    settings.max_recv_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;
    if let Some(dir) = &args.common.results_dir {
        if args.common.log_keys {
            settings.keylog_file = Some(format!("{dir}/ssl-proxy.key"));
        }
        if args.common.qlog {
            settings.qlog_dir = Some(dir.clone());
        }
    }
    let mut listeners = listen(
        vec![socket],
        ConnectionParams::new_server(
            settings,
            TlsCertificatePaths {
                cert: &args.cert,
                private_key: &args.key,
                kind: CertificateKind::X509,
            },
            Default::default(),
        ),
        DefaultMetrics,
    )?;
    log::info!("HTTP/3 proxy listening"; "address" => %address);
    let mut connections = JoinSet::new();
    let mut accepted_connections = 0_u64;
    loop {
        tokio::select! {
            conn = listeners[0].next() => {
                let Some(conn) = conn else { break; };
                let mut settings = Http3Settings::default();
                settings.enable_extended_connect = true;
                let (driver, controller) = ServerH3Driver::new(settings);
                let connection = conn?.start(driver);
                accepted_connections += 1;
                let connection_id = format!("{:?}", connection.scid());
                log::info!("Outer HTTP/3 connection accepted"; "connection_id" => %connection_id, "accepted_connections" => accepted_connections);
                let results = args.common.results_dir.clone();
                let substrate = Substrate::from_reliable(args.reliable);
                let connect_ports = args.connect_ports.clone();
                connections.spawn(async move {
                    handle_connection(controller, connection_id, substrate, Duration::from_secs(args.connect_timeout), connect_ports).await;
                    if args.log_stats {
                        if let Some(dir) = results {
                            if let Err(err) = write_connection_stats(&connection, &dir, connection.scid()) {
                                log::warn!("Could not write connection statistics"; "error" => %err);
                            }
                        }
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = result { log::warn!("Connection task failed"; "error" => %err); }
            }
        }
    }
    Ok(())
}

async fn handle_connection(
    mut controller: ServerH3Controller,
    connection_id: String,
    substrate: Substrate,
    connect_timeout: Duration,
    connect_ports: Vec<ConnectPort>,
) {
    let mut datagram_channels = HashMap::new();
    let mut peer_datagrams = false;
    let mut tasks = JoinSet::new();
    let mut running = HashMap::new();
    loop {
        tokio::select! {
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Ok(stream_id) = result { running.remove(&stream_id); }
            }
            event = controller.event_receiver_mut().recv() => {
                let Some(event) = event else { break; };
                match event {
                    ServerH3Event::Core(H3Event::IncomingSettings { settings }) => {
                        peer_datagrams = settings.contains(&(SETTINGS_H3_DATAGRAM, 1));
                    }
                    ServerH3Event::Core(H3Event::NewFlow { flow_id: quarter_stream_id, send, recv }) => { datagram_channels.insert(quarter_stream_id, (send, recv)); }
                    ServerH3Event::Headers { incoming_headers: IncomingH3Headers { stream_id, headers, mut send, recv, read_fin, .. }, .. } => {
                        let value = |name: &[u8]| headers.iter().find(|h| h.name() == name).map(|h| h.value());
                        let datagrams = datagram_channels.remove(&(stream_id / 4));
                        let target = match request_target(&headers, &connect_ports) {
                            Ok(target) => target,
                            Err(status) => { reject(&mut send, status).await; continue; }
                        };
                        if value(b":protocol").is_none() {
                            let priority = parse_raw_priority(value(b"priority").map(|p| p.to_vec()));
                            let commands = controller.h3_cmd_sender();
                            let tunnel_connection_id = connection_id.clone();
                            // A slow TCP handshake must not stall other streams,
                            // including CONNECT-UDP on this same connection.
                            let handle = tasks.spawn(async move {
                                let mut socket = match timeout(connect_timeout, TcpStream::connect(target)).await {
                                    Ok(Ok(socket)) => TcpTarget { socket, finished: false },
                                    result => {
                                        log::warn!("Could not connect to TCP target"; "target" => %target, "stream_id" => stream_id, "error" => ?result);
                                        reject(&mut send, if result.is_err() { b"504" } else { b"502" }).await;
                                        return stream_id;
                                    }
                                };
                                if send.send(OutboundFrame::Headers(vec![Header::new(b":status", b"200")], priority)).await.is_err() {
                                    return stream_id;
                                }
                                let (_state, status) = watch::channel(TunnelState::Open);
                                let mut tunnel = TcpTunnel::new(target, stream_id, send, recv, read_fin, status, move || {
                                    let _ = commands.send(H3Command::ShutdownStream {
                                        stream_id,
                                        shutdown: StreamShutdown::Both { read_error_code: WireErrorCode::ConnectError as u64, write_error_code: WireErrorCode::ConnectError as u64 },
                                    });
                                });
                                log::info!("TCP tunnel established"; "target" => %target, "connection_id" => %tunnel_connection_id, "stream_id" => stream_id);
                                match tokio::io::copy_bidirectional(&mut socket.socket, &mut tunnel).await {
                                    Ok(_) => socket.finished = true,
                                    Err(error) => {
                                        log::warn!("TCP tunnel stopped"; "target" => %target, "connection_id" => %tunnel_connection_id, "stream_id" => stream_id, "error" => %error);
                                    }
                                }
                                stream_id
                            });
                            running.insert(stream_id, (handle, true));
                            continue;
                        }
                        if read_fin { reject(&mut send, b"400").await; continue; }
                        let target_socket = match open_target_socket(target).await {
                            Ok(socket) => socket,
                            Err(err) => { log::warn!("Could not open target UDP socket"; "target" => %target, "error" => %err); reject(&mut send, b"502").await; continue; }
                        };
                        // Validate the configured outgoing mode before accepting CONNECT.
                        let datagram_maximum = if substrate == Substrate::Datagram && peer_datagrams && datagrams.is_some() {
                            let (reply, response) = oneshot::channel();
                            let _ = controller.cmd_sender().send(QuicCommand::Custom(Box::new(move |conn| {
                                let _ = reply.send(conn.dgram_max_writable_len().map(|n| n.saturating_sub(octets::varint_len(stream_id / 4) + 1)));
                            })));
                            match timeout(Duration::from_secs(5), response).await {
                                Ok(Ok(maximum)) => maximum,
                                _ => None,
                            }
                        } else {
                            None
                        };
                        let maximum = match substrate {
                            Substrate::Capsule => MAX_UDP_PAYLOAD,
                            Substrate::Datagram => match datagram_maximum {
                                Some(maximum) if maximum > 0 => maximum.min(MAX_UDP_PAYLOAD),
                                _ => {
                                    log::warn!("Rejecting UDP tunnel: configured DATAGRAM sending is unavailable"; "connection_id" => %connection_id, "stream_id" => stream_id, "target" => %target);
                                    reject(&mut send, b"501").await;
                                    continue;
                                }
                            },
                        };
                        let priority = parse_raw_priority(value(b"priority").map(|p| p.to_vec()));
                        let channels = match TunnelChannels::new(send.clone(), recv, datagrams, substrate) {
                            Ok(channels) => channels,
                            Err(err) => {
                                log::warn!("Could not prepare UDP tunnel channels"; "error" => %err);
                                reject(&mut send, b"501").await;
                                continue;
                            }
                        };
                        if send.send(OutboundFrame::Headers(vec![
                            Header::new(b":status", b"200"),
                            Header::new(b"capsule-protocol", b"?1"),
                        ], priority)).await.is_err() { continue; }
                        log::info!("UDP tunnel established"; "target" => %target, "connection_id" => %connection_id, "stream_id" => stream_id, "sending_mode" => ?substrate, "max_payload" => maximum);
                        if maximum < 1200 {
                            log::warn!("Tunnel cannot carry QUIC's minimum 1200-byte UDP payload"; "target" => %target, "connection_id" => %connection_id, "stream_id" => stream_id, "sending_mode" => ?substrate, "max_payload" => maximum);
                        }
                        let commands = controller.h3_cmd_sender();
                        let tunnel_connection_id = connection_id.clone();
                        let handle = tasks.spawn(async move {
                            if let Err(err) = proxy_tunnel(target_socket, channels, stream_id / 4, substrate, maximum, &tunnel_connection_id).await {
                                log::warn!("UDP tunnel stopped"; "target" => %target, "connection_id" => %tunnel_connection_id, "stream_id" => stream_id, "sending_mode" => ?substrate, "max_payload" => maximum, "error" => %err);
                            }
                            let _ = commands.send(H3Command::ShutdownStream { stream_id, shutdown: StreamShutdown::Both { read_error_code: 0, write_error_code: 0 } });
                            stream_id
                        });
                        running.insert(stream_id, (handle, false));
                    }
                    ServerH3Event::Core(H3Event::ResetStream { stream_id }) => {
                        datagram_channels.remove(&(stream_id / 4));
                        if let Some((handle, _)) = running.remove(&stream_id) { handle.abort(); }
                        controller.shutdown_stream(stream_id, StreamShutdown::Both { read_error_code: WireErrorCode::ConnectError as u64, write_error_code: WireErrorCode::ConnectError as u64 });
                    }
                    ServerH3Event::Core(H3Event::StreamClosed { stream_id }) => {
                        datagram_channels.remove(&(stream_id / 4));
                        // TCP workers must drain queued bytes/FIN to the target.
                        if let Some((handle, tcp)) = running.remove(&stream_id) {
                            if !tcp { handle.abort(); }
                        }
                    }
                    ServerH3Event::Core(H3Event::ConnectionError(_) | H3Event::ConnectionShutdown(_)) => break,
                    _ => (),
                }
            }
        }
    }
}

fn request_target(headers: &[Header], ports: &[ConnectPort]) -> Result<SocketAddr, &'static [u8]> {
    let value = |name: &[u8]| headers.iter().find(|h| h.name() == name).map(|h| h.value());
    if value(b":method") != Some(b"CONNECT") {
        return Err(b"405");
    }
    let target = match value(b":protocol") {
        None => tcp_target(headers),
        Some(b"connect-udp") => value(b":path").and_then(dest_addr_from_masque_uri),
        _ => return Err(b"405"),
    }
    .ok_or(b"400".as_slice())?;
    if !ports.iter().any(|rule| rule.allows(target.port())) {
        return Err(b"403");
    }
    Ok(target)
}

fn tcp_target(headers: &[Header]) -> Option<SocketAddr> {
    if headers
        .iter()
        .any(|h| h.name().starts_with(b":") && !matches!(h.name(), b":method" | b":authority"))
    {
        return None;
    }
    let mut methods = headers.iter().filter(|h| h.name() == b":method");
    if methods.next()?.value() != b"CONNECT" || methods.next().is_some() {
        return None;
    }
    let mut authorities = headers.iter().filter(|h| h.name() == b":authority");
    let target: SocketAddr = std::str::from_utf8(authorities.next()?.value())
        .ok()?
        .parse()
        .ok()?;
    if authorities.next().is_some()
        || target.port() == 0
        || target.ip().is_unspecified()
        || target.ip().is_multicast()
    {
        return None;
    }
    Some(target)
}

async fn reject(send: &mut OutboundFrameSender, status: &[u8]) {
    let _ = send
        .send(OutboundFrame::Headers(
            vec![Header::new(b":status", status)],
            None,
        ))
        .await;
    let _ = send
        .send(OutboundFrame::Body(Default::default(), true))
        .await;
}

async fn open_target_socket(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(target).await?;
    Ok(socket)
}

async fn proxy_tunnel(
    socket: UdpSocket,
    mut channels: TunnelChannels,
    quarter_stream_id: u64,
    substrate: Substrate,
    maximum: usize,
    connection_id: &str,
) -> ProxyResult {
    let target = socket.peer_addr()?;
    let mut buffer = vec![0; 65_536];
    let mut deframer = CapsuleDeframer::new();
    loop {
        let frame = tokio::select! {
            result = socket.recv(&mut buffer) => {
                let len = result?;
                if len > maximum {
                    log::warn!("Dropping oversized target datagram"; "target" => %target, "connection_id" => connection_id, "stream_id" => quarter_stream_id * 4, "sending_mode" => ?substrate, "size" => len, "maximum" => maximum);
                    continue;
                }
                let frame = match substrate {
                    Substrate::Datagram => proxied_dgram(quarter_stream_id, &buffer[..len]),
                    Substrate::Capsule => dgram_capsule_from_udp_payload(&buffer[..len]),
                };
                channels.send.send(frame).await?;
                continue;
            }
            frame = channels.capsules.recv() => frame,
            Some(frame) = async { channels.datagrams.as_mut().expect("guarded datagrams").recv().await }, if channels.datagrams.is_some() => Some(frame),
        };
        let Some(frame) = frame else {
            deframer.finish()?;
            break;
        };
        match frame {
            InboundFrame::Datagram(buffer) => {
                if let Some(payload) = decode_dgram(buffer.as_ref())? {
                    socket.send(payload).await?;
                }
            }
            InboundFrame::Body(buffer, fin) => {
                deframer.feed(&buffer)?;
                while let Some(payload) = deframer.pop_udp_payload() {
                    socket.send(&payload).await?;
                }
                if fin {
                    deframer.finish()?;
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_tunnel_types_apply_the_same_default_and_custom_port_policy() {
        use crate::{
            args::{Cli, Command},
            helpers::connect_udp_path,
        };
        use clap::Parser;

        let Command::Proxy(default) = Cli::try_parse_from([
            "nada",
            "proxy",
            "--cert",
            "unused-cert",
            "--key",
            "unused-key",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        let custom_ports = ["8443".parse::<ConnectPort>().unwrap()];
        for ip in ["192.0.2.1", "2001:db8::1"] {
            for udp in [false, true] {
                for port in [0, 1, 53, 80, 443, 4432, 4433, 25, 123, 8443, 65535] {
                    let target = SocketAddr::new(ip.parse().unwrap(), port);
                    let headers = if udp {
                        vec![
                            Header::new(b":method", b"CONNECT"),
                            Header::new(b":protocol", b"connect-udp"),
                            Header::new(b":path", connect_udp_path(target).as_bytes()),
                        ]
                    } else {
                        vec![
                            Header::new(b":method", b"CONNECT"),
                            Header::new(b":authority", target.to_string().as_bytes()),
                        ]
                    };
                    let expected = if port == 0 {
                        Err(b"400".as_slice())
                    } else if [53, 80, 443, 4433].contains(&port) {
                        Ok(target)
                    } else {
                        Err(b"403".as_slice())
                    };
                    assert_eq!(request_target(&headers, &default.connect_ports), expected);
                    let expected = if port == 0 {
                        Err(b"400".as_slice())
                    } else if port == 8443 {
                        Ok(target)
                    } else {
                        Err(b"403".as_slice())
                    };
                    assert_eq!(request_target(&headers, &custom_ports), expected);
                    assert_eq!(
                        request_target(&headers, &[ConnectPort::All]),
                        if port == 0 {
                            Err(b"400".as_slice())
                        } else {
                            Ok(target)
                        },
                    );
                }
            }
        }
        assert_eq!(
            request_target(&[Header::new(b":method", b"GET")], &[ConnectPort::All]),
            Err(b"405".as_slice())
        );
        assert_eq!(
            request_target(&[Header::new(b":method", b"CONNECT")], &[ConnectPort::All]),
            Err(b"400".as_slice())
        );
    }

    #[test]
    fn connect_authority_requires_an_explicit_valid_port_and_no_scheme_or_path() {
        for target in ["1.1.1.1:53", "[2606:4700:4700::1111]:443"] {
            let headers = vec![
                Header::new(b":method", b"CONNECT"),
                Header::new(b":authority", target.as_bytes()),
            ];
            assert_eq!(tcp_target(&headers), Some(target.parse().unwrap()));
            for name in [
                b":scheme".as_slice(),
                b":path",
                b":protocol",
                b":authority",
                b":method",
                b":status",
            ] {
                let mut invalid = headers.clone();
                invalid.push(Header::new(name, b"invalid"));
                assert!(tcp_target(&invalid).is_none());
            }
        }
        for target in [
            "",
            "1.1.1.1",
            "1.1.1.1:",
            "1.1.1.1:0",
            "1.1.1.1:65536",
            "1.1.1.1:-1",
            "0.0.0.0:53",
            "[::]:53",
            "[ff02::1]:53",
            "https://1.1.1.1:443",
            "user@1.1.1.1:53",
        ] {
            assert!(
                tcp_target(&[
                    Header::new(b":method", b"CONNECT"),
                    Header::new(b":authority", target.as_bytes())
                ])
                .is_none(),
                "{target}"
            );
        }
    }
}
