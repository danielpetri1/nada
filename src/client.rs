use crate::args::ConnectionArgs;
use crate::helpers::connect_udp_path;
use crate::tcp_tunnel::TcpTunnel;
use crate::tunnel::{
    Substrate, TunnelChannels, TunnelError, TunnelState, UdpTunnel, MAX_UDP_PAYLOAD,
};
use crate::{
    write_connection_stats, MAX_OUTER_QUIC_PACKET_SIZE, MAX_STREAMS, SETTINGS_H3_DATAGRAM,
};
use boring::ssl::{SslContextBuilder, SslMethod};
use foundations::telemetry::log;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, watch},
    time::{interval, timeout},
};
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Command, H3Event, InboundFrameStream, IncomingH3Headers, NewClientRequest,
    OutboundFrameSender, StreamShutdown,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::{connect_with_config, ConnectionHook, QuicCommand};
use tokio_quiche::quiche::h3::{Header, NameValue, WireErrorCode};
use tokio_quiche::settings::{CertificateKind, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::{ClientH3Controller, ClientH3Driver, ConnectionParams};

/// Default CONNECT/CONNECT-UDP priority
pub const DEFAULT_STREAM_PRIORITY: &str = "u=3,i";

struct ProxyTrust(Mutex<Option<SslContextBuilder>>);
impl ConnectionHook for ProxyTrust {
    fn create_custom_ssl_context_builder(
        &self,
        _: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        self.0.lock().ok()?.take()
    }
}

struct OpenRequest {
    target: SocketAddr,
    priority: String,
    kind: TunnelKind,
    reply: oneshot::Sender<Result<OpenedTunnel, TunnelError>>,
}

#[derive(Clone, Copy)]
enum TunnelKind {
    Tcp,
    Udp,
}

enum OpenedTunnel {
    Tcp(TcpTunnel),
    Udp(UdpTunnel),
}

impl OpenRequest {
    fn headers(&self, proxy_authority: &str) -> Vec<Header> {
        let mut headers = vec![Header::new(b":method", b"CONNECT")];
        match self.kind {
            TunnelKind::Tcp => headers.push(Header::new(
                b":authority",
                self.target.to_string().as_bytes(),
            )),
            TunnelKind::Udp => headers.extend([
                Header::new(b":protocol", b"connect-udp"),
                Header::new(b":authority", proxy_authority.as_bytes()),
                Header::new(b":scheme", b"https"),
                Header::new(b":path", connect_udp_path(self.target).as_bytes()),
                Header::new(b"capsule-protocol", b"?1"),
            ]),
        }
        headers.push(Header::new(b"priority", self.priority.as_bytes()));
        headers
    }
}

/// One outer HTTP/3 connection to a proxy. TCP CONNECT and CONNECT-UDP tunnels
/// may coexist. Each request uses its own independent HTTP/3 stream.
#[derive(Clone)]
pub struct MasqueClient {
    requests: mpsc::Sender<OpenRequest>,
    connection_id: Arc<str>,
    substrate: Substrate,
    state: watch::Receiver<TunnelState>,
    shutdown: watch::Sender<bool>,
    request_timeout: Duration,
}

impl MasqueClient {
    /// Establish the outer QUIC connection and its HTTP/3 session with the proxy.
    pub async fn connect(args: &ConnectionArgs) -> Result<Self, TunnelError> {
        let proxy = args.proxy_address;
        let local = args.client_address.unwrap_or_else(|| {
            if proxy.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap()
        });
        if local.is_ipv4() != proxy.is_ipv4() {
            return Err(TunnelError::Connection(
                "client and proxy addresses must use the same IP family".into(),
            ));
        }
        let udp = UdpSocket::bind(local).await.map_err(connection_error)?;
        udp.connect(proxy).await.map_err(connection_error)?;
        let socket = Socket::<UdpSocket, UdpSocket>::from_udp(udp).map_err(connection_error)?;
        let (driver, controller) = ClientH3Driver::new(Http3Settings::default());
        let mut params = ConnectionParams::default();
        params.settings.verify_peer = true;
        params.settings.enable_dgram = true;
        params.settings.enable_pacing = true;
        params.settings.max_idle_timeout = Some(Duration::from_secs(args.idle_timeout_secs));
        params.settings.handshake_timeout = Some(Duration::from_secs(args.connect_timeout));
        params.settings.cc_algorithm = args.common.cc_algorithm.clone();
        params.settings.initial_max_streams_uni = MAX_STREAMS;
        params.settings.initial_max_streams_bidi = MAX_STREAMS;
        params.settings.max_send_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;
        params.settings.max_recv_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;
        if let Some(dir) = &args.common.results_dir {
            if args.common.log_keys {
                params.settings.keylog_file = Some(format!("{dir}/ssl-client.key"));
            }
            if args.common.qlog {
                params.settings.qlog_dir = Some(dir.clone());
            }
        }
        let ca = args
            .proxy_ca
            .as_ref()
            .map(|p| {
                p.to_str()
                    .ok_or_else(|| connection_error("CA path is not UTF-8"))
            })
            .transpose()?;
        if let Some(ca) = ca {
            let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(connection_error)?;
            builder.set_ca_file(ca).map_err(connection_error)?;
            params.hooks.connection_hook = Some(Arc::new(ProxyTrust(Mutex::new(Some(builder)))));
            params.tls_cert = Some(TlsCertificatePaths {
                cert: ca,
                private_key: "",
                kind: CertificateKind::X509,
            });
        }
        let request_timeout = Duration::from_secs(args.connect_timeout);
        let connection = timeout(
            request_timeout,
            connect_with_config(socket, Some(&args.proxy_authority), &params, driver),
        )
        .await
        .map_err(|_| TunnelError::Timeout)?
        .map_err(connection_error)?;
        let (requests, receiver) = mpsc::channel(64);
        let (state, status) = watch::channel(TunnelState::Open);
        let (shutdown, stop) = watch::channel(false);
        let authority = args.proxy_authority.clone();
        let log_stats = args.log_stats;
        let results_dir = args.common.results_dir.clone();
        let connection_id: Arc<str> = format!("{:?}", connection.scid()).into();
        let substrate = Substrate::from_reliable(args.reliable);
        log::info!("Outer proxy connection established"; "connection_id" => %connection_id, "sending_mode" => ?substrate);
        tokio::spawn(async move {
            let result = run_connection(controller, receiver, authority, stop, substrate).await;
            if log_stats {
                if let Some(dir) = results_dir {
                    if let Err(err) = write_connection_stats(&connection, &dir, connection.scid()) {
                        log::warn!("Failed to write connection statistics"; "error" => %err);
                    }
                }
            }
            state.send_replace(TunnelState::Failed(result));
        });
        Ok(Self {
            connection_id,
            substrate,
            requests,
            state: status,
            shutdown,
            request_timeout,
        })
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Outgoing CONNECT-UDP encoding. TCP tunnels always use reliable DATA frames.
    pub fn sending_mode(&self) -> Substrate {
        self.substrate
    }

    /// Open one independent tunnel using this client's configured sending mode.
    /// Incoming payloads may use either supported encoding.
    pub async fn connect_udp(&self, target: SocketAddr) -> Result<UdpTunnel, TunnelError> {
        self.open_udp(target, DEFAULT_STREAM_PRIORITY.into()).await
    }

    /// Open a TCP byte stream with `u=3,i` priority on this shared connection.
    pub async fn connect_tcp(&self, target: SocketAddr) -> Result<TcpTunnel, TunnelError> {
        self.open_tcp(target, DEFAULT_STREAM_PRIORITY.into()).await
    }

    /// Open a TCP byte stream with an explicit outer HTTP Priority.
    pub async fn connect_tcp_with_priority(
        &self,
        target: SocketAddr,
        urgency: u8,
        incremental: bool,
    ) -> Result<TcpTunnel, TunnelError> {
        self.open_tcp(target, priority(urgency, incremental)?).await
    }

    async fn open_tcp(
        &self,
        target: SocketAddr,
        priority: String,
    ) -> Result<TcpTunnel, TunnelError> {
        match self.open(target, priority, TunnelKind::Tcp).await? {
            OpenedTunnel::Tcp(tunnel) => Ok(tunnel),
            OpenedTunnel::Udp(_) => unreachable!("TCP request produced UDP tunnel"),
        }
    }

    /// Open a CONNECT-UDP tunnel with an explicit HTTP Priority.
    pub async fn connect_udp_with_priority(
        &self,
        target: SocketAddr,
        urgency: u8,
        incremental: bool,
    ) -> Result<UdpTunnel, TunnelError> {
        self.open_udp(target, priority(urgency, incremental)?).await
    }

    async fn open_udp(
        &self,
        target: SocketAddr,
        priority: String,
    ) -> Result<UdpTunnel, TunnelError> {
        match self.open(target, priority, TunnelKind::Udp).await? {
            OpenedTunnel::Udp(tunnel) => Ok(tunnel),
            OpenedTunnel::Tcp(_) => unreachable!("UDP request produced TCP tunnel"),
        }
    }

    async fn open(
        &self,
        target: SocketAddr,
        priority: String,
        kind: TunnelKind,
    ) -> Result<OpenedTunnel, TunnelError> {
        if target.port() == 0 || target.ip().is_unspecified() || target.ip().is_multicast() {
            return Err(TunnelError::Protocol(
                "target must be a unicast IP address with a nonzero port".into(),
            ));
        }
        let (reply, response) = oneshot::channel();
        timeout(self.request_timeout, async {
            self.requests
                .send(OpenRequest {
                    target,
                    priority,
                    kind,
                    reply,
                })
                .await
                .map_err(|_| self.failure())?;
            response.await.map_err(|_| self.failure())?
        })
        .await
        .map_err(|_| TunnelError::Timeout)?
    }

    /// Resolves when the shared proxy connection stops. Can be cancelled.
    pub async fn closed(&self) -> TunnelError {
        let mut state = self.state.clone();
        while matches!(*state.borrow(), TunnelState::Open) {
            if state.changed().await.is_err() {
                break;
            }
        }
        self.failure()
    }

    /// Close this connection and all its tunnels, including those opened by
    /// clones. Waits for transport cleanup and any requested statistics output.
    pub async fn shutdown(&self) {
        self.shutdown.send_replace(true);
        self.closed().await;
    }

    fn failure(&self) -> TunnelError {
        match &*self.state.borrow() {
            TunnelState::Failed(err) => err.clone(),
            _ => TunnelError::Closed,
        }
    }
}

fn priority(urgency: u8, incremental: bool) -> Result<String, TunnelError> {
    if urgency > 7 {
        return Err(TunnelError::Protocol(
            "priority urgency must be 0..=7".into(),
        ));
    }
    Ok(format!("u={urgency},i=?{}", u8::from(incremental)))
}

fn connection_error(err: impl std::fmt::Display) -> TunnelError {
    TunnelError::Connection(err.to_string())
}

async fn run_connection(
    mut controller: ClientH3Controller,
    mut requests: mpsc::Receiver<OpenRequest>,
    authority: String,
    mut shutdown: watch::Receiver<bool>,
    substrate: Substrate,
) -> TunnelError {
    let mut next_id = 0;
    let mut pending = HashMap::<u64, OpenRequest>::new();
    let mut streams = HashMap::<u64, OpenRequest>::new();
    let mut datagram_channels = HashMap::<u64, (OutboundFrameSender, InboundFrameStream)>::new();
    let mut states = HashMap::<u64, watch::Sender<TunnelState>>::new();
    let mut peer_datagrams = false;
    let mut cleanup = interval(Duration::from_secs(1));
    let error = loop {
        tokio::select! {
            _ = shutdown.changed() => break TunnelError::Closed,
            request = requests.recv() => {
                let Some(request) = request else { break TunnelError::Closed; };
                if request.reply.is_closed() { continue; }
                let id = next_id;
                next_id += 1;
                let (body, _unused) = oneshot::channel();
                let result = controller.request_sender().send(NewClientRequest {
                    request_id: id,
                    headers: request.headers(&authority), body_writer: Some(body),
                });
                if result.is_err() { break TunnelError::Closed; }
                pending.insert(id, request);
            }
            _ = cleanup.tick() => {
                pending.retain(|_, request| !request.reply.is_closed());
                states.retain(|_, state| state.receiver_count() != 0);
                streams.retain(|id, request| {
                    if request.reply.is_closed() {
                        close_stream(&controller, *id);
                        datagram_channels.remove(&(id / 4));
                        false
                    } else { true }
                });
            }
            event = controller.event_receiver_mut().recv() => {
                let Some(event) = event else { break TunnelError::Closed; };
                match event {
                    ClientH3Event::Core(H3Event::IncomingSettings { settings }) => {
                        peer_datagrams = settings.contains(&(SETTINGS_H3_DATAGRAM, 1));
                    }
                    ClientH3Event::NewOutboundRequest { stream_id, request_id } => {
                        if let Some(request) = pending.remove(&request_id) {
                            if request.reply.is_closed() { close_stream(&controller, stream_id); }
                            else { streams.insert(stream_id, request); }
                        } else { close_stream(&controller, stream_id); }
                    }
                    ClientH3Event::Core(H3Event::NewFlow { flow_id: quarter_stream_id, send, recv }) => { datagram_channels.insert(quarter_stream_id, (send, recv)); }
                    ClientH3Event::Core(H3Event::IncomingHeaders(headers)) => {
                        let stream_id = headers.stream_id;
                        if let Some(request) = streams.remove(&stream_id) {
                            let result = establish_tunnel(&controller, headers, &request, datagram_channels.remove(&(stream_id / 4)), peer_datagrams, substrate).await;
                            match result {
                                Ok((tunnel, state)) => {
                                    states.insert(stream_id, state);
                                    let _ = request.reply.send(Ok(tunnel));
                                }
                                Err(err) => {
                                    let _ = request.reply.send(Err(err));
                                    close_stream(&controller, stream_id);
                                }
                            }
                        } else { close_stream(&controller, stream_id); }
                    }
                    ClientH3Event::Core(H3Event::ResetStream { stream_id }) => {
                        let err = TunnelError::Protocol("peer reset the CONNECT stream".into());
                        if let Some(request) = streams.remove(&stream_id) { let _ = request.reply.send(Err(err.clone())); }
                        if let Some(state) = states.remove(&stream_id) { state.send_replace(TunnelState::Failed(err)); }
                        datagram_channels.remove(&(stream_id / 4));
                    }
                    ClientH3Event::Core(H3Event::StreamClosed { stream_id }) => {
                        if let Some(request) = streams.remove(&stream_id) { let _ = request.reply.send(Err(TunnelError::Closed)); }
                        states.remove(&stream_id);
                        datagram_channels.remove(&(stream_id / 4));
                    }
                    ClientH3Event::Core(H3Event::ConnectionError(err)) => break connection_error(err),
                    ClientH3Event::Core(H3Event::ConnectionShutdown(err)) => break connection_error(format!("connection shut down: {err:?}")),
                    _ => (),
                }
            }
        }
    };
    for (_, request) in pending.into_iter().chain(streams) {
        let _ = request.reply.send(Err(error.clone()));
    }
    for (_, state) in states {
        state.send_replace(TunnelState::Failed(error.clone()));
    }
    let _ = controller
        .cmd_sender()
        .send(QuicCommand::Custom(Box::new(|connection| {
            let _ = connection.close(true, 0, b"client stopped");
        })));
    let _ = timeout(Duration::from_secs(5), async {
        while controller.event_receiver_mut().recv().await.is_some() {}
    })
    .await;
    error
}

fn close_stream(controller: &ClientH3Controller, stream_id: u64) {
    controller.shutdown_stream(
        stream_id,
        StreamShutdown::Both {
            read_error_code: WireErrorCode::RequestCancelled as u64,
            write_error_code: WireErrorCode::RequestCancelled as u64,
        },
    );
}

async fn establish_tunnel(
    controller: &ClientH3Controller,
    headers: IncomingH3Headers,
    request: &OpenRequest,
    datagrams: Option<(OutboundFrameSender, InboundFrameStream)>,
    peer_datagrams: bool,
    substrate: Substrate,
) -> Result<(OpenedTunnel, watch::Sender<TunnelState>), TunnelError> {
    let status = headers
        .headers
        .iter()
        .find(|h| h.name() == b":status")
        .and_then(|h| std::str::from_utf8(h.value()).ok())
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| TunnelError::Protocol("missing HTTP status".into()))?;
    if !(200..300).contains(&status) {
        return Err(TunnelError::Rejected(status));
    }
    let stream_id = headers.stream_id;
    if matches!(request.kind, TunnelKind::Tcp) {
        let (state, status) = watch::channel(TunnelState::Open);
        let commands = controller.h3_cmd_sender();
        let tunnel = TcpTunnel::new(
            request.target,
            stream_id,
            headers.send,
            headers.recv,
            headers.read_fin,
            status,
            move || {
                let _ = commands.send(H3Command::ShutdownStream {
                    stream_id,
                    shutdown: StreamShutdown::Both {
                        read_error_code: WireErrorCode::RequestCancelled as u64,
                        write_error_code: WireErrorCode::RequestCancelled as u64,
                    },
                });
            },
        );
        return Ok((OpenedTunnel::Tcp(tunnel), state));
    }
    if headers.read_fin {
        return Err(TunnelError::Protocol(
            "CONNECT response closed the stream".into(),
        ));
    }
    // CONNECT-UDP defines capsule framing even when the optional header is absent
    // or false. It does not negotiate either endpoint's outgoing substrate.
    let maximum = match substrate {
        Substrate::Capsule => MAX_UDP_PAYLOAD,
        Substrate::Datagram => {
            if !peer_datagrams {
                return Err(TunnelError::Protocol(
                    "peer did not enable HTTP/3 Datagrams".into(),
                ));
            }
            let (reply, result) = oneshot::channel();
            controller
                .cmd_sender()
                .send(QuicCommand::Custom(Box::new(move |connection| {
                    let maximum = connection
                        .dgram_max_writable_len()
                        .map(|n| n.saturating_sub(octets::varint_len(stream_id / 4) + 1));
                    let _ = reply.send(maximum);
                })))
                .map_err(|_| TunnelError::Closed)?;
            let maximum = timeout(Duration::from_secs(5), result)
                .await
                .map_err(|_| TunnelError::Timeout)?
                .map_err(|_| TunnelError::Closed)?
                .filter(|maximum| *maximum > 0)
                .ok_or_else(|| {
                    TunnelError::Protocol("peer does not support QUIC DATAGRAM".into())
                })?;
            maximum.min(MAX_UDP_PAYLOAD)
        }
    };
    let channels = TunnelChannels::new(headers.send, headers.recv, datagrams, substrate)?;
    let (state, _) = watch::channel(TunnelState::Open);
    Ok((
        OpenedTunnel::Udp(UdpTunnel::new(
            request.target,
            stream_id,
            substrate,
            maximum,
            channels,
            controller.h3_cmd_sender(),
            state.clone(),
        )),
        state,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_quiche::http3::{
        driver::{InboundFrame, OutboundFrame},
        H3AuditStats,
    };

    fn response(
        stream_id: u64,
        status: &[u8],
    ) -> (
        IncomingH3Headers,
        mpsc::Sender<InboundFrame>,
        mpsc::Receiver<OutboundFrame>,
    ) {
        let (send, outgoing) = mpsc::channel(8);
        let (incoming, recv) = mpsc::channel(8);
        (
            IncomingH3Headers {
                stream_id,
                headers: vec![Header::new(b":status", status)],
                send: OutboundFrameSender::new(send),
                recv,
                read_fin: false,
                h3_audit_stats: Arc::new(H3AuditStats::new(stream_id)),
            },
            incoming,
            outgoing,
        )
    }

    fn request(kind: TunnelKind, target: &str) -> OpenRequest {
        OpenRequest {
            kind,
            target: target.parse().unwrap(),
            priority: DEFAULT_STREAM_PRIORITY.into(),
            reply: oneshot::channel().0,
        }
    }

    #[test]
    fn connect_uses_target_authority_and_no_extended_connect_fields() {
        for target in ["1.1.1.1:53", "[2606:4700:4700::1111]:53"] {
            let tcp = request(TunnelKind::Tcp, target).headers("proxy.example");
            assert_eq!(tcp.len(), 3);
            assert_eq!(tcp[0], Header::new(b":method", b"CONNECT"));
            assert_eq!(tcp[1], Header::new(b":authority", target.as_bytes()));
            assert_eq!(tcp[2], Header::new(b"priority", b"u=3,i"));
            let udp = request(TunnelKind::Udp, target).headers("proxy.example");
            assert!(udp.contains(&Header::new(b":protocol", b"connect-udp")));
            assert!(udp.contains(&Header::new(b":authority", b"proxy.example")));
            assert!(udp.contains(&Header::new(
                b":path",
                connect_udp_path(target.parse().unwrap()).as_bytes()
            )));
        }
    }

    #[tokio::test]
    async fn tcp_accepts_all_successes_ignores_content_length_and_needs_no_datagrams() {
        let (_driver, controller) = ClientH3Driver::new(Http3Settings::default());
        for substrate in [Substrate::Datagram, Substrate::Capsule] {
            for status in [b"200", b"204", b"299"] {
                let (mut headers, _incoming, mut outgoing) = response(0, status);
                headers.headers.extend([
                    Header::new(b"content-length", b"0"),
                    Header::new(b"transfer-encoding", b"chunked"),
                ]);
                headers.read_fin = true;
                let (OpenedTunnel::Tcp(mut tunnel), _state) = establish_tunnel(
                    &controller,
                    headers,
                    &request(TunnelKind::Tcp, "1.1.1.1:53"),
                    None,
                    false,
                    substrate,
                )
                .await
                .unwrap() else {
                    panic!()
                };
                assert_eq!(tunnel.read(&mut [0]).await.unwrap(), 0);
                tunnel.write_all(b"raw bytes").await.unwrap();
                assert!(
                    matches!(outgoing.recv().await.unwrap(), OutboundFrame::Body(bytes, false) if bytes.as_ref() == b"raw bytes")
                );
            }
        }
        for status in [b"400", b"403", b"502"] {
            let (headers, _, _) = response(0, status);
            assert!(matches!(
                establish_tunnel(
                    &controller,
                    headers,
                    &request(TunnelKind::Tcp, "1.1.1.1:53"),
                    None,
                    false,
                    Substrate::Datagram
                )
                .await,
                Err(TunnelError::Rejected(_))
            ));
        }
    }

    #[tokio::test]
    async fn one_client_dispatches_tcp_and_udp_to_independent_streams() {
        let (_driver, controller) = ClientH3Driver::new(Http3Settings::default());
        let (requests, mut pending) = mpsc::channel::<OpenRequest>(8);
        let (_state, state) = watch::channel(TunnelState::Open);
        let client = MasqueClient {
            requests,
            state,
            substrate: Substrate::Capsule,
            connection_id: "shared".into(),
            shutdown: watch::channel(false).0,
            request_timeout: Duration::from_secs(1),
        };
        let dispatch = async {
            let mut peers = Vec::new();
            for id in [0, 4] {
                let request = pending.recv().await.unwrap();
                let (headers, incoming, outgoing) = response(id, b"200");
                let (tunnel, state) = establish_tunnel(
                    &controller,
                    headers,
                    &request,
                    None,
                    false,
                    client.sending_mode(),
                )
                .await
                .unwrap();
                peers.push((request.kind, incoming, outgoing, state));
                assert!(request.reply.send(Ok(tunnel)).is_ok());
            }
            peers
        };
        let (tcp, udp, peers) = tokio::join!(
            client.connect_tcp("1.1.1.1:53".parse().unwrap()),
            client.connect_udp("[2606:4700:4700::1111]:53".parse().unwrap()),
            dispatch
        );
        let mut tcp = tcp.unwrap();
        let udp = udp.unwrap();
        assert_ne!(tcp.stream_id(), udp.stream_id());
        let (udp_send, mut udp_recv) = udp.split();
        tcp.write_all(b"tcp").await.unwrap();
        udp_send.send(b"udp").await.unwrap();
        for (kind, incoming, mut outgoing, _state) in peers {
            let OutboundFrame::Body(bytes, false) = outgoing.recv().await.unwrap() else {
                panic!()
            };
            match kind {
                TunnelKind::Tcp => assert_eq!(bytes.as_ref(), b"tcp"),
                TunnelKind::Udp => {
                    let mut capsules = crate::capsules::CapsuleDeframer::new();
                    capsules.feed(&bytes).unwrap();
                    assert_eq!(capsules.pop_udp_payload().unwrap(), b"udp");
                }
            }
            incoming
                .send(InboundFrame::Body(bytes.into(), false))
                .await
                .unwrap();
            match kind {
                TunnelKind::Tcp => {
                    let mut bytes = [0; 3];
                    tcp.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"tcp");
                }
                TunnelKind::Udp => assert_eq!(udp_recv.recv().await.unwrap().unwrap(), b"udp"),
            }
        }
    }
}
