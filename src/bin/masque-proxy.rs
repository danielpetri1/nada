use clap::Parser;
use foundations::telemetry::log;
use futures::{SinkExt as _, StreamExt as _};
use nada::args::ProxyArgs;
use nada::capsules::sfv_bool_from_header;
use nada::capsules::{dgram_capsule_from_udp_payload, CapsuleDeframer};
use nada::dgrams::{proxied_dgram, retrieve_dgram};
use nada::helpers::{dest_addr_from_masque_uri, flow_id_from_stream_id, sfv_bool};
use nada::prios::parse_raw_priority;
use nada::{
    create_results_dir, logging, write_connection_stats, MAX_OUTER_QUIC_PACKET_SIZE, MAX_STREAMS,
};
use nada::{MasqueTunnels, Tunnel};
use tokio::net::UdpSocket;
use tokio::task;
use tokio_quiche::http3::driver::InboundFrame::{Body, Datagram};
use tokio_quiche::http3::driver::{
    H3Event, InboundFrameStream, IncomingH3Headers, OutboundFrame, OutboundFrameSender,
    ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quiche::h3::{Header, NameValue, Priority};
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::{ConnectionParams, ServerH3Controller, ServerH3Driver};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ProxyArgs::parse();
    logging::init(args.common.log_level.into());

    create_results_dir(&args.common.results_dir);

    let bind_addresses = vec![args.common.proxy_address.clone()];

    let mut sockets = Vec::new();
    for addr in &bind_addresses {
        let socket = UdpSocket::bind(addr).await?;
        sockets.push(socket);
    }

    let mut quic_settings = QuicSettings::default();
    quic_settings.enable_pacing = true;

    if args.common.log_keys {
        if let Some(ref results_dir) = args.common.results_dir {
            quic_settings.keylog_file = Some(format!("{}/ssl-proxy.key", results_dir));
        }
    }

    if args.common.qlog {
        quic_settings.qlog_dir = args.common.results_dir.clone();
    }

    quic_settings.cc_algorithm = args.common.cc_algorithm;
    quic_settings.initial_max_streams_uni = MAX_STREAMS;
    quic_settings.initial_max_streams_bidi = MAX_STREAMS;
    quic_settings.max_send_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;
    quic_settings.max_recv_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;

    let mut listeners = listen(
        sockets,
        ConnectionParams::new_server(
            quic_settings,
            tokio_quiche::settings::TlsCertificatePaths {
                cert: &args.cert,
                private_key: &args.key,
                kind: tokio_quiche::settings::CertificateKind::X509,
            },
            Default::default(),
        ),
        DefaultMetrics,
    )?;

    let accept_stream = &mut listeners[0];

    let log_stats = args.log_stats;
    let results_dir = args.common.results_dir.clone();

    while let Some(conn) = accept_stream.next().await {
        let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
        let connection = conn?.start(driver);

        let results_dir = results_dir.clone();
        tokio::spawn(async move {
            handle_connection(controller).await;

            if log_stats {
                if let Some(ref results_dir) = results_dir {
                    let conn_id = connection.scid();
                    if let Err(e) = write_connection_stats(&connection, results_dir, conn_id) {
                        log::error!("Failed to write connection stats"; "error" => ?e);
                    }
                } else {
                    log::warn!("--log-stats requires --results-dir to be set");
                }
            }
        });
    }

    Ok(())
}

/// Handle an accepted MASQUE connection.
async fn handle_connection(mut controller: ServerH3Controller) {
    let mut masque_tunnels = MasqueTunnels::new();

    while let Some(event) = controller.event_receiver_mut().recv().await {
        match event {
            ServerH3Event::Headers {
                incoming_headers:
                    IncomingH3Headers {
                        recv,
                        mut send,
                        headers,
                        stream_id,
                        ..
                    },
                ..
            } => {
                log::info!("incoming headers"; "headers" => ?headers);

                let mut method = None;
                let mut protocol = None;
                let mut path = None;
                let mut capsule_protocol = None;
                let mut priority = None;

                for request_header in headers {
                    let name = request_header.name();

                    match name {
                        b":method" => {
                            method = Some(request_header);
                        }

                        b":path" => path = Some(request_header),

                        b":protocol" => protocol = Some(request_header),

                        b"capsule-protocol" => {
                            capsule_protocol = Some(request_header.value().to_vec());
                        }

                        b"priority" => {
                            priority = Some(request_header.value().to_vec());
                        }

                        _ => (),
                    }
                }

                let reliable_masque =
                    sfv_bool_from_header(capsule_protocol) == sfv_bool(true).as_bytes();

                // Parse the H3 priority (u= / i) for the response stream.
                let h3_priority = parse_raw_priority(priority.clone());

                match (method, path, protocol) {
                    (Some(m), Some(target), Some(p))
                        if m.value() == b"CONNECT" && p.value() == b"connect-udp" =>
                    {
                        if let Some((ip, port)) = dest_addr_from_masque_uri(target.value()) {
                            log::info!("Handling MASQUE proxying request"; "ip" => &ip, "port" => &port);

                            let proxy = UdpSocket::bind("[::]:0")
                                .await
                                .expect("Failed binding upstream UDP socket");
                            let target_addr = format!("[{}]:{}", ip, port);
                            proxy
                                .connect(&target_addr)
                                .await
                                .expect("Failed to set the socket's destination");

                            if reliable_masque {
                                log::info!("Using the Capsule Protocol for this tunnel");

                                indicate_successful_response(
                                    &mut send,
                                    reliable_masque,
                                    h3_priority,
                                )
                                .await;
                                forward_capsules(proxy, send, recv);
                            } else {
                                let flow_id = flow_id_from_stream_id(stream_id);

                                indicate_successful_response(
                                    &mut send,
                                    reliable_masque,
                                    h3_priority,
                                )
                                .await;

                                let t = masque_tunnels
                                    .masque_map
                                    .get_mut(&flow_id)
                                    .expect("Failed to get MASQUE tunnel");

                                if let (Some(dgram_send), Some(dgram_recv)) =
                                    (t.send.take(), t.recv.take())
                                {
                                    forward_dgrams(proxy, dgram_send, dgram_recv, flow_id);
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!("Invalid combination of :method, :path, and :protocol");
                    }
                }
            }
            ServerH3Event::Core(H3Event::NewFlow {
                flow_id,
                send,
                recv,
            }) => {
                log::info!("HTTP/3 DATAGRAM flow created"; "flow_id" => flow_id);
                masque_tunnels
                    .masque_map
                    .insert(flow_id, Tunnel::new(send, recv));
            }

            ServerH3Event::Core(H3Event::BodyBytesReceived {
                stream_id,
                num_bytes,
                fin,
            }) => {
                log::trace!(
                    "Received {} DATA bytes on stream {} (fin={})",
                    num_bytes,
                    stream_id,
                    fin
                );
            }

            ServerH3Event::Core(event) => {
                log::debug!("event: {event:?}");
            }
        }
    }
}

async fn indicate_successful_response(
    send: &mut OutboundFrameSender,
    reliable_masque: bool,
    priority: Option<Priority>,
) {
    send.send(OutboundFrame::Headers(
        vec![
            Header::new(b":status", b"200"),
            Header::new(b"capsule-protocol", sfv_bool(reliable_masque).as_bytes()),
        ],
        priority,
    ))
    .await
    .expect("Failed to send 200 OK");
}

/// Forwards (proxied) datagrams in both directions.
fn forward_dgrams(
    proxy: UdpSocket,
    mut t_send: OutboundFrameSender,
    mut t_recv: InboundFrameStream,
    flow_id: u64,
) {
    task::spawn(async move {
        let mut ingress = [0; tokio_quiche::datagram_socket::MAX_DATAGRAM_SIZE];

        loop {
            tokio::select! {
                outer_datagram = t_recv.recv() => {
                    match outer_datagram {
                        Some(datagram) => {
                            if let Datagram(mut dg) = datagram {
                                log::trace!("Received DATAGRAM"; "flow_id" => flow_id);

                                if let Err(e) = proxy.send(retrieve_dgram(dg.as_mut())).await {
                                    log::info!("Failed sending UDP datagram to the target: {}", e);
                                    break;
                                }
                            }
                        }

                        None => {
                            log::info!("Closed tunnel to the proxy"; "flow_id" => flow_id);
                            break;
                        }
                    }
                }

                target_to_proxy = proxy.recv(&mut ingress) => {
                    match target_to_proxy {
                        Ok(written) => {
                            log::trace!("Received UDP datagram from the target server"; "size" => written);
                            if t_send.send(proxied_dgram(flow_id, &ingress[..written])).await.is_err() {
                                log::warn!("Closed tunnel to the client");
                                break;
                            }
                        }

                        Err(e) => {
                            log::info!("Error receiving from the target server: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });
}

/// Forwards UDP datagrams using Datagram Capsules.
fn forward_capsules(
    proxy: UdpSocket,
    mut h3_send: OutboundFrameSender,
    mut h3_recv: InboundFrameStream,
) {
    task::spawn(async move {
        let mut ingress = [0; tokio_quiche::datagram_socket::MAX_DATAGRAM_SIZE];
        let mut capsule_deframer = CapsuleDeframer::new();

        loop {
            tokio::select! {
                frame = h3_recv.recv() => {
                    match frame {
                        Some(Body(buf, fin)) => {
                            // Feed the new data into the deframer
                            capsule_deframer.feed(&buf);

                            // Process all complete UDP payloads
                            while let Some(udp_payload) = capsule_deframer.pop_udp_payload() {
                                if let Err(e) = proxy.send(&udp_payload).await {
                                    log::info!("Failed sending UDP datagram to the target (capsule): {}", e);
                                    break;
                                }
                            }

                            if fin {
                                log::info!("Capsule stream finished by client");
                                break;
                            }
                        }

                        Some(Datagram(_)) => {
                            log::warn!("Received QUIC Datagram on capsule tunnel!");
                            break;
                        }

                        None => {
                            log::info!("Closed capsule tunnel to the proxy");
                            break;
                        }
                    }
                }

                target_to_proxy = proxy.recv(&mut ingress) => {
                    match target_to_proxy {
                        Ok(written) => {
                            log::trace!("Received UDP datagram from the target server"; "size" => written);

                            let frame = dgram_capsule_from_udp_payload(&ingress[..written]);

                            if h3_send.send(frame).await.is_err() {
                                log::warn!("Closed capsule tunnel to the client");
                                break;
                            }
                        }

                        Err(e) => {
                            log::info!("Error receiving from the target server: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });
}
