use clap::Parser;
use foundations::telemetry::log;
use nada::args::ClientArgs;
use nada::capsules::sfv_bool_from_header;
use nada::create_results_dir;
use nada::write_connection_stats;
use nada::e2e::{quic_client, E2eClientConfig};
use nada::helpers::{flow_id_from_stream_id, sfv_bool};
use nada::logging;
use nada::MAX_STREAMS;
use nada::{MasqueTunnels, Tunnel};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task;
use tokio_quiche::http3::driver::H3Event::NewFlow;
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Event, InboundFrame, IncomingH3Headers, OutboundFrameSender,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::quiche::h3;
use tokio_quiche::quiche::h3::NameValue;
use tokio_quiche::{ClientH3Driver, ConnectionParams};
use tokio_quiche::socket::Socket;
use nada::MAX_OUTER_QUIC_PACKET_SIZE;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = ClientArgs::parse();
    logging::init(args.common.log_level.clone().into());

    create_results_dir(&args.common.results_dir);

    let proxy_addr: SocketAddr = args
        .common
        .proxy_address
        .parse()
        .expect("Invalid proxy address");

    let udp_socket = UdpSocket::bind(&args.client_address).await?;
    udp_socket.connect(&proxy_addr).await?;
    let socket= Socket::<UdpSocket, UdpSocket>::from_udp(udp_socket)?;

    let (h3_driver, mut controller) =
        ClientH3Driver::new(Http3Settings::default());

    let mut params = ConnectionParams::default();
    params.settings.enable_dgram = true;
    params.settings.enable_pacing = true;

    let idle_timeout_secs = args.idle_timeout_secs;

    if args.common.log_keys {
        if let Some(ref results_dir) = args.common.results_dir {
            params.settings.keylog_file =
                Some(format!("{}/ssl-client.key", results_dir));
        }
    }

    if args.common.qlog {
        params.settings.qlog_dir = args.common.results_dir.clone();
    }

    params.settings.max_idle_timeout =
        Some(Duration::from_secs(idle_timeout_secs));
    params.settings.cc_algorithm = args.common.cc_algorithm.clone();
    params.settings.initial_max_streams_uni = MAX_STREAMS;
    params.settings.initial_max_streams_bidi = MAX_STREAMS;
    params.settings.max_send_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;
    params.settings.max_recv_udp_payload_size = MAX_OUTER_QUIC_PACKET_SIZE;

    let path = format!(
        "/.well-known/masque/udp/{}/{}",
        &args.target_ip, &args.target_port
    );

    let reliable_masque = args.reliable;
    let endpoints = args.endpoint.clone();
    let e2e_cfg = E2eClientConfig::from(&args);

    let connection =
        connect_with_config(socket, None, &params, h3_driver).await?;

    // QUIC Datagrams available, perform MASQUE in DATAGRAM mode.
    let mut masque_tunnels = MasqueTunnels::new();

    for (req_id, prio) in args.outer_prios.iter().enumerate() {
        let (tx, _rx) = oneshot::channel::<OutboundFrameSender>();
        controller
            .request_sender()
            .send(tokio_quiche::http3::driver::NewClientRequest {
                request_id: req_id as u64,
                headers: vec![
                    h3::Header::new(b":method", b"CONNECT"),
                    h3::Header::new(b":protocol", b"connect-udp"),
                    h3::Header::new(
                        b":authority",
                        args.proxy_authority.as_bytes(),
                    ),
                    h3::Header::new(b":scheme", b"https"),
                    h3::Header::new(b":path", path.as_bytes()),
                    h3::Header::new(
                        b"capsule-protocol",
                        sfv_bool(reliable_masque).as_bytes(),
                    ),
                    h3::Header::new(b"priority", prio.as_bytes()),
                ],
                body_writer: Some(tx),
            })
            .expect("Failed sending NewClientRequest");
    }

    while let Some(event) = controller.event_receiver_mut().recv().await {
        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(
                IncomingH3Headers {
                    stream_id,
                    headers,
                    mut recv,
                    send,
                    ..
                },
            )) => {
                log::info!("incoming headers"; "stream_id" => stream_id, "headers" => ?headers);

                let mut status = None;
                let mut capsule_protocol = None;

                // Parse some of the request headers.
                for request_header in headers {
                    let name = request_header.name();

                    match name {
                        b":status" => {
                            status = Some(request_header);
                        }
                        b"capsule-protocol" => {
                            capsule_protocol =
                                Some(request_header.value().to_vec());
                        }
                        _ => (),
                    }
                }

                if let Some(s) = status {
                    if s.value() == b"200" {
                        let use_capsules = sfv_bool_from_header(capsule_protocol)
                            == sfv_bool(true).as_bytes();
                        let flow_id = flow_id_from_stream_id(stream_id);

                        // Pick the endpoint for this tunnel (fall back to
                        // the last one if fewer endpoints than tunnels).
                        let mut e2e_cfg = e2e_cfg.clone();
                        if let Some(ep) = endpoints.get(flow_id as usize) {
                            e2e_cfg.endpoint = ep.clone();
                        }

                        if use_capsules {
                            log::info!(
                                "MASQUE proxying request successful; using the Capsule Protocol"
                            );

                            task::spawn(async move {
                                if let Err(e) = quic_client(
                                    send, recv, e2e_cfg, flow_id, true,
                                )
                                .await
                                {
                                    log::error!(
                                        "Inner QUIC client failed (capsule protocol)";
                                        "error" => ?e
                                    );
                                }
                            });
                        } else {
                            log::info!("MASQUE proxying request successful");

                            let t = masque_tunnels
                                .masque_map
                                .get_mut(&flow_id)
                                .expect("Failed to get MASQUE tunnel");

                            if let (Some(send), Some(recv)) =
                                (t.send.take(), t.recv.take())
                            {
                                task::spawn(async move {
                                    if let Err(e) = quic_client(
                                        send, recv, e2e_cfg, flow_id, false,
                                    )
                                    .await
                                    {
                                        log::error!(
                                            "Inner QUIC client failed (datagram)";
                                            "flow_id" => flow_id,
                                            "error" => ?e
                                        );
                                    }
                                });
                            }

                            task::spawn(async move {
                                'recv_loop: while let Some(frame) =
                                    recv.recv().await
                                {
                                    match frame {
                                        InboundFrame::Body(pooled, fin) => {
                                            log::trace!(
                                                "inbound body: {:?}", std::str::from_utf8(&pooled);
                                                "fin" => fin,
                                                "len" => pooled.len()
                                            );
                                            if fin {
                                                log::info!(
                                                    "received full body, exiting"
                                                );
                                                break 'recv_loop;
                                            }
                                        }
                                        InboundFrame::Datagram(pooled) => {
                                            log::trace!("inbound datagram"; "len" => pooled.len());
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }

            ClientH3Event::Core(NewFlow {
                flow_id,
                send,
                recv,
            }) => {
                log::info!("HTTP/3 DATAGRAM flow created"; "flow_id" => flow_id);
                masque_tunnels
                    .masque_map
                    .insert(flow_id, Tunnel::new(send, recv));
            }

            ClientH3Event::Core(H3Event::BodyBytesReceived {
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

            ClientH3Event::Core(event) => {
                log::debug!("received event: {event:?}")
            }

            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id,
            } => log::info!(
                "sending outbound request";
                "stream_id" => stream_id,
                "request_id" => request_id
            ),
        }
    }

    // Connection closed
    if args.log_stats {
        if let Some(ref results_dir) = args.common.results_dir {
            let conn_id = connection.scid();
            if let Err(e) =
                write_connection_stats(&connection, results_dir, conn_id)
            {
                log::error!("Failed to write connection stats"; "error" => ?e);
            }
        } else {
            log::warn!("--log-stats requires --results-dir to be set");
        }
    }

    Ok(())
}

