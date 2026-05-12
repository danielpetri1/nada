use crate::args::ClientArgs;
use crate::capsules::{dgram_capsule_from_udp_payload, CapsuleDeframer};
use crate::dgrams::{proxied_dgram, retrieve_dgram};
use crate::MAX_STREAMS;
use foundations::telemetry::log;
use futures::SinkExt;
use octets::Octets;
use quiche::h3::{Event, NameValue};
use quiche::{h3, Connection, ConnectionId, Error};
use serde_json::json;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::task;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::{
    InboundFrame, InboundFrameStream, OutboundFrameSender,
};
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::ConnectionIdGenerator;
const CONNECTION_LEVEL_BUFFER_SIZE: u64 = 10_000_000;
const STREAM_LEVEL_BUFFER_SIZE: u64 = 1_000_000;
const MAX_E2E_QUIC_PACKET_SIZE: usize = 1280; // Kühlewind et al. (2021), Section 4.1
const DGRAM_BUFFER_SIZE: usize = 65_536; // tokio-quiche default for sending/receiving DATAGRAM frames

#[derive(Clone)]
pub struct E2eClientConfig {
    pub client_address: String,
    pub target_ip: String,
    pub target_port: String,
    pub server_name: String,
    pub endpoint: String,
    pub inner_prio: String,
    pub ca: String,
    pub no_verify: bool,
    pub cc_algorithm: String,
    pub results_dir: Option<String>,
    pub log_keys: bool,
    pub qlog: bool,
    pub log_stats: bool,
    pub keep_resp: bool,
}

impl From<&ClientArgs> for E2eClientConfig {
    fn from(args: &ClientArgs) -> Self {
        Self {
            client_address: args.client_address.clone(),
            target_ip: args.target_ip.clone(),
            target_port: args.target_port.clone(),
            server_name: args.server_name.clone(),
            endpoint: args.endpoint.first().cloned().unwrap_or_default(),
            inner_prio: args.inner_prio.clone(),
            ca: args.ca.clone(),
            no_verify: args.no_verify,
            cc_algorithm: args.common.cc_algorithm.clone(),
            results_dir: args.common.results_dir.clone(),
            log_keys: args.common.log_keys,
            qlog: args.common.qlog,
            log_stats: args.log_stats,
            keep_resp: args.keep_resp,
        }
    }
}

/// Logging-related HTTP/3 parameters.
struct LoggingContext {
    results_dir: Option<String>,
    request_start_time: Option<Instant>,
    log_stats: bool,
    keep_resp: bool,
    resp_map: HashMap<u64, File>,
    dgram_map: HashMap<u64, File>,
    bytes_received: HashMap<u64, u64>,
}

fn ensure_log_file(
    map: &mut HashMap<u64, File>,
    id: u64,
    file_path: String,
    label: &str,
) {
    if let Entry::Vacant(e) = map.entry(id) {
        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file_path)
        {
            Ok(file) => {
                e.insert(file);
                log::info!("Writing {} {} data to {}", label, id, file_path);
            }
            Err(e) => {
                log::warn!("Failed to open file {}: {}", file_path, e);
            }
        }
    }
}

fn write_chunk(file: &mut File, chunk: &[u8]) {
    if let Err(e) = file.write_all(chunk) {
        log::warn!("Failed to write to file: {}", e);
    }
}

fn drain_h3_datagrams(
    conn: &mut Connection,
    logging_ctx: &mut LoggingContext,
    flow_id: u64,
) {
    let mut buf = [0u8; BufFactory::MAX_BUF_SIZE];

    loop {
        match conn.dgram_recv(&mut buf) {
            Ok(read) => {
                log::trace!("Received HTTP/3 DATAGRAM ({} bytes)", read);

                if !logging_ctx.keep_resp {
                    continue;
                }

                let dgram = &mut buf[..read];
                let mut octets = Octets::with_slice(dgram);
                let dgram_flow_id = match octets.get_varint() {
                    Ok(id) => id,
                    Err(e) => {
                        log::warn!("Failed to parse DATAGRAM flow ID: {}", e);
                        continue;
                    }
                };
                let payload_offset = octets.off();
                if payload_offset > dgram.len() {
                    log::warn!(
                        "Invalid DATAGRAM payload offset: {}",
                        payload_offset
                    );
                    continue;
                }
                let payload = retrieve_dgram(&mut dgram[payload_offset..]);

                let file_path = match logging_ctx.results_dir.as_ref() {
                    Some(results_dir) => format!(
                        "{}/flow_{}_dgram_{}.data",
                        results_dir, flow_id, dgram_flow_id
                    ),
                    None => continue,
                };
                ensure_log_file(
                    &mut logging_ctx.dgram_map,
                    dgram_flow_id,
                    file_path,
                    "datagram flow",
                );

                if let Some(file) = logging_ctx.dgram_map.get_mut(&dgram_flow_id)
                {
                    write_chunk(file, payload);
                }
            }
            Err(Error::Done) => {
                break;
            }
            Err(e) => {
                log::warn!("dgram_recv error: {}", e);
                break;
            }
        }
    }
}

/// Starts a QUIC client at the MASQUE tunnel ingress.
pub async fn quic_client(
    mut t_send: OutboundFrameSender,
    mut t_recv: InboundFrameStream,
    config: E2eClientConfig,
    flow_id: u64,
    reliable_masque: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!("End-to-end QUIC client started");
    let mut egress = [0; BufFactory::MAX_BUF_SIZE];
    let mut quic_config = e2e_quic_config(&config);

    let peer = format!("[{}]:{}", config.target_ip, config.target_port)
        .parse()
        .expect("Invalid peer address");

    let local = config
        .client_address
        .parse()
        .expect("Invalid local address");

    let scid = SimpleConnectionIdGenerator::new_connection_id(
        &SimpleConnectionIdGenerator
    );

    let mut e2e_conn = quiche::connect(
        Some(&config.server_name),
        &scid,
        local,
        peer,
        &mut quic_config,
    )?;

    // Apply keylog settings
    if config.log_keys {
        if let Some(ref results_dir) = config.results_dir {
            let keylog_path = format!("{}/ssl-client.key", results_dir);
            let keylog_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&keylog_path)
                .map_err(|e| {
                    format!("Failed to open keylog file {}: {}", keylog_path, e)
                })?;
            e2e_conn.set_keylog(Box::new(keylog_file));
        }
    }

    if config.qlog {
        if let Some(ref results_dir) = config.results_dir {
            let qlog_file_path = format!("{}/e2e-{:?}.qlog", results_dir, scid);
            let qlog_file = File::create(&qlog_file_path).map_err(|e| {
                format!("Failed to create qlog file {}: {}", qlog_file_path, e)
            })?;
            e2e_conn.set_qlog(
                Box::new(qlog_file),
                "e2e-h3".to_string(),
                "Proxied end-to-end HTTP/3 connection".to_string(),
            );
        }
    }

    match e2e_conn.send(&mut egress) {
        Ok((written, _)) => {
            let frame = if reliable_masque {
                dgram_capsule_from_udp_payload(&egress[..written])
            } else {
                proxied_dgram(flow_id, &egress[..written])
            };

            if let Err(e) = t_send.send(frame).await {
                log::warn!("Failed to send encapsulated UDP datagram: {}", e);
            }
        }
        Err(Error::Done) => {}
        Err(e) => {
            log::warn!("Initial conn.send() error: {}", e);
        }
    }

    task::spawn(async move {
        let mut h3_conn: Option<h3::Connection> = None;
        let mut get_request_sent = false;
        let mut logging_ctx = LoggingContext {
            results_dir: config.results_dir.clone(),
            request_start_time: None,
            log_stats: config.log_stats,
            keep_resp: config.keep_resp,
            resp_map: HashMap::new(),
            dgram_map: HashMap::new(),
            bytes_received: HashMap::new(),
        };

        let mut capsule_deframer = CapsuleDeframer::new();

        let default_sleep = Duration::from_secs(1);
        let mut timeout_deadline = tokio::time::Instant::now() + default_sleep;
        let sleep = tokio::time::sleep_until(timeout_deadline);
        tokio::pin!(sleep);

        'e2e: loop {
            // Update the timer to the inner connection's next timeout
            let new_deadline = match e2e_conn.timeout() {
                Some(timeout) => tokio::time::Instant::now() + timeout,
                None => tokio::time::Instant::now() + default_sleep,
            };
            if new_deadline != timeout_deadline {
                timeout_deadline = new_deadline;
                sleep.as_mut().reset(timeout_deadline);
            }

            tokio::select! {
                biased;
                () = &mut sleep => {
                    e2e_conn.on_timeout();
                    timeout_deadline = tokio::time::Instant::now() + default_sleep;
                    sleep.as_mut().reset(timeout_deadline);
                }
                frame = t_recv.recv() => {
                    match frame {
                        Some(frame) => {
                            if handle_masque_inbound_frame(
                                frame,
                                reliable_masque,
                                &mut capsule_deframer,
                                &mut e2e_conn,
                                &mut h3_conn,
                                &mut logging_ctx,
                                &scid,
                                flow_id,
                                peer,
                                local,
                            ) {
                                break 'e2e;
                            }
                        }
                        None => {
                            log::warn!("Client-side tunnel closed");
                            break 'e2e;
                        }
                    }
                }
            }

            // Drain send() until done after every recv or timeout
            'send: loop {
                if e2e_conn.is_draining() {
                    break 'send;
                }

                match e2e_conn.send(&mut egress) {
                    Ok((written, _)) => {
                        let frame = if reliable_masque {
                            dgram_capsule_from_udp_payload(&egress[..written])
                        } else {
                            proxied_dgram(flow_id, &egress[..written])
                        };

                        if let Err(e) = t_send.send(frame).await {
                            log::warn!("Failed to send UDP datagram: {}", e);
                            break 'e2e;
                        }
                    }
                    Err(Error::Done) => {
                        break 'send;
                    }
                    Err(e) => {
                        log::warn!("conn.send() error: {}", e);
                        break 'e2e;
                    }
                }
            }

            if e2e_conn.is_established() {
                if let Some(ref mut h3) = h3_conn {
                    if !get_request_sent {
                        let headers = vec![
                            h3::Header::new(b":method", b"GET"),
                            h3::Header::new(b":scheme", b"https"),
                            h3::Header::new(
                                b":authority",
                                config.server_name.as_bytes(),
                            ),
                            h3::Header::new(b":path", config.endpoint.as_bytes()),
                            h3::Header::new(
                                b"priority",
                                config.inner_prio.as_bytes(),
                            ),
                        ];

                        get_request_sent = true;
                        logging_ctx.request_start_time = Some(Instant::now());

                        match h3.send_request(&mut e2e_conn, &headers, true) {
                            Ok(sid) => {
                                log::info!("Sent GET request on stream {}", sid);
                            }
                            Err(e) => {
                                log::warn!("Failed to send GET request: {}", e);
                            }
                        }

                        handle_h3_recv(
                            &mut e2e_conn,
                            h3,
                            &mut logging_ctx,
                            &scid,
                            flow_id,
                        );
                    }
                } else {
                    log::info!("End-to-end QUIC connection established");

                    let h3_config = h3::Config::new()
                        .expect("Failed to create the HTTP/3 config");

                    match h3::Connection::with_transport(
                        &mut e2e_conn,
                        &h3_config,
                    ) {
                        Ok(h3c) => {
                            h3_conn = Some(h3c);
                            log::info!("Inner HTTP/3 connection created");
                        }
                        Err(e) => {
                            log::info!("Failed to establish the inner HTTP/3 connection: {}", e);
                        }
                    }
                }
            }

            if e2e_conn.is_closed() {
                break 'e2e;
            }
        }
    });

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_masque_inbound_frame(
    frame: InboundFrame,
    reliable_masque: bool,
    capsule_deframer: &mut CapsuleDeframer,
    e2e_conn: &mut Connection,
    h3_conn: &mut Option<h3::Connection>,
    logging_ctx: &mut LoggingContext,
    scid: &ConnectionId,
    flow_id: u64,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
) -> bool {
    let recv_info = quiche::RecvInfo {
        from: peer,
        to: local,
    };

    match frame {
        InboundFrame::Datagram(mut pooled) => {
            match e2e_conn.recv(retrieve_dgram(pooled.as_mut()), recv_info) {
                Ok(_) => {
                    if let Some(ref mut h3) = h3_conn {
                        handle_h3_recv(e2e_conn, h3, logging_ctx, scid, flow_id);
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Error receiving on the inner QUIC connection (Datagram): {}",
                        e
                    );
                    return true;
                }
            }
        }
        InboundFrame::Body(buf, fin) => {
            if !reliable_masque {
                log::warn!(
                    "Unexpected body data on MASQUE tunnel without Capsule-Protocol; Ignoring"
                );
                return false;
            }

            // Feed the data into the deframer
            capsule_deframer.feed(&buf);

            // Process all complete UDP payloads
            while let Some(mut udp_payload) = capsule_deframer.pop_udp_payload() {
                match e2e_conn.recv(&mut udp_payload, recv_info) {
                    Ok(_) => {
                        if let Some(ref mut h3) = h3_conn {
                            handle_h3_recv(
                                e2e_conn,
                                h3,
                                logging_ctx,
                                scid,
                                flow_id,
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Error receiving on the inner QUIC connection (capsule): {}",
                            e
                        );
                        return true;
                    }
                }
            }

            if fin {
                log::info!("Capsule stream finished by peer");
                return true;
            }
        }
    }

    false
}

fn handle_h3_recv(
    conn: &mut Connection,
    h3: &mut h3::Connection,
    logging_ctx: &mut LoggingContext,
    scid: &ConnectionId,
    flow_id: u64,
) {
    'poll: loop {
        match h3.poll(conn) {
            Ok((
                sid,
                Event::Headers {
                    list,
                    more_frames: _,
                },
            )) => {
                log::trace!("Received HTTP/3 headers on stream {}", sid);

                for h in list {
                    log::trace!(
                        "{} {}",
                        std::str::from_utf8(h.name()).unwrap_or("<non-utf8>"),
                        std::str::from_utf8(h.value()).unwrap_or("<non-utf8>")
                    )
                }
            }

            Ok((sid, Event::Data)) => {
                log::trace!("Received DATA on stream {}", sid);
                let mut buf = [0u8; BufFactory::MAX_BUF_SIZE];

                if logging_ctx.keep_resp {
                    if let Some(ref results_dir) = logging_ctx.results_dir {
                        let file_path = format!(
                            "{}/flow_{}_stream_{}.data",
                            results_dir, flow_id, sid
                        );
                        ensure_log_file(
                            &mut logging_ctx.resp_map,
                            sid,
                            file_path,
                            "stream",
                        );
                    }
                }

                // Drain body frames
                'h3_stream: loop {
                    match h3.recv_body(conn, sid, &mut buf) {
                        Ok(read) => {
                            if read == 0 {
                                break 'h3_stream;
                            }

                            *logging_ctx
                                .bytes_received
                                .entry(sid)
                                .or_insert(0) += read as u64;

                            let chunk = &buf[..read];

                            log::trace!(
                                "Received HTTP/3 body ({} bytes)",
                                chunk.len()
                            );

                            // Write the response, if needed
                            if let Some(file) = logging_ctx.resp_map.get_mut(&sid)
                            {
                                write_chunk(file, chunk);
                            }
                        }

                        Err(h3::Error::Done) => {
                            break 'h3_stream;
                        }

                        Err(e) => {
                            log::warn!("recv_body error: {}", e);
                        }
                    }
                }
            }

            Ok((sid, Event::Finished)) => {
                log::info!("HTTP/3 stream {} finished", sid);

                // Close file for this stream
                if logging_ctx.resp_map.remove(&sid).is_some() {
                    log::debug!("Closed file for stream {}", sid);
                }

                if let Some(start_time) = logging_ctx.request_start_time.take() {
                    let duration = start_time.elapsed();
                    let duration_us = duration.as_micros();

                    log::info!(
                        "Flow {} total request time: {:.3}µs",
                        flow_id,
                        duration_us,
                    );

                    // Write JSON timing data to results directory if timing logging is enabled
                    if logging_ctx.log_stats {
                        if let Some(ref results_dir) = logging_ctx.results_dir {
                            let timing_file_path = format!(
                                "{}/e2e-{:?}.timing.json",
                                results_dir, scid
                            );
                            let bytes = logging_ctx
                                .bytes_received
                                .remove(&sid)
                                .unwrap_or(0);
                            let timing_data = json!({
                                "flow_id": flow_id,
                                "stream_id": sid,
                                "duration_us": duration_us,
                                "bytes_received": bytes,
                            });

                            if let Ok(mut file) = File::create(&timing_file_path)
                            {
                                if let Err(e) = writeln!(
                                    file,
                                    "{}",
                                    serde_json::to_string_pretty(&timing_data)
                                        .unwrap_or_default()
                                ) {
                                    log::warn!(
                                        "Failed to write timing data to {}: {}",
                                        timing_file_path,
                                        e
                                    );
                                } else {
                                    log::debug!(
                                        "Timing data written to {}",
                                        timing_file_path
                                    );
                                }
                            } else {
                                log::warn!(
                                    "Failed to create timing file: {}",
                                    timing_file_path
                                );
                            }
                        }
                    }
                }
            }

            Ok((sid, Event::Reset(_))) => {
                log::info!("HTTP/3 stream {} reset", sid);

                if logging_ctx.resp_map.remove(&sid).is_some() {
                    log::debug!("Closed file for reset stream {}", sid);
                }
                logging_ctx.bytes_received.remove(&sid);
            }

            Ok((sid, Event::PriorityUpdate)) => {
                log::info!("Updated HTTP/3 stream {} priority", sid);
            }

            Ok((sid, Event::GoAway)) => {
                log::info!("HTTP/3 stream {} GOAWAY", sid);
            }

            Err(h3::Error::Done) => {
                break 'poll;
            }

            Err(e) => {
                log::warn!("h3 poll error: {}", e);
                break 'poll;
            }
        }
    }

    drain_h3_datagrams(conn, logging_ctx, flow_id);
}

fn e2e_quic_config(client_cfg: &E2eClientConfig) -> quiche::Config {
    let mut qc = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .expect("Failed to create QUIC config");

    qc.set_application_protos(h3::APPLICATION_PROTOCOL)
        .expect("Failed setting HTTP/3 as the application protocol");

    qc.set_initial_max_streams_uni(MAX_STREAMS);
    qc.set_initial_max_streams_bidi(MAX_STREAMS);

    qc.set_initial_max_stream_data_uni(STREAM_LEVEL_BUFFER_SIZE);
    qc.set_initial_max_stream_data_bidi_local(STREAM_LEVEL_BUFFER_SIZE);
    qc.set_initial_max_stream_data_bidi_remote(STREAM_LEVEL_BUFFER_SIZE);

    qc.set_initial_max_data(CONNECTION_LEVEL_BUFFER_SIZE);

    // Account for the MASQUE overhead
    qc.set_max_send_udp_payload_size(MAX_E2E_QUIC_PACKET_SIZE);
    qc.set_max_recv_udp_payload_size(MAX_E2E_QUIC_PACKET_SIZE);

    qc.set_cc_algorithm_name(&client_cfg.cc_algorithm)
        .expect("Unsupported congestion control algorithm");

    qc.verify_peer(!client_cfg.no_verify);
    qc.load_verify_locations_from_file(&client_cfg.ca)
        .expect("Failed to load CA certificates");

    qc.enable_dgram(true, DGRAM_BUFFER_SIZE, DGRAM_BUFFER_SIZE);

    if client_cfg.log_keys {
        qc.log_keys();
    }

    qc
}
