pub mod args;
pub mod capsules;
pub mod dgrams;
pub mod e2e;
pub mod helpers;
pub mod logging;
pub mod prios;

use foundations::telemetry::log;
use octets::varint_len;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tokio_quiche::http3::driver::{InboundFrameStream, OutboundFrameSender};
use tokio_quiche::QuicConnection;

pub const UDP_PAYLOAD_CONTEXT_ID: u64 = 0x00;
pub const CONTEXT_ID_VARINT_LEN: usize = varint_len(UDP_PAYLOAD_CONTEXT_ID);
pub const MAX_STREAMS: u64 = 1000;

/// Maximum outer QUIC packet size on the client-proxy segment.
/// Ref: Kühlewind et al. (2021), Section 4.1.
pub const MAX_OUTER_QUIC_PACKET_SIZE: usize = 1380;

pub struct Tunnel {
    /// Sends HTTP/3 DATAGRAMS to the client
    pub send: Option<OutboundFrameSender>,

    /// Receives HTTP/3 DATAGRAMS from the client
    pub recv: Option<InboundFrameStream>,
}

impl Tunnel {
    pub fn new(send: OutboundFrameSender, recv: InboundFrameStream) -> Self {
        Tunnel {
            send: Some(send),
            recv: Some(recv),
        }
    }
}

pub struct MasqueTunnels {
    /// Maps a flow ID to a MASQUE tunnel
    pub masque_map: HashMap<u64, Tunnel>,
}

impl MasqueTunnels {
    pub fn new() -> Self {
        MasqueTunnels {
            masque_map: HashMap::new(),
        }
    }
}

impl Default for MasqueTunnels {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates the results directory if needed, panicking on failure.
pub fn create_results_dir(results_dir: &Option<String>) {
    if let Some(ref results_dir) = results_dir {
        if let Err(e) = std::fs::create_dir_all(results_dir) {
            panic!("Failed to create results directory {}: {}", results_dir, e);
        }
    }
}

/// Writes outer-connection stats to a JSON file in the results directory.
pub fn write_connection_stats(
    connection: &QuicConnection,
    results_dir: &str,
    conn_id: &tokio_quiche::quiche::ConnectionId<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stats = connection.stats();
    let stats_guard = stats
        .lock()
        .map_err(|e| format!("Failed to lock stats: {}", e))?;

    let quiche_stats = &stats_guard.stats;
    let path_stats = stats_guard.path_stats.as_ref();

    let json = serde_json::json!({
        "recv": quiche_stats.recv,
        "recv_bytes": quiche_stats.recv_bytes,
        "sent": quiche_stats.sent,
        "sent_bytes": quiche_stats.sent_bytes,
        "lost": quiche_stats.lost,
        "lost_bytes": quiche_stats.lost_bytes,
        "retrans": quiche_stats.retrans,
        "stream_retrans_bytes": quiche_stats.stream_retrans_bytes,
        "dgram_recv": quiche_stats.dgram_recv,
        "dgram_sent": quiche_stats.dgram_sent,
        "cwnd": path_stats.map(|p| p.cwnd),
        "pmtu": path_stats.map(|p| p.pmtu),
        "rtt_us": path_stats.map(|p| p.rtt.as_micros() as u64),
        "min_rtt_us": path_stats.and_then(|p| p.min_rtt).map(|r| r.as_micros() as u64),
        "rttvar_us": path_stats.map(|p| p.rttvar.as_micros() as u64),
        "delivery_rate": path_stats.map(|p| p.delivery_rate),
    });

    let stats_file_path =
        format!("{}/outer-connection-stats-{:?}.json", results_dir, conn_id);
    let json_string = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("Failed to serialize stats: {}", e))?;

    let mut file = File::create(&stats_file_path).map_err(|e| {
        format!("Failed to create stats file {}: {}", stats_file_path, e)
    })?;
    file.write_all(json_string.as_bytes())
        .map_err(|e| format!("Failed to write stats to file: {}", e))?;

    log::info!("Connection stats written to {}", stats_file_path);

    Ok(())
}
