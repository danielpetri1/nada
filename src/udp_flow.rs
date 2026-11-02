use crate::{client::MasqueClient, tunnel::TunnelError};
use foundations::telemetry::log;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{sleep_until, timeout, Instant},
};

pub type FlowResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const FLOW_QUEUE: usize = 64;
const RECEIVE_QUEUE: usize = 256;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FlowKey {
    source: SocketAddr,
    listener: usize,
}

struct ReceivedPacket {
    flow: FlowKey,
    payload: Vec<u8>,
}

pub struct FlowConfig {
    pub max_flows: usize,
    pub idle_timeout: Duration,
    pub target: SocketAddr,
}

pub async fn serve(
    client: MasqueClient,
    sockets: Vec<UdpSocket>,
    config: FlowConfig,
) -> FlowResult {
    let sockets: Vec<_> = sockets.into_iter().map(Arc::new).collect();
    let (send, mut incoming) = mpsc::channel(RECEIVE_QUEUE);
    let mut listeners = JoinSet::new();
    for (listener, socket) in sockets.iter().enumerate() {
        let socket = socket.clone();
        let send = send.clone();
        listeners.spawn(async move {
            // Receive full UDP payloads, including ones the tunnel may reject.
            let mut buffer = vec![0; 65_536];
            loop {
                let (length, source) = match socket.recv_from(&mut buffer).await {
                    Ok(packet) => packet,
                    Err(error) => return error,
                };
                let packet = ReceivedPacket {
                    flow: FlowKey { source, listener },
                    payload: buffer[..length].to_vec(),
                };
                if let Err(error) = send.try_send(packet) {
                    log::warn!("Dropping UDP packet: receive queue unavailable"; "source" => %source, "error" => %error);
                }
            }
        });
    }
    drop(send);
    let mut flows = HashMap::<FlowKey, mpsc::Sender<Vec<u8>>>::new();
    let mut tasks = JoinSet::new();
    let target = config.target;
    loop {
        tokio::select! {
            biased;
            error = client.closed() => return Err(error.into()),
            Some(result) = listeners.join_next() => return Err(result?.into()),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                let (key, result) = result?;
                flows.remove(&key);
                if let Err(error) = result {
                    log::warn!("UDP flow closed"; "source" => %key.source, "target" => %target, "connection_id" => client.connection_id(), "error" => %error);
                }
            }
            packet = incoming.recv() => {
                let Some(ReceivedPacket { flow: key, payload }) = packet else { return Ok(()); };
                if !flows.contains_key(&key) {
                    if flows.len() >= config.max_flows {
                        log::warn!("Dropping UDP packet: shared flow limit reached"; "source" => %key.source, "target" => %target);
                        continue;
                    }
                    let (sender, receiver) = mpsc::channel(FLOW_QUEUE);
                    flows.insert(key, sender);
                    let client = client.clone();
                    let socket = sockets[key.listener].clone();
                    let idle = config.idle_timeout;
                    tasks.spawn(async move {
                        let result = serve_flow(key.source, target, client, receiver, socket, idle).await;
                        (key, result)
                    });
                }
                if let Err(error) = flows[&key].try_send(payload) {
                    log::warn!("Dropping UDP packet: bounded flow queue unavailable"; "source" => %key.source, "target" => %target, "error" => %error);
                }
            }
        }
    }
}

async fn serve_flow(
    source: SocketAddr,
    target: SocketAddr,
    client: MasqueClient,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    idle: Duration,
) -> FlowResult {
    let tunnel = timeout(idle, client.connect_udp(target)).await??;
    let stream_id = tunnel.stream_id();
    let maximum = tunnel.max_payload_size();
    log::info!("CONNECT-UDP flow established"; "source" => %source, "target" => %target, "connection_id" => client.connection_id(), "stream_id" => stream_id, "sending_mode" => ?client.sending_mode(), "max_payload" => maximum);
    if maximum < 1200 {
        log::warn!("Tunnel cannot carry QUIC's minimum 1200-byte UDP payload"; "source" => %source, "target" => %target, "connection_id" => client.connection_id(), "stream_id" => stream_id, "max_payload" => maximum);
    }
    let (tx, mut rx) = tunnel.split();
    let (activity, mut changed) = watch::channel(Instant::now());
    let upload = async {
        while let Some(payload) = incoming.recv().await {
            match tx.send(&payload).await {
                Ok(()) => {
                    activity.send_replace(Instant::now());
                }
                Err(error @ TunnelError::TooLarge { .. }) => {
                    log::warn!("Dropping oversized UDP payload"; "source" => %source, "target" => %target, "connection_id" => client.connection_id(), "stream_id" => stream_id, "sending_mode" => ?client.sending_mode(), "error" => %error);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    };
    let download = async {
        while let Some(payload) = rx.recv().await? {
            socket.send_to(&payload, source).await?;
            activity.send_replace(Instant::now());
        }
        Ok(())
    };
    let expiry = async {
        loop {
            let deadline = *changed.borrow_and_update() + idle;
            tokio::select! {
                _ = sleep_until(deadline) => return Ok(()),
                result = changed.changed() => if result.is_err() { return Ok(()); },
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
        result = expiry => result,
    }
}
