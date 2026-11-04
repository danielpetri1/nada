//! UDP tunnels established by CONNECT-UDP requests.
use crate::capsules::{dgram_capsule_from_udp_payload, CapsuleDeframer};
use crate::dgrams::{decode_dgram, relayed_dgram};
use futures::SinkExt;
use std::{fmt, net::SocketAddr, sync::Arc};
use tokio::sync::{mpsc, watch};
use tokio_quiche::http3::driver::{
    ClientH3Command, H3Command, InboundFrame, InboundFrameStream, OutboundFrameSender,
    RequestSender, StreamShutdown,
};

/// Maximum UDP payload accepted by capsule tunnels (also valid for IPv4).
pub const MAX_UDP_PAYLOAD: usize = 65_507;
const RECEIVE_QUEUE: usize = 64;

/// The local sending policy for HTTP Datagrams on the client-relay connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Substrate {
    /// Unreliable HTTP Datagrams carried in QUIC DATAGRAM frames.
    Datagram,
    /// Reliable HTTP Datagrams carried in DATAGRAM capsules on the request stream.
    Capsule,
}

impl Substrate {
    pub fn from_reliable(reliable: bool) -> Self {
        if reliable {
            Self::Capsule
        } else {
            Self::Datagram
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelError {
    Closed,
    Connection(String),
    Rejected(u16),
    Protocol(String),
    TooLarge { size: usize, maximum: usize },
    Timeout,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "tunnel closed"),
            Self::Connection(reason) => write!(f, "relay connection failed: {reason}"),
            Self::Rejected(status) => write!(f, "tunnel request rejected with HTTP {status}"),
            Self::Protocol(reason) => write!(f, "invalid tunnel data: {reason}"),
            Self::TooLarge { size, maximum } => {
                write!(f, "UDP payload is {size} bytes; tunnel limit is {maximum}")
            }
            Self::Timeout => write!(f, "timed out establishing tunnel"),
        }
    }
}
impl std::error::Error for TunnelError {}

/// Lifecycle shared by individual UDP tunnels and the outer client-relay connection.
#[derive(Clone, Debug)]
pub(crate) enum TunnelState {
    Open,
    Closed,
    Failed(TunnelError),
}

pub(crate) type ControlSender = RequestSender<ClientH3Command, H3Command>;

struct Lifetime {
    stream_id: u64,
    commands: ControlSender,
    state: watch::Sender<TunnelState>,
    _stream_keepalive: Option<OutboundFrameSender>,
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.state.send_replace(TunnelState::Closed);
        let _ = self.commands.send(H3Command::ShutdownStream {
            stream_id: self.stream_id,
            shutdown: StreamShutdown::Both {
                read_error_code: 0,
                write_error_code: 0,
            },
        });
    }
}

/// A UDP tunnel created by one successful CONNECT-UDP request to a target socket address.
pub struct UdpTunnel {
    target: SocketAddr,
    tx: DatagramSender,
    rx: DatagramReceiver,
}

impl UdpTunnel {
    pub fn stream_id(&self) -> u64 {
        self.tx.quarter_stream_id * 4
    }

    pub fn target(&self) -> SocketAddr {
        self.target
    }
    /// Maximum UDP payload accepted for local sends under the outgoing policy.
    /// This is not a limit on capsule payloads received from the peer.
    pub fn max_payload_size(&self) -> usize {
        self.tx.maximum
    }
    pub fn split(self) -> (DatagramSender, DatagramReceiver) {
        (self.tx, self.rx)
    }

    pub(crate) fn new(
        target: SocketAddr,
        stream_id: u64,
        substrate: Substrate,
        maximum: usize,
        channels: TunnelChannels,
        commands: ControlSender,
        state: watch::Sender<TunnelState>,
    ) -> Self {
        let lifetime = Arc::new(Lifetime {
            stream_id,
            commands,
            state: state.clone(),
            _stream_keepalive: channels.stream_keepalive,
        });
        let (payloads, receiver) = mpsc::channel(RECEIVE_QUEUE);
        let tx = DatagramSender {
            frames: channels.send,
            substrate,
            quarter_stream_id: stream_id / 4,
            maximum,
            state: state.subscribe(),
            _lifetime: lifetime.clone(),
        };
        let rx = DatagramReceiver {
            payloads: receiver,
            state: state.subscribe(),
            finished: false,
            _lifetime: lifetime,
        };
        tokio::spawn(async move {
            let result = receive_payloads(
                channels.capsules,
                channels.datagrams,
                &payloads,
                state.subscribe(),
            )
            .await;
            // Do not overwrite a reset/connection error reported by the controller.
            state.send_if_modified(|current| {
                if matches!(current, TunnelState::Open) {
                    *current = match result {
                        Ok(()) => TunnelState::Closed,
                        Err(err) => TunnelState::Failed(err),
                    };
                    true
                } else {
                    false
                }
            });
        });
        Self { target, tx, rx }
    }
}

pub(crate) struct TunnelChannels {
    pub send: OutboundFrameSender,
    pub capsules: InboundFrameStream,
    pub datagrams: Option<InboundFrameStream>,
    // DATAGRAM sends still need an open request stream.
    pub stream_keepalive: Option<OutboundFrameSender>,
}

impl TunnelChannels {
    pub fn new(
        stream_send: OutboundFrameSender,
        stream_recv: InboundFrameStream,
        datagrams: Option<(OutboundFrameSender, InboundFrameStream)>,
        substrate: Substrate,
    ) -> Result<Self, TunnelError> {
        let (datagram_send, datagrams) = match datagrams {
            Some((send, recv)) => (Some(send), Some(recv)),
            None => (None, None),
        };
        let (send, stream_keepalive) = match substrate {
            Substrate::Capsule => (stream_send, None),
            Substrate::Datagram => (
                datagram_send.ok_or_else(|| {
                    TunnelError::Protocol(
                        "HTTP Datagram channels unavailable for the selected outgoing policy"
                            .into(),
                    )
                })?,
                Some(stream_send),
            ),
        };
        Ok(Self {
            send,
            capsules: stream_recv,
            datagrams,
            stream_keepalive,
        })
    }
}

#[derive(Clone)]
pub struct DatagramSender {
    frames: OutboundFrameSender,
    substrate: Substrate,
    quarter_stream_id: u64,
    maximum: usize,
    state: watch::Receiver<TunnelState>,
    _lifetime: Arc<Lifetime>,
}

impl DatagramSender {
    /// Maximum UDP payload accepted for local sends under the outgoing policy.
    pub fn max_payload_size(&self) -> usize {
        self.maximum
    }

    /// Accept a UDP payload into the bounded transport queue. Oversized datagrams are never split.
    pub async fn send(&self, payload: &[u8]) -> Result<(), TunnelError> {
        match &*self.state.borrow() {
            TunnelState::Open => (),
            TunnelState::Closed => return Err(TunnelError::Closed),
            TunnelState::Failed(err) => return Err(err.clone()),
        }
        if payload.len() > self.maximum {
            return Err(TunnelError::TooLarge {
                size: payload.len(),
                maximum: self.maximum,
            });
        }
        let frame = match self.substrate {
            Substrate::Datagram => relayed_dgram(self.quarter_stream_id, payload),
            Substrate::Capsule => dgram_capsule_from_udp_payload(payload),
        };
        let mut sender = self.frames.clone();
        let mut state = self.state.clone();
        tokio::select! {
            result = sender.send(frame) => result.map_err(|_| TunnelError::Closed),
            _ = state.changed() => match &*state.borrow() {
                TunnelState::Failed(err) => Err(err.clone()),
                _ => Err(TunnelError::Closed),
            },
        }
    }
}

pub struct DatagramReceiver {
    payloads: mpsc::Receiver<Vec<u8>>,
    state: watch::Receiver<TunnelState>,
    finished: bool,
    _lifetime: Arc<Lifetime>,
}

impl DatagramReceiver {
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, TunnelError> {
        if self.finished {
            return Ok(None);
        }
        if let Some(payload) = self.payloads.recv().await {
            return Ok(Some(payload));
        }
        self.finished = true;
        match &*self.state.borrow() {
            TunnelState::Failed(err) => Err(err.clone()),
            _ => Ok(None),
        }
    }
}

async fn receive_payloads(
    mut capsules: InboundFrameStream,
    mut datagrams: Option<InboundFrameStream>,
    payloads: &mpsc::Sender<Vec<u8>>,
    mut state: watch::Receiver<TunnelState>,
) -> Result<(), TunnelError> {
    let mut deframer = CapsuleDeframer::new();
    loop {
        if !matches!(*state.borrow(), TunnelState::Open) {
            return Ok(());
        }
        let frame = tokio::select! {
            _ = state.changed() => return Ok(()),
            frame = capsules.recv() => frame,
            Some(frame) = async { datagrams.as_mut().expect("guarded datagrams").recv().await }, if datagrams.is_some() => Some(frame),
        };
        let Some(frame) = frame else {
            return deframer
                .finish()
                .map_err(|e| TunnelError::Protocol(e.to_string()));
        };
        let mut finished = false;
        match frame {
            InboundFrame::Datagram(buffer) => {
                if let Some(payload) = decode_dgram(buffer.as_ref())
                    .map_err(|e| TunnelError::Protocol(e.to_string()))?
                {
                    tokio::select! {
                        _ = state.changed() => return Ok(()),
                        _ = payloads.send(payload.to_vec()) => (),
                    }
                }
            }
            InboundFrame::Body(buffer, fin) => {
                deframer
                    .feed(&buffer)
                    .map_err(|e| TunnelError::Protocol(e.to_string()))?;
                finished = fin;
            }
        }
        while let Some(payload) = deframer.pop_udp_payload() {
            tokio::select! {
                _ = state.changed() => return Ok(()),
                _ = payloads.send(payload) => (),
            }
        }
        if finished {
            return deframer
                .finish()
                .map_err(|e| TunnelError::Protocol(e.to_string()));
        }
    }
}
