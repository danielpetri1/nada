//! Reliable byte streams carried in HTTP/3 CONNECT DATA frames.
use crate::tunnel::{TunnelError, TunnelState};
use futures::future::BoxFuture;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
};
use tokio_quiche::http3::driver::{
    InboundFrame, InboundFrameStream, OutboundFrame, OutboundFrameSender,
};
use tokio_quiche::{buf_factory::BufFactory, quiche::BufFactory as _};

const WRITE_CHUNK: usize = 16_384;

struct Failure {
    changed: BoxFuture<'static, TunnelError>,
    error: Option<TunnelError>,
}

impl Failure {
    fn new(mut state: watch::Receiver<TunnelState>) -> Self {
        Self {
            changed: Box::pin(async move {
                loop {
                    match state.borrow().clone() {
                        TunnelState::Failed(error) => return error,
                        TunnelState::Closed => return TunnelError::Closed,
                        TunnelState::Open => (),
                    }
                    if state.changed().await.is_err() {
                        return futures::future::pending().await;
                    }
                }
            }),
            error: None,
        }
    }

    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.error.is_none() {
            if let Poll::Ready(error) = self.changed.as_mut().poll(cx) {
                self.error = Some(error);
            }
        }
        match &self.error {
            Some(error) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                error.clone(),
            )),
            None => Ok(()),
        }
    }
}

/// One CONNECT tunnel to a TCP target.
pub struct TcpTunnel {
    target: SocketAddr,
    stream_id: u64,
    send: OutboundFrameSender,
    recv: InboundFrameStream,
    buffered: Vec<u8>,
    offset: usize,
    read_fin: bool,
    write_fin: bool,
    read_failure: Failure,
    write_failure: Failure,
    cancel: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl TcpTunnel {
    pub fn target(&self) -> SocketAddr {
        self.target
    }
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub(crate) fn new(
        target: SocketAddr,
        stream_id: u64,
        send: OutboundFrameSender,
        recv: InboundFrameStream,
        read_fin: bool,
        state: watch::Receiver<TunnelState>,
        cancel: impl FnOnce() + Send + Sync + 'static,
    ) -> Self {
        Self {
            target,
            stream_id,
            send,
            recv,
            read_fin,
            buffered: Vec::new(),
            offset: 0,
            write_fin: false,
            read_failure: Failure::new(state.clone()),
            write_failure: Failure::new(state),
            cancel: Some(Box::new(cancel)),
        }
    }
}

impl AsyncRead for TcpTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.read_failure.check(cx)?;
        loop {
            if this.offset < this.buffered.len() {
                let n = output.remaining().min(this.buffered.len() - this.offset);
                output.put_slice(&this.buffered[this.offset..this.offset + n]);
                this.offset += n;
                return Poll::Ready(Ok(()));
            }
            if this.read_fin {
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(this.recv.poll_recv(cx)) {
                Some(InboundFrame::Body(bytes, fin)) => {
                    this.buffered = bytes.to_vec();
                    this.offset = 0;
                    this.read_fin = fin;
                }
                Some(InboundFrame::Datagram(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "datagram on TCP tunnel",
                    )))
                }
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "CONNECT stream ended without FIN",
                    )))
                }
            }
        }
    }
}

impl AsyncWrite for TcpTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_failure.check(cx)?;
        if this.write_fin {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(this.send.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let n = bytes.len().min(WRITE_CHUNK);
        this.send
            .send_item(OutboundFrame::Body(
                BufFactory::buf_from_slice(&bytes[..n]),
                false,
            ))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().write_failure.check(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_fin {
            return Poll::Ready(Ok(()));
        }
        this.write_failure.check(cx)?;
        std::task::ready!(this.send.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        this.send
            .send_item(OutboundFrame::Body(Default::default(), true))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        this.write_fin = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpTunnel {
    fn drop(&mut self) {
        if !(self.read_fin && self.write_fin && self.offset == self.buffered.len()) {
            if let Some(cancel) = self.cancel.take() {
                cancel();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
    };

    struct Peer {
        send: mpsc::Sender<InboundFrame>,
        recv: mpsc::Receiver<OutboundFrame>,
        state: watch::Sender<TunnelState>,
        cancelled: Arc<AtomicUsize>,
    }

    fn tunnel(capacity: usize) -> (TcpTunnel, Peer) {
        let (outgoing, recv) = mpsc::channel(capacity);
        let (send, incoming) = mpsc::channel(capacity);
        let (state, status) = watch::channel(TunnelState::Open);
        let cancelled = Arc::new(AtomicUsize::new(0));
        let count = cancelled.clone();
        (
            TcpTunnel::new(
                "1.1.1.1:53".parse().unwrap(),
                4,
                OutboundFrameSender::new(outgoing),
                incoming,
                false,
                status,
                move || {
                    count.fetch_add(1, Ordering::SeqCst);
                },
            ),
            Peer {
                send,
                recv,
                state,
                cancelled,
            },
        )
    }

    #[tokio::test]
    async fn data_is_a_byte_stream_and_empty_data_is_not_eof() {
        let (mut tunnel, peer) = tunnel(4);
        peer.send
            .send(InboundFrame::Body(Default::default(), false))
            .await
            .unwrap();
        let mut byte = [0];
        assert!(futures::poll!(Box::pin(tunnel.read(&mut byte))).is_pending());
        peer.send
            .send(InboundFrame::Body(
                BufFactory::buf_from_slice(b"abc").into(),
                false,
            ))
            .await
            .unwrap();
        peer.send
            .send(InboundFrame::Body(
                BufFactory::buf_from_slice(b"def").into(),
                true,
            ))
            .await
            .unwrap();
        // Driver cleanup must not discard unread DATA or FIN.
        drop(peer.state);
        let mut received = Vec::new();
        while tunnel.read(&mut byte).await.unwrap() != 0 {
            received.extend(byte);
        }
        assert_eq!(received, b"abcdef");
        // Receiving FIN does not close the write half.
        tunnel.write_all(b"reply").await.unwrap();
        tunnel.shutdown().await.unwrap();
        drop(tunnel);
        assert_eq!(peer.cancelled.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn shutdown_preserves_reads_and_queues_fin_after_data() {
        let (mut tunnel, mut peer) = tunnel(4);
        tunnel.write_all(b"request").await.unwrap();
        tunnel.shutdown().await.unwrap();
        tunnel.shutdown().await.unwrap();
        assert!(
            matches!(peer.recv.recv().await.unwrap(), OutboundFrame::Body(bytes, false) if bytes.as_ref() == b"request")
        );
        assert!(
            matches!(peer.recv.recv().await.unwrap(), OutboundFrame::Body(bytes, true) if bytes.is_empty())
        );
        assert!(peer.recv.try_recv().is_err());
        assert_eq!(
            tunnel.write(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        peer.send
            .send(InboundFrame::Body(
                BufFactory::buf_from_slice(b"response").into(),
                true,
            ))
            .await
            .unwrap();
        let mut received = Vec::new();
        tunnel.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"response");
        drop(tunnel);
        assert_eq!(peer.cancelled.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn writes_are_chunked_and_backpressured_without_losing_bytes() {
        let (mut tunnel, mut peer) = tunnel(1);
        let bytes = vec![42; WRITE_CHUNK * 3 + 7];
        assert_eq!(tunnel.write(&bytes).await.unwrap(), WRITE_CHUNK);
        assert!(futures::poll!(Box::pin(tunnel.write(&bytes[WRITE_CHUNK..]))).is_pending());
        let transfer = async {
            tunnel.write_all(&bytes[WRITE_CHUNK..]).await.unwrap();
            tunnel.shutdown().await.unwrap();
        };
        let receive = async {
            let mut received = Vec::new();
            loop {
                let OutboundFrame::Body(bytes, fin) = peer.recv.recv().await.unwrap() else {
                    panic!()
                };
                assert!(bytes.len() <= WRITE_CHUNK);
                received.extend_from_slice(&bytes);
                if fin {
                    return received;
                }
            }
        };
        let (_, received) = tokio::join!(transfer, receive);
        assert_eq!(received, bytes);
    }

    #[tokio::test]
    async fn resets_and_outer_failure_wake_both_blocked_halves() {
        use futures::task::{waker_ref, ArcWake};
        use std::future::Future;
        struct Wake(AtomicUsize);
        impl ArcWake for Wake {
            fn wake_by_ref(w: &Arc<Self>) {
                w.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        for error in [
            TunnelError::Protocol("reset".into()),
            TunnelError::Connection("outer failed".into()),
        ] {
            let (mut tunnel, peer) = tunnel(1);
            tunnel.write_all(b"fill queue").await.unwrap();
            let (mut read, mut write) = tokio::io::split(tunnel);
            let mut bytes = [0; 1];
            let mut reading = Box::pin(read.read(&mut bytes));
            let mut writing = Box::pin(write.write(b"blocked"));
            let read_wake = Arc::new(Wake(AtomicUsize::new(0)));
            let write_wake = Arc::new(Wake(AtomicUsize::new(0)));
            assert!(reading
                .as_mut()
                .poll(&mut Context::from_waker(&waker_ref(&read_wake)))
                .is_pending());
            assert!(writing
                .as_mut()
                .poll(&mut Context::from_waker(&waker_ref(&write_wake)))
                .is_pending());
            peer.state.send_replace(TunnelState::Failed(error));
            assert!(read_wake.0.load(Ordering::SeqCst) > 0);
            assert!(write_wake.0.load(Ordering::SeqCst) > 0);
            assert_eq!(
                reading.await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            assert_eq!(
                writing.await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
        }
    }

    #[tokio::test]
    async fn missing_fin_is_an_error_and_drop_cancels_only_that_tunnel() {
        let (mut first, first_peer) = tunnel(1);
        let (mut second, second_peer) = tunnel(1);
        drop(first_peer.send);
        assert_eq!(
            first.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        drop(first);
        assert_eq!(first_peer.cancelled.load(Ordering::SeqCst), 1);
        second.write_all(b"unaffected").await.unwrap();
        assert_eq!(second_peer.cancelled.load(Ordering::SeqCst), 0);
    }
}
