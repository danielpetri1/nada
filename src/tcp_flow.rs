use crate::client::MasqueClient;
use foundations::telemetry::log;
use futures::{stream::FuturesUnordered, StreamExt};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::JoinSet,
    time::{sleep_until, timeout, Instant},
};

type FlowResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub async fn serve(
    client: MasqueClient,
    listeners: Vec<TcpListener>,
    target: SocketAddr,
    max_tunnels: usize,
    idle: Duration,
) -> FlowResult {
    let mut accepts = FuturesUnordered::new();
    for listener in &listeners {
        accepts.push(accept(listener));
    }
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            error = client.closed() => return Err(error.into()),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                let (source, result) = result?;
                if let Err(error) = result {
                    log::warn!("TCP flow closed"; "source" => %source, "target" => %target, "connection_id" => client.connection_id(), "error" => %error);
                }
            }
            Some((listener, accepted)) = accepts.next() => {
                let (mut socket, source) = accepted?;
                accepts.push(accept(listener));
                if tasks.len() >= max_tunnels {
                    log::warn!("Closing TCP connection: shared tunnel limit reached"; "source" => %source, "target" => %target);
                    continue;
                }
                let client = client.clone();
                tasks.spawn(async move {
                    let result: FlowResult = async {
                        let mut tunnel = timeout(idle, client.connect_tcp(target)).await??;
                        log::info!("CONNECT flow established"; "source" => %source, "target" => %target, "connection_id" => client.connection_id(), "stream_id" => tunnel.stream_id());
                        relay(&mut socket, &mut tunnel, idle).await?;
                        Ok(())
                    }.await;
                    (source, result)
                });
            }
        }
    }
}

async fn accept(
    listener: &TcpListener,
) -> (
    &TcpListener,
    std::io::Result<(tokio::net::TcpStream, SocketAddr)>,
) {
    (listener, listener.accept().await)
}

async fn relay<A, B>(a: &mut A, b: &mut B, idle: Duration) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let (activity, mut changed) = watch::channel(Instant::now());
    let transfer = async {
        tokio::try_join!(
            copy(&mut ar, &mut bw, &activity),
            copy(&mut br, &mut aw, &activity)
        )?;
        Ok(())
    };
    let expiry = async {
        loop {
            let deadline = *changed.borrow_and_update() + idle;
            tokio::select! {
                _ = sleep_until(deadline) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP tunnel idle timeout")),
                _ = changed.changed() => (),
            }
        }
    };
    tokio::select! { result = transfer => result, result = expiry => result }
}

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    activity: &watch::Sender<Instant>,
) -> std::io::Result<()> {
    let mut buffer = [0; 16_384];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            return writer.shutdown().await;
        }
        activity.send_replace(Instant::now());
        let mut remaining = &buffer[..n];
        while !remaining.is_empty() {
            let written = writer.write(remaining).await?;
            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            remaining = &remaining[written..];
            activity.send_replace(Instant::now());
        }
    }
}
