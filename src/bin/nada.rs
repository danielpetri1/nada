use clap::Parser;
use nada::{
    args::{Cli, Command, ConnectArgs, ConnectUdpArgs, ProxyArgs},
    create_results_dir, logging, proxy,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match Cli::parse().command {
        Command::Connect(args) => connect_tcp(args).await,
        Command::ConnectUdp(args) => connect_udp(args).await,
        Command::Proxy(args) => run_proxy(args).await,
    }
}

async fn connect_tcp(args: ConnectArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use foundations::telemetry::log;
    use nada::{client::MasqueClient, tcp_flow};
    use tokio::net::TcpListener;
    logging::init(args.connection.common.log_level.clone().into());
    create_results_dir(&args.connection.common.results_dir);
    let mut listeners = Vec::new();
    for address in &args.listen {
        listeners.push(TcpListener::bind(address).await.map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("cannot bind TCP listener {address}: {error}"),
            )
        })?);
    }
    let client = tokio::select! {
        result = MasqueClient::connect(&args.connection) => result?,
        result = stopped() => { result?; return Ok(()); },
    };
    for listener in &listeners {
        log::info!("TCP forwarder ready"; "listen" => %listener.local_addr()?, "target" => %args.target, "connection_id" => client.connection_id());
    }
    let result = tokio::select! {
        result = tcp_flow::serve(client.clone(), listeners, args.target, args.max_tunnels as usize, std::time::Duration::from_secs(args.tunnel_idle_timeout)) => result,
        result = stopped() => result.map_err(Into::into),
    };
    client.shutdown().await;
    result
}

async fn stopped() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

async fn connect_udp(args: ConnectUdpArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use foundations::telemetry::log;
    use nada::{
        client::MasqueClient,
        udp_flow::{self, FlowConfig},
    };
    use tokio::net::UdpSocket;
    logging::init(args.connection.common.log_level.clone().into());
    create_results_dir(&args.connection.common.results_dir);
    // Bind every listener before opening the shared proxy connection.
    let mut sockets = Vec::new();
    for address in &args.listen {
        let socket = UdpSocket::bind(address).await.map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("cannot bind UDP listener {address}: {error}"),
            )
        })?;
        sockets.push(socket);
    }
    let client = tokio::select! {
        result = MasqueClient::connect(&args.connection) => result?,
        result = stopped() => { result?; return Ok(()); },
    };
    for socket in &sockets {
        log::info!("UDP forwarder ready"; "listen" => %socket.local_addr()?, "target" => %args.target, "connection_id" => client.connection_id());
    }
    let config = FlowConfig {
        max_flows: args.max_tunnels as usize,
        idle_timeout: std::time::Duration::from_secs(args.tunnel_idle_timeout),
        target: args.target,
    };
    let result = tokio::select! {
        result = udp_flow::serve(client.clone(), sockets, config) => result,
        result = stopped() => result.map_err(Into::into),
    };
    client.shutdown().await;
    result
}

async fn run_proxy(args: ProxyArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    logging::init(args.common.log_level.clone().into());
    create_results_dir(&args.common.results_dir);
    tokio::select! {
        result = proxy::serve(args) => result,
        result = stopped() => { result?; Ok(()) },
    }
}
