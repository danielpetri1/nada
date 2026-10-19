use crate::logging::LogLevel;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
/// Common arguments between server and client.
pub struct Args {
    /// IP proxy address, including the port number
    #[arg(long, default_value = "[fd00:0:0:3::1]:443")]
    pub proxy_address: String,

    /// Enable TLS key logging in the results directory.
    #[arg(long, default_value_t = false)]
    pub log_keys: bool,

    /// Directory to store the desired results
    #[arg(long)]
    pub results_dir: Option<String>,

    /// Enable qlog output in the results directory.
    #[arg(long, default_value_t = false)]
    pub qlog: bool,

    /// Log verbosity level
    #[arg(long, default_value = "info", value_enum)]
    pub log_level: LogLevel,

    /// Congestion control algorithm to use for the inner and outer QUIC connections.
    #[arg(long, default_value = "cubic")]
    pub cc_algorithm: String,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct ClientArgs {
    #[clap(flatten)]
    pub common: Args,

    /// IP client address, including the port number
    #[arg(long, default_value = "[fd00:0:0:1::1]:0")]
    pub client_address: String,

    /// Proxy authority
    #[arg(long, default_value = "masque.technology")]
    pub proxy_authority: String,

    /// Target server host.
    #[arg(long, default_value = "fd00:0:0:4::1")]
    pub target_ip: String,

    /// Target server port.
    #[arg(long, default_value = "25565")]
    pub target_port: String,

    /// Path to the Certificate Authority used by the end-to-end connection.
    #[arg(long, default_value = "./src/bin/certs/ca.pem")]
    pub ca: String,

    /// Hostname of the server being connected to.
    #[arg(long, default_value = "quic.tech")]
    pub server_name: String,

    /// GET request filepath (one per tunnel). Can be specified multiple times.
    #[arg(long, alias = "ep", default_value = "/index.html", action = clap::ArgAction::Append)]
    pub endpoint: Vec<String>,

    /// Logs statistics for the inner and outer connections.
    #[arg(long = "log-stats", default_value_t = false)]
    pub log_stats: bool,

    /// Stores responses of the inner connection.
    #[arg(long = "keep-resp", default_value_t = false)]
    pub keep_resp: bool,

    /// Whether to verify the peer's certificate.
    #[arg(long, default_value_t = false)]
    pub no_verify: bool,

    /// Enable the capsule protocol (reliable MASQUE).
    #[arg(long, default_value_t = false)]
    pub reliable: bool,

    /// HTTP/3 priority header values for outer tunnel connections (one per
    /// CONNECT-UDP request). Can be specified multiple times.
    #[arg(long = "outer-prio", alias = "op", default_value = "u=3", action = clap::ArgAction::Append)]
    pub outer_prios: Vec<String>,

    /// HTTP/3 priority header value for the inner tunnel connections.
    #[arg(long, default_value = "u=3")]
    pub inner_prio: String,

    /// Maximum idle timeout in seconds before the connection closes.
    #[arg(long = "idle-timeout", default_value = "3")]
    pub idle_timeout_secs: u64,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct ProxyArgs {
    #[clap(flatten)]
    pub common: Args,

    /// Path to the TLS certificate.
    #[arg(long, default_value = "./src/bin/certs/proxy-cert.pem")]
    pub cert: String,

    /// Path to the private TLS key.
    #[arg(long, default_value = "./src/bin/certs/proxy-key.pem")]
    pub key: String,

    /// Logs statistics for each outer connection to the results directory.
    #[arg(long = "log-stats", default_value_t = false)]
    pub log_stats: bool,
}
