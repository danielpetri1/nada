use crate::logging::LogLevel;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::str::FromStr;

const DEFAULT_RELAY_ADDRESS: &str = "[::1]:4431";

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
/// Common arguments between server and client.
pub struct Args {
    /// Enable TLS key logging in the results directory.
    #[arg(long, default_value_t = false)]
    pub log_keys: bool,

    /// Directory to store the desired results.
    #[arg(long)]
    pub results_dir: Option<String>,

    /// Enable qlog output in the results directory.
    #[arg(long, default_value_t = false)]
    pub qlog: bool,

    /// Log verbosity level.
    #[arg(long, default_value = "info", value_enum)]
    pub log_level: LogLevel,

    /// QUIC congestion control for local sends (GET example: both inner and outer).
    #[arg(long, default_value = "bbr2_gcongestion")]
    pub cc_algorithm: String,
}

/// Nada's command-line entry point.
#[derive(Parser, Debug)]
#[command(
    name = "nada",
    version,
    about = "Forward TCP and UDP over HTTP/3 using CONNECT and CONNECT-UDP"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Forward local TCP connections to a fixed target on one shared relay connection.
    Connect(ConnectArgs),
    /// Forward local UDP traffic to a fixed target on one shared relay connection.
    ConnectUdp(ConnectUdpArgs),
    /// Run a relay that accepts CONNECT and CONNECT-UDP requests over HTTP/3.
    Relay(RelayArgs),
}

/// Settings for the client-relay HTTP/3 connection over outer QUIC.
#[derive(clap::Args, Debug, Clone)]
pub struct ConnectionArgs {
    #[command(flatten)]
    pub common: Args,

    /// Remote relay IP and port (IPv4:port or [IPv6]:port).
    #[arg(long, env = "RELAY_ADDRESS", default_value = DEFAULT_RELAY_ADDRESS)]
    pub relay_address: SocketAddr,

    /// Local address for the connection to the relay (default: wildcard in the relay's IP family).
    #[arg(long)]
    pub client_address: Option<SocketAddr>,

    /// Relay TLS server name and HTTP authority.
    #[arg(long, env = "RELAY_AUTHORITY", default_value = "localhost")]
    pub relay_authority: String,

    /// PEM CA bundle for verifying the relay (default: system trust roots).
    #[arg(long)]
    pub relay_ca: Option<PathBuf>,

    /// Maximum idle time for the outer QUIC connection; 0 disables its idle timeout.
    #[arg(long = "idle-timeout", default_value_t = 0)]
    pub idle_timeout_secs: u64,

    /// Time allowed for the relay connection handshake and each tunnel request.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    pub connect_timeout: u64,

    /// Send client-relay UDP payloads in reliable DATAGRAM capsules; no effect on TCP.
    #[arg(long)]
    pub reliable: bool,

    /// Write outer connection statistics on shutdown.
    #[arg(long, requires = "results_dir")]
    pub log_stats: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct ConnectArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,

    /// Remote TCP destination as reached from the relay (IPv4:port or [IPv6]:port).
    #[arg(long, value_name = "ADDRESS", value_parser = parse_target)]
    pub target: SocketAddr,

    /// Local TCP addresses; explicit values replace both defaults. Repeat for multiple sockets.
    #[arg(long, value_name = "ADDRESS", default_values = ["[::1]:18018", "127.0.0.1:18018"])]
    pub listen: Vec<SocketAddr>,

    /// Close a TCP tunnel after this many seconds without transferred bytes.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub tunnel_idle_timeout: u64,

    /// Maximum number of opening and active TCP tunnels across all listeners.
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub max_tunnels: u32,
}

#[derive(clap::Args, Debug, Clone)]
pub struct ConnectUdpArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,

    /// Remote UDP destination as reached from the relay (IPv4:port or [IPv6]:port).
    #[arg(long, value_name = "ADDRESS", value_parser = parse_target)]
    pub target: SocketAddr,

    /// Local UDP addresses; explicit values replace both defaults. Repeat for multiple sockets.
    #[arg(long, value_name = "ADDRESS", default_values = ["[::1]:18018", "127.0.0.1:18018"])]
    pub listen: Vec<SocketAddr>,

    /// Close a UDP flow's tunnel after this many idle seconds.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub tunnel_idle_timeout: u64,

    /// Maximum number of concurrent UDP tunnels across all local listeners.
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub max_tunnels: u32,
}

#[derive(clap::Args, Debug, Clone)]
pub struct RelayArgs {
    #[clap(flatten)]
    pub common: Args,

    /// Local UDP address and port on which to accept QUIC connections.
    #[arg(long, env = "RELAY_ADDRESS", value_name = "ADDRESS", default_value = DEFAULT_RELAY_ADDRESS)]
    pub listen: SocketAddr,

    /// Path to the TLS certificate.
    #[arg(long, env = "RELAY_CERT")]
    pub cert: String,

    /// Path to the private TLS key.
    #[arg(long, env = "RELAY_KEY")]
    pub key: String,

    /// Send all relay-to-client UDP payloads in reliable DATAGRAM capsules.
    #[arg(long)]
    pub reliable: bool,

    /// Time allowed to establish each CONNECT tunnel's outgoing TCP connection.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    pub connect_timeout: u64,

    /// Allowed destination ports, or "all"; explicit values replace the environment/default list.
    #[arg(long = "connect-port", env = "RELAY_CONNECT_PORTS", value_name = "PORT|all", value_delimiter = ',', default_values = ["53", "80", "443", "4433"])]
    pub connect_ports: Vec<ConnectPort>,

    /// Logs statistics for each outer connection to the results directory.
    #[arg(long = "log-stats", default_value_t = false)]
    pub log_stats: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectPort {
    All,
    Port(NonZeroU16),
}

impl FromStr for ConnectPort {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "all" {
            return Ok(Self::All);
        }
        value
            .parse::<NonZeroU16>()
            .map(Self::Port)
            .map_err(|_| "expected 'all' or a port from 1 to 65535")
    }
}

impl ConnectPort {
    pub fn allows(self, port: u16) -> bool {
        port != 0
            && match self {
                Self::All => true,
                Self::Port(allowed) => allowed.get() == port,
            }
    }
}

fn parse_target(value: &str) -> Result<SocketAddr, String> {
    let target: SocketAddr = value.parse().map_err(|error| format!("{error}"))?;
    if target.port() == 0 || target.ip().is_unspecified() || target.ip().is_multicast() {
        return Err("target must be a unicast IP address with a nonzero port".into());
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ports_are_explicit_and_replace_defaults() {
        let Command::Relay(default) = Cli::try_parse_from([
            "nada",
            "relay",
            "--cert",
            "unused-cert",
            "--key",
            "unused-key",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(
            default.connect_ports,
            [53, 80, 443, 4433].map(|port| ConnectPort::Port(NonZeroU16::new(port).unwrap()))
        );
        let Command::Relay(custom) = Cli::try_parse_from([
            "nada",
            "relay",
            "--cert",
            "unused-cert",
            "--key",
            "unused-key",
            "--connect-port",
            "53",
            "--connect-port",
            "8443",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(
            custom.connect_ports,
            [53, 8443].map(|port| ConnectPort::Port(NonZeroU16::new(port).unwrap()))
        );
        let Command::Relay(comma_separated) = Cli::try_parse_from([
            "nada",
            "relay",
            "--cert",
            "unused-cert",
            "--key",
            "unused-key",
            "--connect-port",
            "53,8443",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(comma_separated.connect_ports, custom.connect_ports);
        for port in [
            "0",
            "65536",
            "-1",
            "53,0",
            "53,65536",
            "53,invalid",
            "*",
            "1-65535",
        ] {
            assert!(Cli::try_parse_from([
                "nada",
                "relay",
                "--cert",
                "unused-cert",
                "--key",
                "unused-key",
                "--connect-port",
                port,
            ])
            .is_err());
        }
    }

    #[test]
    fn relay_all_ports_and_explicit_overrides() {
        let Command::Relay(all) = Cli::try_parse_from([
            "nada",
            "relay",
            "--cert",
            "unused-cert",
            "--key",
            "unused-key",
            "--connect-port",
            "all",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(all.connect_ports, [ConnectPort::All]);
        for port in 1..=u16::MAX {
            assert!(all.connect_ports.iter().any(|rule| rule.allows(port)));
        }
        assert!(!ConnectPort::All.allows(0));

        let Command::Relay(restricted) = Cli::try_parse_from([
            "nada",
            "relay",
            "--cert",
            "unused-cert",
            "--key",
            "unused-key",
            "--connect-port",
            "443",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(
            restricted.connect_ports,
            [ConnectPort::Port(NonZeroU16::new(443).unwrap())]
        );
        assert!(restricted.connect_ports[0].allows(443));
        assert!(!restricted.connect_ports[0].allows(4432));
    }

    #[test]
    fn tcp_listeners_are_dual_stack_and_explicit_overrides_replace_both_defaults() {
        assert!(Cli::try_parse_from(["nada", "connect"]).is_err());
        for target in ["1.1.1.1:53", "[2606:4700:4700::1111]:53"] {
            let Command::Connect(args) =
                Cli::try_parse_from(["nada", "connect", "--target", target])
                    .unwrap()
                    .command
            else {
                panic!()
            };
            assert_eq!(
                args.listen,
                vec![
                    "[::1]:18018".parse::<SocketAddr>().unwrap(),
                    "127.0.0.1:18018".parse().unwrap()
                ]
            );
            assert_eq!(args.target, target.parse().unwrap());
            assert!(args.connection.relay_address.is_ipv6());
            let Command::Connect(args) = Cli::try_parse_from([
                "nada",
                "connect",
                "--target",
                target,
                "--listen",
                "127.0.0.1:18018",
                "--reliable",
            ])
            .unwrap()
            .command
            else {
                panic!()
            };
            assert_eq!(args.listen.len(), 1);
            assert!(args.listen[0].is_ipv4());
        }
        for target in ["1.1.1.1:0", "0.0.0.0:53", "224.0.0.1:53"] {
            assert!(Cli::try_parse_from(["nada", "connect", "--target", target]).is_err());
        }
        for option in [
            "--max-tunnels",
            "--tunnel-idle-timeout",
            "--connect-timeout",
        ] {
            assert!(Cli::try_parse_from([
                "nada",
                "connect",
                "--target",
                "1.1.1.1:53",
                option,
                "0"
            ])
            .is_err());
        }
    }

    #[test]
    fn listener_target_and_relay_families_are_independent() {
        assert!(Cli::try_parse_from(["nada", "connect-udp"]).is_err());
        for target in ["1.1.1.1:53", "[2606:4700:4700::1111]:53"] {
            for relay in [DEFAULT_RELAY_ADDRESS, "192.0.2.1:4431"] {
                let Command::ConnectUdp(args) = Cli::try_parse_from([
                    "nada",
                    "connect-udp",
                    "--target",
                    target,
                    "--relay-address",
                    relay,
                ])
                .unwrap()
                .command
                else {
                    panic!()
                };
                assert_eq!(args.target, target.parse::<SocketAddr>().unwrap());
                assert_eq!(
                    args.connection.relay_address,
                    relay.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    args.listen,
                    vec![
                        "[::1]:18018".parse::<SocketAddr>().unwrap(),
                        "127.0.0.1:18018".parse::<SocketAddr>().unwrap(),
                    ]
                );
                assert!(!args.connection.reliable);
                assert!(args.connection.client_address.is_none());
            }
        }
    }

    #[test]
    fn listen_overrides_and_sending_modes() {
        for address in ["127.0.0.1:18018", "[::1]:18018"] {
            let Command::ConnectUdp(args) = Cli::try_parse_from([
                "nada",
                "connect-udp",
                "--target",
                "1.1.1.1:53",
                "--listen",
                address,
            ])
            .unwrap()
            .command
            else {
                panic!()
            };
            assert_eq!(args.listen, vec![address.parse::<SocketAddr>().unwrap()]);
            assert_eq!(
                args.connection.relay_address,
                DEFAULT_RELAY_ADDRESS.parse::<SocketAddr>().unwrap()
            );
        }

        let Command::ConnectUdp(args) = Cli::try_parse_from([
            "nada",
            "connect-udp",
            "--target",
            "1.1.1.1:53",
            "--listen",
            "127.0.0.1:18018",
            "--listen",
            "[::1]:18018",
            "--relay-address",
            "127.0.0.1:4431",
            "--reliable",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(
            args.listen,
            vec![
                "127.0.0.1:18018".parse::<SocketAddr>().unwrap(),
                "[::1]:18018".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert!(args.connection.reliable);
        let Command::Relay(args) = Cli::try_parse_from([
            "nada",
            "relay",
            "--cert",
            "unused-cert",
            "--key",
            "unused-key",
            "--reliable",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert!(args.reliable);
        assert_eq!(
            args.listen,
            DEFAULT_RELAY_ADDRESS.parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn obsolete_modes_and_invalid_limits_are_rejected() {
        assert!(Cli::try_parse_from(["nada", "client"]).is_err());
        for option in ["--control-socket", "--priority", "--transparent"] {
            assert!(Cli::try_parse_from([
                "nada",
                "connect-udp",
                "--target",
                "1.1.1.1:53",
                option,
                "unused"
            ])
            .is_err());
        }
        for option in [
            "--connect-timeout",
            "--tunnel-idle-timeout",
            "--max-tunnels",
        ] {
            assert!(Cli::try_parse_from([
                "nada",
                "connect-udp",
                "--target",
                "1.1.1.1:53",
                option,
                "0"
            ])
            .is_err());
        }
        assert!(Cli::try_parse_from([
            "nada",
            "connect-udp",
            "--target",
            "1.1.1.1:53",
            "--max-tunnels",
            "1001"
        ])
        .is_err());
    }

    #[test]
    fn rejects_invalid_targets_before_connecting() {
        for target in [
            "invalid",
            "1.1.1.1",
            "1.1.1.1:0",
            "0.0.0.0:53",
            "[::]:53",
            "224.0.0.1:53",
            "[ff02::1]:53",
        ] {
            assert!(Cli::try_parse_from(["nada", "connect-udp", "--target", target]).is_err());
        }
    }
}
