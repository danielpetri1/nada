use percent_encoding::percent_decode;
use sfv::{BareItem, FieldType, Item};
use std::net::SocketAddr;

/// Expands the CONNECT-UDP URI template, percent-encoding IPv6 colons.
pub fn connect_udp_path(target: SocketAddr) -> String {
    let host = target.ip().to_string().replace(':', "%3A");
    format!("/.well-known/masque/udp/{host}/{}/", target.port())
}

pub fn dest_addr_from_masque_uri(target_path: &[u8]) -> Option<SocketAddr> {
    match masque_target(target_path)? {
        Destination::Address(address) => Some(address),
        Destination::Hostname { .. } => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Destination {
    Address(SocketAddr),
    Hostname { host: String, port: u16 },
}

impl Destination {
    pub(crate) fn hostname(host: &str, port: u16) -> Option<Self> {
        let name = host.strip_suffix('.').unwrap_or(host);
        if port == 0 || name.len() > 253 {
            return None;
        }
        let valid = name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        valid.then(|| Self::Hostname {
            host: host.to_owned(),
            port,
        })
    }

    pub(crate) fn port(&self) -> u16 {
        match self {
            Self::Address(address) => address.port(),
            Self::Hostname { port, .. } => *port,
        }
    }
}

pub(crate) fn masque_target(target_path: &[u8]) -> Option<Destination> {
    let path_str = str::from_utf8(target_path).ok()?;
    let parts: Vec<&str> = path_str
        .strip_suffix('/')
        .unwrap_or(path_str)
        .split('/')
        .collect();

    match parts.as_slice() {
        ["", ".well-known", "masque", "udp", host, port] => {
            let host = percent_decode(host.as_bytes()).decode_utf8().ok()?;
            let port = port.parse().ok()?;
            if port == 0 {
                return None;
            }
            match host.parse() {
                Ok(ip) => Some(Destination::Address(SocketAddr::new(ip, port))),
                Err(_) => Destination::hostname(&host, port),
            }
        }
        _ => None,
    }
}

/// Serializes a boolean into a Structured Field Value Item
pub fn sfv_bool(enabled: bool) -> String {
    let sfv = Item {
        bare_item: BareItem::Boolean(enabled),
        params: Default::default(),
    };

    sfv.serialize()
}

/// Returns the Quarter Stream ID for a request stream (RFC 9297, Section 2.1).
pub fn quarter_stream_id_from_stream_id(stream_id: u64) -> u64 {
    stream_id / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_targets() {
        for (path, expected) in [
            ("/.well-known/masque/udp/192.0.2.1/443", "192.0.2.1:443"),
            (
                "/.well-known/masque/udp/2001:db8::1/443",
                "[2001:db8::1]:443",
            ),
        ] {
            assert_eq!(
                dest_addr_from_masque_uri(path.as_bytes()),
                Some(expected.parse().unwrap())
            );
        }
    }

    #[test]
    fn rejects_invalid_targets() {
        for path in [
            "/.well-known/masque/udp/invalid/443",
            "/.well-known/masque/udp/192.0.2.1/65536",
            "/.well-known/masque/udp/2001:db8::1/invalid",
            "/.well-known/masque/udp//443",
            "/.well-known/masque/udp/192.0.2.1/",
            "/.well-known/masque/udp/192.0.2.1",
            "/.well-known/masque/udp/192.0.2.1/0",
            "/.well-known/masque/udp/192.0.2.1/443/extra",
        ] {
            assert_eq!(dest_addr_from_masque_uri(path.as_bytes()), None);
        }
    }

    #[test]
    fn uri_template_round_trips_both_address_families() {
        for target in ["192.0.2.1:53", "[2001:db8::1]:53"] {
            let target = target.parse().unwrap();
            let path = connect_udp_path(target);
            assert!(!path.contains(':'));
            assert!(path.ends_with('/'));
            assert_eq!(dest_addr_from_masque_uri(path.as_bytes()), Some(target));
        }
    }

    #[test]
    fn decodes_udp_hostnames_without_accepting_invalid_authority_characters() {
        assert_eq!(
            masque_target(b"/.well-known/masque/udp/a%2Eexample/443/"),
            Some(Destination::Hostname {
                host: "a.example".into(),
                port: 443,
            })
        );
        for host in ["a%2Fexample", "a%40example", "a%ff.example", "a..example"] {
            assert!(
                masque_target(format!("/.well-known/masque/udp/{host}/443/").as_bytes()).is_none()
            );
        }
    }
}
