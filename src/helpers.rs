use sfv::{BareItem, FieldType, Item};
use std::net::SocketAddr;

/// Expands the CONNECT-UDP URI template, percent-encoding IPv6 colons.
pub fn connect_udp_path(target: SocketAddr) -> String {
    let host = target.ip().to_string().replace(':', "%3A");
    format!("/.well-known/masque/udp/{host}/{}/", target.port())
}

pub fn dest_addr_from_masque_uri(target_path: &[u8]) -> Option<SocketAddr> {
    let path_str = str::from_utf8(target_path).ok()?;
    let parts: Vec<&str> = path_str
        .strip_suffix('/')
        .unwrap_or(path_str)
        .split('/')
        .collect();

    match parts.as_slice() {
        ["", ".well-known", "masque", "udp", ip, port] => {
            let ip = ip.replace("%3A", ":").replace("%3a", ":");
            let port = port.parse().ok()?;
            if port == 0 {
                return None;
            }
            Some(SocketAddr::new(ip.parse().ok()?, port))
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
}
