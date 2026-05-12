use sfv::{BareItem, FieldType, Item};

/// Extracts the destination address from a MASQUE URI
/// Expected format: /.well-known/masque/udp/{ip}/{port}
pub fn dest_addr_from_masque_uri(target_path: &[u8]) -> Option<(String, String)> {
    let path_str = str::from_utf8(target_path).ok()?;
    let parts: Vec<&str> = path_str.split('/').collect();

    match parts.as_slice() {
        ["", ".well-known", "masque", "udp", ip, port, ..] => {
            Some((ip.to_string(), port.to_string()))
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

/// Returns the quarter stream id for a given request stream id.
pub fn flow_id_from_stream_id(stream_id: u64) -> u64 {
    stream_id / 4
}
