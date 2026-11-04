use crate::{CONTEXT_ID_VARINT_LEN, UDP_PAYLOAD_CONTEXT_ID};
use octets::{Octets, OctetsMut};
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::quiche::BufFactory as _;

/// Encodes a UDP payload as an HTTP Datagram with Context ID 0 (RFC 9298, Section 5).
/// tokio-quiche prepends the Quarter Stream ID (RFC 9297, Section 2.1).
pub fn relayed_dgram(quarter_stream_id: u64, udp_payload: &[u8]) -> OutboundFrame {
    let mut dgram = vec![0u8; udp_payload.len() + CONTEXT_ID_VARINT_LEN];
    let mut octets = OctetsMut::with_slice(&mut dgram);

    octets
        .put_varint(UDP_PAYLOAD_CONTEXT_ID)
        .expect("Failed to write the context ID as a varint");

    octets
        .put_bytes(udp_payload)
        .expect("Failed to write the UDP payload");

    let written = octets.off();

    OutboundFrame::Datagram(
        BufFactory::dgram_buf_from_slice(&dgram[..written]),
        quarter_stream_id,
    )
}

/// Decode a context ID. Unknown contexts are ignored, malformed IDs are errors.
pub fn decode_dgram(datagram: &[u8]) -> std::io::Result<Option<&[u8]>> {
    let mut input = Octets::with_slice(datagram);
    let context = input.get_varint().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing or truncated datagram context ID",
        )
    })?;
    Ok((context == UDP_PAYLOAD_CONTEXT_ID).then(|| &datagram[input.off()..]))
}
