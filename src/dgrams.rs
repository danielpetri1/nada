use crate::{CONTEXT_ID_VARINT_LEN, UDP_PAYLOAD_CONTEXT_ID};
use octets::OctetsMut;
use quiche::BufFactory as _;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::OutboundFrame;

/// Produces an HTTP/3 datagram starting with a context ID of 0 (i.e., for UDP payloads).
/// tokio-quiche ensures the context ID is preceded by the flow ID (quarter stream ID).
/// See RFC 9298, Section 4.
pub fn proxied_dgram(flow_id: u64, udp_payload: &[u8]) -> OutboundFrame {
    let mut dgram = vec![0u8; udp_payload.len() + CONTEXT_ID_VARINT_LEN];
    let mut octets = OctetsMut::with_slice(&mut dgram);

    octets
        .put_varint(UDP_PAYLOAD_CONTEXT_ID)
        .expect("Failed to write the context ID as a varint");

    octets
        .put_bytes(udp_payload)
        .expect("Failed to write the UDP payload");

    let written = octets.off();

    OutboundFrame::Datagram(BufFactory::dgram_buf_from_slice(&dgram[..written]), flow_id)
}

/// Retrieves the UDP payload from an HTTP/3 datagram starting with a context ID of 0.
pub fn retrieve_dgram(udp_payload: &mut [u8]) -> &mut [u8] {
    let mut octets = OctetsMut::with_slice(udp_payload);

    if octets
        .get_varint()
        .is_ok_and(|ctx_id| ctx_id == UDP_PAYLOAD_CONTEXT_ID)
    {
        let read = octets.off();
        return &mut udp_payload[read..];
    }

    log::warn!("Missing context ID or empty UDP payload");
    udp_payload
}
