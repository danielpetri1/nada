use crate::{CONTEXT_ID_VARINT_LEN, UDP_PAYLOAD_CONTEXT_ID};
use octets::{varint_len, Octets, OctetsMut};
use std::collections::VecDeque;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::quiche::BufFactory as _;

/// See RFC 9297, Section 3.5.
pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;
pub const DGRAM_CAPSULE_TYPE_LEN: usize = varint_len(CAPSULE_TYPE_DATAGRAM);
pub const MAX_VARINT_SIZE_BYTES: usize = 8;

/// Build a Datagram Capsule that carries a UDP payload
pub fn dgram_capsule_from_udp_payload(udp_payload: &[u8]) -> OutboundFrame {
    // Calculate sizes upfront
    // HTTP Datagram Payload = Context ID + UDP payload
    let http_datagram_payload_len = CONTEXT_ID_VARINT_LEN + udp_payload.len();
    let payload_len_varint_size = varint_len(http_datagram_payload_len as u64);

    // Capsule = Type (CAPSULE_TYPE_DATAGRAM) + Length + HTTP Datagram Payload
    let capsule_capacity =
        DGRAM_CAPSULE_TYPE_LEN + payload_len_varint_size + http_datagram_payload_len;
    let mut capsule = vec![0u8; capsule_capacity];
    let mut o = OctetsMut::with_slice(&mut capsule);

    // Write capsule type
    o.put_varint(CAPSULE_TYPE_DATAGRAM)
        .expect("failed to write Datagram capsule type");

    // Write capsule length
    o.put_varint(http_datagram_payload_len as u64)
        .expect("failed to write Datagram capsule length");

    // Write HTTP Datagram Payload directly (Context ID + UDP payload)
    o.put_varint(UDP_PAYLOAD_CONTEXT_ID)
        .expect("failed to write context ID");
    o.put_bytes(udp_payload)
        .expect("failed to write UDP payload");

    let written = o.off();

    OutboundFrame::Body(BufFactory::buf_from_slice(&capsule[..written]), false)
}

/// Incrementally decodes capsules, preserving UDP message boundaries.
/// Unknown capsule types/context IDs are skipped.
#[derive(Default)]
pub struct CapsuleDeframer {
    buffer: Vec<u8>,
    skip: u64,
    udp_payloads: VecDeque<Vec<u8>>,
}

impl CapsuleDeframer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, new_data: &[u8]) -> std::io::Result<()> {
        // Limit temporary buffering even for large stream chunks.
        for chunk in new_data.chunks(4096) {
            self.buffer.extend_from_slice(chunk);
            loop {
                if self.skip != 0 {
                    let n = self.skip.min(self.buffer.len() as u64) as usize;
                    self.buffer.drain(..n);
                    self.skip -= n as u64;
                    if self.skip != 0 {
                        break;
                    }
                }
                let mut input = Octets::with_slice(&self.buffer);
                let Ok(kind) = input.get_varint() else {
                    break;
                };
                let Ok(length) = input.get_varint() else {
                    break;
                };
                let header_len = input.off();
                if kind != CAPSULE_TYPE_DATAGRAM {
                    self.buffer.drain(..header_len);
                    self.skip = length;
                    continue;
                }
                // Allow an 8-byte context ID as well as the maximum UDP payload.
                if length > (crate::tunnel::MAX_UDP_PAYLOAD + MAX_VARINT_SIZE_BYTES) as u64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "datagram capsule exceeds UDP payload limit",
                    ));
                }
                let end = header_len + length as usize;
                if self.buffer.len() < end {
                    break;
                }
                if let Some(payload) = crate::dgrams::decode_dgram(&self.buffer[header_len..end])? {
                    if payload.len() > crate::tunnel::MAX_UDP_PAYLOAD {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "UDP payload exceeds limit",
                        ));
                    }
                    self.udp_payloads.push_back(payload.to_vec());
                }
                self.buffer.drain(..end);
            }
        }
        Ok(())
    }

    pub fn finish(&self) -> std::io::Result<()> {
        if self.buffer.is_empty() && self.skip == 0 {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated capsule",
            ))
        }
    }

    pub fn pop_udp_payload(&mut self) -> Option<Vec<u8>> {
        self.udp_payloads.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule(payload: &[u8]) -> Vec<u8> {
        match dgram_capsule_from_udp_payload(payload) {
            OutboundFrame::Body(bytes, _) => bytes.to_vec(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn fragmented_and_coalesced_capsules_preserve_empty_and_binary_payloads() {
        let expected = [
            vec![],
            vec![0, 255, 128],
            vec![42; crate::tunnel::MAX_UDP_PAYLOAD],
        ];
        let bytes: Vec<u8> = expected.iter().flat_map(|p| capsule(p)).collect();
        for chunk_size in [1, 2, 7, bytes.len()] {
            let mut decoder = CapsuleDeframer::new();
            for chunk in bytes.chunks(chunk_size) {
                decoder.feed(chunk).unwrap();
            }
            decoder.finish().unwrap();
            for payload in &expected {
                assert_eq!(decoder.pop_udp_payload().as_ref(), Some(payload));
            }
            assert!(decoder.pop_udp_payload().is_none());
        }
    }

    #[test]
    fn skips_unknown_capsules_and_contexts_and_rejects_malformed_input() {
        let mut bytes = vec![0x40, 0x25, 3, 1, 2, 3]; // unknown two-byte capsule type
        bytes.extend_from_slice(&[0, 2, 7, 99]); // unknown context ID
        bytes.extend_from_slice(&capsule(b"valid"));
        let mut decoder = CapsuleDeframer::new();
        for byte in bytes {
            decoder.feed(&[byte]).unwrap();
        }
        assert_eq!(decoder.pop_udp_payload().unwrap(), b"valid");
        assert!(decoder.pop_udp_payload().is_none());
        decoder.finish().unwrap();
        assert!(CapsuleDeframer::new().feed(&[0, 0]).is_err());
        let mut truncated = CapsuleDeframer::new();
        truncated.feed(&[0, 3, 0, 42]).unwrap();
        assert!(truncated.finish().is_err());
        // Declared payload is 2^30-1 bytes: reject without allocating it.
        assert!(CapsuleDeframer::new()
            .feed(&[0, 0xbf, 0xff, 0xff, 0xff])
            .is_err());
    }
}
