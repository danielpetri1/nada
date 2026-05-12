use crate::helpers::sfv_bool;
use crate::{CONTEXT_ID_VARINT_LEN, UDP_PAYLOAD_CONTEXT_ID};
use foundations::telemetry::log;
use octets::{varint_len, varint_parse_len, Octets, OctetsMut};
use std::collections::VecDeque;
use quiche::BufFactory as _;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::OutboundFrame;

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
    let capsule_capacity = DGRAM_CAPSULE_TYPE_LEN
        + payload_len_varint_size
        + http_datagram_payload_len;
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

/// Extract UDP payload from a complete datagram capsule value.
fn extract_udp_from_datagram_capsule(capsule_value: &[u8]) -> Option<Vec<u8>> {
    let mut o = Octets::with_slice(capsule_value);

    // Read context ID
    if let Ok(ctx_id) = o.get_varint() {
        if ctx_id == UDP_PAYLOAD_CONTEXT_ID {
            let udp_start = o.off();

            return Some(capsule_value[udp_start..].to_vec());
        } else {
            panic!("Unkown context ID");
        }
    }

    None
}

/// Validates that a capsule protocol value is correct, i.e., either true or false as an sfv.
pub fn sfv_bool_from_header(capsule_protocol: Option<Vec<u8>>) -> Vec<u8> {
    match capsule_protocol {
        Some(value) if value == sfv_bool(true).as_bytes() => value,
        _ => sfv_bool(false).as_bytes().to_vec(),
    }
}

/// State machine for parsing capsules from streams.
/// Format: RFC 9297, Section 3.2.
#[derive(Debug)]
enum PartialCapsule {
    /// Reading the capsule type (varint)
    Type,
    /// Reading the capsule length (varint)
    Length {
        partial_buf: [u8; MAX_VARINT_SIZE_BYTES],
        partial_written: usize,
    },
    /// Reading the capsule value (bytes)
    Value {
        partial_buf: Vec<u8>,
        partial_written: usize,
    },
}

/// Parses a capsule carried over HTTP DATA frames.
/// Partial capsules may be split across multiple body chunks.
pub struct CapsuleDeframer {
    state: PartialCapsule,
    /// Queue of fully parsed UDP payloads
    udp_payloads: VecDeque<Vec<u8>>,
}

impl CapsuleDeframer {
    pub fn new() -> Self {
        Self {
            state: PartialCapsule::Type,
            udp_payloads: VecDeque::new(),
        }
    }

    /// Feed new data into the deframer.
    /// Note that the body may contain multiple capsules.
    pub fn feed(&mut self, new_data: &[u8]) {
        let mut data_index = 0;

        log::trace!("New body data: {} bytes", new_data.len());
        while data_index < new_data.len() {
            match &mut self.state {
                PartialCapsule::Type => {
                    // We are assuming the following invariants here:
                    // - at least 1B of space is available here
                    // - data index is pointing to a Type value
                    // - only datagram capsules are supported

                    // Try to parse the varint
                    if let (Some(capsule_type), consumed) = Self::try_parse_varint(
                        &new_data
                            [data_index..data_index + DGRAM_CAPSULE_TYPE_LEN],
                    ) {
                        if capsule_type == CAPSULE_TYPE_DATAGRAM {
                            log::trace!(
                                "Parsed capsule type: {} ({}B varint)",
                                capsule_type,
                                consumed
                            );
                            // Advance the data index by the real number of new bytes consumed
                            data_index += consumed;
                            self.state = PartialCapsule::Length {
                                partial_buf: [0; MAX_VARINT_SIZE_BYTES],
                                partial_written: 0,
                            };
                        } else {
                            panic!("Unsupported capsule type: {}", capsule_type);
                        }
                    } else {
                        panic!("Invariant broken: failed to parse a varint");
                    }
                }

                PartialCapsule::Length {
                    partial_buf,
                    partial_written,
                } => {
                    let prev_written = *partial_written;
                    let max_still_needed = MAX_VARINT_SIZE_BYTES - prev_written;
                    let unparsed = new_data.len() - data_index;
                    let new_length_bytes = max_still_needed.min(unparsed);
                    let total_length_bytes = prev_written + new_length_bytes;

                    // Store the bytes in case they are needed later.
                    partial_buf[prev_written..total_length_bytes]
                        .copy_from_slice(
                            &new_data[data_index..data_index + new_length_bytes],
                        );

                    // Try to parse the varint
                    if let (Some(l), consumed) =
                        Self::try_parse_varint(&partial_buf[..total_length_bytes])
                    {
                        let length = l as usize;

                        log::trace!(
                            "Parsed capsule length: {} ({}B varint)",
                            length,
                            consumed
                        );

                        // Advance the data index by the real number of new bytes consumed
                        // The data index resets once new data arrives,
                        // so the difference states how many of those bytes are new.
                        data_index += consumed
                            .checked_sub(prev_written)
                            .expect("Underflow: wrote more Length varint bytes than consumed");

                        self.state = PartialCapsule::Value {
                            partial_buf: vec![0u8; length],
                            partial_written: 0,
                        };
                    } else {
                        // Failed to parse as the data is incomplete.
                        // Available data is stored in the partial_buf for the next iterations.
                        // So we update the state and wait for more data.
                        log::trace!("Length field was not fully available");

                        self.state = PartialCapsule::Length {
                            partial_buf: *partial_buf,
                            partial_written: total_length_bytes,
                        };

                        break;
                    }
                }

                PartialCapsule::Value {
                    partial_buf,
                    partial_written,
                } => {
                    // Read the capsule value
                    let length = partial_buf.len();
                    let max_still_needed = length - *partial_written;
                    let unparsed = new_data.len() - data_index;
                    let new_value_bytes = max_still_needed.min(unparsed);

                    // Store the bytes in case they are needed later.
                    partial_buf
                        [*partial_written..*partial_written + new_value_bytes]
                        .copy_from_slice(
                            &new_data[data_index..data_index + new_value_bytes],
                        );

                    let p_written = *partial_written + new_value_bytes;

                    // If we have the complete value, process it
                    if p_written == length {
                        if let Some(udp_payload) =
                            extract_udp_from_datagram_capsule(partial_buf)
                        {
                            // Advance by the new bytes consumed should more capsules follow
                            data_index += new_value_bytes;
                            self.udp_payloads.push_back(udp_payload);
                        } else {
                            panic!("Failed to extract UDP payload from datagram capsule");
                        }

                        // Move to reading the type of the next capsule
                        self.state = PartialCapsule::Type;
                    } else if p_written > length {
                        panic!("Read beyond the capsule's value");
                    } else {
                        log::trace!("Capsule value not fully parsed yet");

                        self.state = PartialCapsule::Value {
                            partial_buf: std::mem::take(partial_buf),
                            partial_written: p_written,
                        };

                        break;
                    }
                }
            }
        }
    }

    /// Try to parse a varint from the buffer.
    /// Returns (Some(u64), len(varint) if successful, (None, 0) if more bytes are needed.
    fn try_parse_varint(buf: &[u8]) -> (Option<u64>, usize) {
        if buf.is_empty() || buf.len() < varint_parse_len(buf[0]) {
            return (None, 0);
        }

        let mut o = Octets::with_slice(buf);
        (o.get_varint().ok(), o.off())
    }

    /// Pop the next complete UDP payload, if available.
    pub fn pop_udp_payload(&mut self) -> Option<Vec<u8>> {
        self.udp_payloads.pop_front()
    }
}

impl Default for CapsuleDeframer {
    fn default() -> Self {
        Self::new()
    }
}
