//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded, owned-byte frames for test oracles in separate Unix processes.
//!
//! The `test-oracle` feature enables this transport for GPL tests that exercise
//! an Apache host API through a separate executable. Each connection starts
//! with a `Ready` response using request ID zero. Other requests use nonzero
//! IDs and receive a success or failure frame with the same operation and ID.
//! Integers use big-endian encoding; reserved bytes must be zero.
//!
//! ```text
//! offset  size  field
//! 0       4     magic: CQTO
//! 4       2     version: 2 (v1 peers are rejected)
//! 6       2     kind: request=0, success=1, failure=2
//! 8       8     request ID
//! 16      2     operation: ready=0, status=1, reconnect=2, promote=3, shutdown=4, engine=5
//! 18      2     reserved: 0
//! 20      4     payload length: at most 65536 bytes
//! 24      N     owned payload bytes
//! ```
//!
//! `Ready` carries a Unix control path, one NUL separator, and an optional
//! UTF-8 operator endpoint. `BackendStatus` returns the existing debugger
//! gateway status codec. `PromoteBackend` takes raw Unix path bytes and returns
//! an eight-byte generation. `Shutdown` returns a four-byte Linux wait status.
//! `BackendStatus`, `Reconnect`, and `Shutdown` requests have empty payloads.
//! A successful `Reconnect` also has an empty payload. Failure payloads contain
//! UTF-8 errors.
//! Engine mode announces the exact bytes `engine-v2` and accepts only `Engine`
//! requests. Gateway mode rejects `Engine`; engine mode rejects gateway methods.
//! Engine payloads are UTF-8 JSON objects. Their closed `operation` registry is:
//!
//! ```text
//! operation      remaining request fields                  successful response
//! rng-init       seed:u64, stream:string                   {root_seed:u64}
//! rng-next       advance:u64 (at most 1000000)              {draw:u64}
//! marker         node:string, icount:u64, frame:bytes       event-log projection
//! diagnostic     node:string, icount:u64, marker:string     event-log projection
//! sim-create     slot:u32, nodes:u32, capacity:u32, steps   {node_count:u32, region_size:u64}
//! sim-control    frame:bytes                               {reply:null|bytes}
//! sim-inbound    source:u32, sequence:u32, icount:u64,       {}
//!                payload:bytes
//! sim-advance    horizon:u64, authorization:"allow-all",    outcome projection
//!                topology_epoch:u64
//! sim-schedule                                             {events:[schedule projections]}
//! ```
//!
//! A byte string is an array of integers in `0..=255`. Unknown or missing
//! request fields are errors. One connection owns one RNG, one event log and
//! one simulation double. Reinitialization replaces only the selected object.
//! `rng-next` advances the real stream before drawing. `marker.frame` uses the
//! existing permissive white-box marker frame codec. Geometry is bounded to
//! 16 VM nodes and queue capacity 4096 before the engine allocates its region.
//! Each step is `{budget:u64, frames:[{destination:u32, icount:u64, payload:bytes}]}`.
//!
//! An event-log projection is `{entries:[entry], causal_projection_empty:bool}`.
//! Each entry contains `class` (`causal` or `observational`), `stamp` with
//! `node` (string or null), `tick:u64`, and `retired` (u64 or null), `source`
//! with `kind:"guest"` and `node:string`, and `payload` with `kind:string`
//! and `assertion` (string or null). An unexpected source is an error.
//!
//! An outcome is `{kind:"reached-horizon"}` or `{kind:"paused", at:u64}`.
//! Schedule projections have `kind:"horizon"` with `from`, `requested`,
//! `reached` (all u64) and `outcome`; `kind:"delivery"` with `source:u32`,
//! `sequence:u32`, `icount:u64`, `payload:bytes`; or `kind:"emission"` with
//! `destination:u32` and the same sequence, icount and payload fields.
//! Other schedule variants fail closed until their wire schema is defined.
//! JSON is a value projection, never serialization of an engine-native object.
//!
//! Version 2 deliberately rejects version 1 peers; its callers and immutable
//! helper are rebuilt together. No frame contains a native pointer, Rust enum
//! representation, private structure, or callback.

use std::io::{self, Read, Write};

/// Maximum owned payload accepted by the test-oracle transport.
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

const HEADER_BYTES: usize = 24;
const VERSION: u16 = 2;

/// Meaning of a test-oracle frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum FrameKind {
    /// Request sent to the oracle.
    Request = 0,
    /// Successful operation result.
    Success = 1,
    /// Failed operation with a UTF-8 diagnostic payload.
    Failure = 2,
}

/// Closed operation registry for the test-oracle protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Operation {
    /// Initial control-path and operator-endpoint announcement.
    Ready = 0,
    /// Actual debugger gateway backend status.
    BackendStatus = 1,
    /// Reconnection through the Apache client.
    Reconnect = 2,
    /// Actual backend preparation and promotion through the Apache client.
    PromoteBackend = 3,
    /// Gateway termination and reaping through the Apache client.
    Shutdown = 4,
    /// Parameterized engine operations with the documented JSON value schema.
    Engine = 5,
}

/// Versioned test-oracle message containing only portable values and bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// Whether the frame requests an operation or returns its result.
    pub kind: FrameKind,
    /// Operation whose payload schema applies.
    pub operation: Operation,
    /// Connection-local request identity; zero is reserved for `Ready`.
    pub request_id: u64,
    /// Owned operation payload bounded by [`MAX_PAYLOAD_BYTES`].
    pub payload: Vec<u8>,
}

impl Frame {
    fn validate(&self) -> io::Result<()> {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid("test-oracle payload exceeds its limit"));
        }
        if self.operation == Operation::Ready {
            if self.kind == FrameKind::Request || self.request_id != 0 {
                return Err(invalid("test-oracle Ready must be an unsolicited response"));
            }
        } else if self.request_id == 0 {
            return Err(invalid(
                "test-oracle operation requires a nonzero request ID",
            ));
        }
        Ok(())
    }
}

/// Writes a validated test-oracle frame and flushes its transport.
///
/// # Errors
///
/// Returns an error for an oversized payload, invalid request identity or
/// `Ready` kind, or an underlying write or flush failure. Validation finishes
/// before any frame bytes are written.
pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> io::Result<()> {
    frame.validate()?;
    let length = u32::try_from(frame.payload.len())
        .map_err(|_| invalid("test-oracle payload cannot be represented"))?;
    let mut header = [0; HEADER_BYTES];
    header[..4].copy_from_slice(b"CQTO");
    header[4..6].copy_from_slice(&VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&(frame.kind as u16).to_be_bytes());
    header[8..16].copy_from_slice(&frame.request_id.to_be_bytes());
    header[16..18].copy_from_slice(&(frame.operation as u16).to_be_bytes());
    header[20..24].copy_from_slice(&length.to_be_bytes());

    writer.write_all(&header)?;
    writer.write_all(&frame.payload)?;
    writer.flush()
}

/// Reads one validated frame, returning `None` only at a clean frame boundary.
///
/// # Errors
///
/// Returns an error for a truncated frame, unsupported magic or version, an
/// unknown kind or operation, nonzero reserved bytes, an invalid request ID,
/// an oversized payload, or an underlying read failure. The payload length is
/// checked before allocation.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Frame>> {
    let mut header = [0; HEADER_BYTES];
    // Preserve read_exact's interruption handling while distinguishing clean EOF.
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut header[1..])?;
    if &header[..4] != b"CQTO" || u16::from_be_bytes(array(&header[4..6])?) != VERSION {
        return Err(invalid("unsupported test-oracle magic or version"));
    }
    if header[18..20] != [0, 0] {
        return Err(invalid("test-oracle reserved bytes must be zero"));
    }

    let kind = match u16::from_be_bytes(array(&header[6..8])?) {
        0 => FrameKind::Request,
        1 => FrameKind::Success,
        2 => FrameKind::Failure,
        _ => return Err(invalid("unknown test-oracle frame kind")),
    };
    let operation = match u16::from_be_bytes(array(&header[16..18])?) {
        0 => Operation::Ready,
        1 => Operation::BackendStatus,
        2 => Operation::Reconnect,
        3 => Operation::PromoteBackend,
        4 => Operation::Shutdown,
        5 => Operation::Engine,
        _ => return Err(invalid("unknown test-oracle operation")),
    };
    let length = usize::try_from(u32::from_be_bytes(array(&header[20..24])?))
        .map_err(|_| invalid("test-oracle payload cannot fit this platform"))?;
    if length > MAX_PAYLOAD_BYTES {
        return Err(invalid("test-oracle payload exceeds its limit"));
    }
    let mut frame = Frame {
        kind,
        operation,
        request_id: u64::from_be_bytes(array(&header[8..16])?),
        payload: Vec::new(),
    };
    frame.validate()?;
    frame.payload.resize(length, 0);
    reader.read_exact(&mut frame.payload)?;
    Ok(Some(frame))
}

fn array<const N: usize>(bytes: &[u8]) -> io::Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| invalid("invalid test-oracle integer width"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Framing conformance assertions panic on unexpected codec results.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn request(payload: Vec<u8>) -> Frame {
        Frame {
            kind: FrameKind::Request,
            operation: Operation::PromoteBackend,
            request_id: 7,
            payload,
        }
    }

    fn encoded(frame: &Frame) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, frame).unwrap();
        bytes
    }

    #[test]
    fn frame_matches_the_frozen_network_byte_order_vector() {
        let frame = request(b"a\0b".to_vec());
        let bytes = encoded(&frame);
        // Keep the frozen wire fields separate when reviewing protocol changes.
        #[rustfmt::skip]
        let expected = [
            // Magic, version, request kind.
            b'C', b'Q', b'T', b'O', 0, 2, 0, 0,

            // Request ID seven.
            0, 0, 0, 0, 0, 0, 0, 7,

            // PromoteBackend, reserved zero, three payload bytes.
            0, 3, 0, 0, 0, 0, 0, 3,

            // Owned payload.
            b'a', 0, b'b',
        ];

        assert_eq!(bytes, expected);
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(frame));
    }

    #[test]
    fn owned_payload_preserves_every_byte_and_the_maximum_length() {
        for payload in [(0..=u8::MAX).collect(), vec![0xff; MAX_PAYLOAD_BYTES]] {
            let frame = request(payload);
            assert_eq!(
                read_frame(&mut encoded(&frame).as_slice()).unwrap(),
                Some(frame)
            );
        }
    }

    #[test]
    fn clean_eof_is_distinct_from_a_truncated_header_or_payload() {
        assert_eq!(read_frame(&mut [].as_slice()).unwrap(), None);
        let bytes = encoded(&request(vec![1, 2]));
        for length in 1..bytes.len() {
            assert_eq!(
                read_frame(&mut &bytes[..length]).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[test]
    fn interrupted_and_fragmented_streams_preserve_the_frame() {
        struct Fragmented {
            interrupt: bool,
            bytes: io::Cursor<Vec<u8>>,
        }

        impl Read for Fragmented {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.interrupt {
                    self.interrupt = false;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let length = buffer.len().min(2);
                self.bytes.read(&mut buffer[..length])
            }
        }

        let frame = request(vec![1, 2, 3]);
        let mut reader = Fragmented {
            interrupt: true,
            bytes: io::Cursor::new(encoded(&frame)),
        };

        assert_eq!(read_frame(&mut reader).unwrap(), Some(frame));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn unknown_header_fields_and_reserved_bytes_are_rejected() {
        for (index, value) in [(0, b'X'), (5, 1), (5, 3), (7, 9), (17, 99), (19, 1)] {
            let mut bytes = encoded(&request(Vec::new()));
            bytes[index] = value;
            assert_eq!(
                read_frame(&mut bytes.as_slice()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn oversized_frames_are_rejected_before_reading_or_writing_payloads() {
        let mut bytes = encoded(&request(Vec::new()));
        bytes[20..24].copy_from_slice(&65_537_u32.to_be_bytes());
        assert_eq!(
            read_frame(&mut bytes.as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut output = Vec::new();
        assert!(write_frame(&mut output, &request(vec![0; MAX_PAYLOAD_BYTES + 1])).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn ready_and_request_id_rules_are_enforced_in_both_directions() {
        let ready = Frame {
            kind: FrameKind::Success,
            operation: Operation::Ready,
            request_id: 0,
            payload: b"socket\0".to_vec(),
        };
        assert_eq!(
            read_frame(&mut encoded(&ready).as_slice()).unwrap(),
            Some(ready.clone())
        );

        for (index, value) in [(7, 0), (15, 1)] {
            let mut bytes = encoded(&ready);
            bytes[index] = value;
            assert_eq!(
                read_frame(&mut bytes.as_slice()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }

        for frame in [
            Frame {
                kind: FrameKind::Request,
                ..ready.clone()
            },
            Frame {
                request_id: 1,
                ..ready
            },
            Frame {
                request_id: 0,
                ..request(Vec::new())
            },
        ] {
            assert!(write_frame(&mut Vec::new(), &frame).is_err());
        }
        let mut bytes = encoded(&request(Vec::new()));
        bytes[8..16].fill(0);
        assert_eq!(
            read_frame(&mut bytes.as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
