//! Native journal frame codec, retained partial reads, and append durability.
//!
//! Frames carry a closed kind, sequence, transaction identity, bounded payload,
//! and checksum. The framing layer does not interpret records or authorize
//! transactions. Replay visibility and poisoning remain with the journal owner.
//!
//! ```text
//! AOSJRN01 | version:u16le | kind:u8 | reserved:u8=0 | sequence:u64le |
//! transaction-ID:16 | payload-length:u32le | checksum:32 | payload
//! ```
//!
//! Structural errors and the record-byte bound are independent of domain types.
//! Domain owners preserve their existing error classification through exhaustive
//! adapters; these mechanics do not decode namespaces or admit transitions.

use std::fs::File;
use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

/// Reports structural framing and append failures without domain authority.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// A native read, write, sync, or metadata operation failed.
    #[error("journal I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A serialized width cannot be represented without overflow.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// A frame names a format version this codec does not understand.
    #[error("unsupported journal format version {0}")]
    UnsupportedVersion(u16),
    /// A complete frame's checksum differs at the original byte offset.
    #[error("journal frame checksum mismatch at byte offset {0}")]
    ChecksumMismatch(u64),
    /// A structural frame field violates its existing closed format.
    #[error("malformed journal transaction: {0}")]
    MalformedTransaction(&'static str),
    /// A frame field or payload exceeds its existing representation bound.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// The parser's retained allocation is absent at the original check.
    // Preserve this internal case's legacy classification without authority.
    #[error("protected journal storage boundary is invalid")]
    MissingRetainedPayload,
    /// Sequence space is exhausted and cannot safely wrap.
    #[error("journal sequence space is exhausted")]
    SequenceExhausted,
}

const MAGIC: &[u8; 8] = b"AOSJRN01";
const FORMAT_VERSION: u16 = 1;
/// Specifies the complete native frame header width.
pub const HEADER_BYTES: usize = 72;
/// Specifies the native COMMIT count and digest payload width.
pub const COMMIT_PAYLOAD_BYTES: usize = 36;
/// Specifies the checksum's offset within the native frame header.
pub const CHECKSUM_OFFSET: usize = 40;
/// Bounds one frame reader's fixed payload staging buffer.
pub const FRAME_READ_SCRATCH_BYTES: usize = 64 * 1024;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.journal.transaction.v1\0";
const FRAME_DOMAIN: &[u8] = b"aos.sandbox.journal.frame.v1\0";

/// Identifies the closed native transaction frame cases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    /// Starts a transaction with its declared record count.
    Begin = 1,
    /// Carries one uninterpreted native record payload.
    Record = 2,
    /// Ends a transaction with its count and ordered payload digest.
    Commit = 3,
}

impl FrameKind {
    fn from_byte(value: u8) -> Result<Self, FrameError> {
        match value {
            1 => Ok(Self::Begin),
            2 => Ok(Self::Record),
            3 => Ok(Self::Commit),
            _ => Err(FrameError::MalformedTransaction("unknown frame kind")),
        }
    }
}

/// Carries decoded frame DATA, not committed state or domain authority.
pub struct Frame {
    /// Names the closed frame case.
    pub kind: FrameKind,
    /// Carries the sequence checked by the owning replay engine.
    pub sequence: u64,
    /// Carries the transaction identity supplied to or read from the frame.
    pub transaction_id: [u8; 16],
    /// Owns the payload without interpreting any namespace or record schema.
    pub payload: Vec<u8>,
}

/// Retains the original partial frame allocation on incomplete or failed reads.
pub struct ReadOnlyFrameScratchV1 {
    header: [u8; HEADER_BYTES],
    header_filled: usize,
    payload: Option<Vec<u8>>,
    payload_filled: usize,
}

/// Shares the frame's u32 payload field and complete serialized width.
pub struct EncodedFrameLayout {
    payload_length: u32,
    /// Measures the complete serialized header and payload width.
    pub frame_bytes: usize,
}

impl EncodedFrameLayout {
    /// Computes the checked native frame width without allocating bytes.
    ///
    /// # Errors
    ///
    /// Rejects payloads exceeding u32 or overflowing the complete usize width.
    pub fn new(payload_bytes: usize) -> Result<Self, FrameError> {
        let payload_length = u32::try_from(payload_bytes)
            .map_err(|_| FrameError::LimitExceeded("frame payload bytes"))?;
        let frame_bytes = HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or(FrameError::JournalTooLarge)?;

        Ok(Self {
            payload_length,
            frame_bytes,
        })
    }
}

#[cfg(test)]
fn read_frame<R: Read>(
    file: &mut R,
    offset: u64,
    maximum_record_bytes: usize,
) -> Result<Option<(Frame, u64)>, FrameError> {
    read_frame_retained(file, offset, maximum_record_bytes, None)
}

/// Bounds incremental payload growth and its fixed read scratch as DATA.
///
/// The reader grows only after receiving bytes and caps its requested Vec
/// capacity at the declared payload length. Retained capacity is bounded by
/// twice the reached payload; reallocation may additionally retain the old
/// buffer, bounded by the reached payload. This includes both buffers at that
/// peak, plus the fixed read scratch. A physical-prefix bound may conservatively
/// include header bytes.
///
/// This calculation authenticates neither that prefix nor a receiving payer.
/// It excludes the frame/header owners and all decoded domain representations.
///
/// # Errors
///
/// Returns a representation limit error on checked byte-count overflow.
pub fn reached_frame_read_memory_bound_v1(
    declared_payload_bound: usize,
    reached_payload_bytes: usize,
) -> Result<usize, FrameError> {
    let new_capacity = declared_payload_bound.min(reached_payload_bytes.saturating_mul(2));
    let old_capacity = declared_payload_bound.min(reached_payload_bytes);

    new_capacity
        .checked_add(old_capacity)
        .and_then(|bytes| bytes.checked_add(FRAME_READ_SCRATCH_BYTES))
        .ok_or(FrameError::LimitExceeded("frame read representation bytes"))
}

/// Reads one bounded native frame and retains selected partial scratch.
///
/// EOF returns `None`, including a partial final frame. The decoder checks
/// framing and checksum only; owners separately validate sequence, transaction
/// ordering, typed namespaces, and semantic admission.
///
/// # Errors
///
/// Returns the original I/O, version, structural, checksum, or width error.
/// Selected scratch preserves the exact reached header, payload bytes and
/// payload capacity. An advertised but missing payload never allocates its
/// declared extent; one fixed buffer stages actual reads before Vec growth.
///
/// # Panics
///
/// Panics if capacity needed for actually reached bytes exceeds the platform's
/// Vec allocation limit. Owners retain their allocation and physical backstops.
pub fn read_frame_retained<R: Read>(
    file: &mut R,
    offset: u64,
    maximum_record_bytes: usize,
    scratch: Option<&mut Option<ReadOnlyFrameScratchV1>>,
) -> Result<Option<(Frame, u64)>, FrameError> {
    let mut header = [0_u8; HEADER_BYTES];
    let mut filled = 0_usize;
    let mut payload_original = None;
    let mut payload_filled = 0_usize;
    let outcome = (|| {
        while filled < HEADER_BYTES {
            let read = file.read(&mut header[filled..])?;
            if read == 0 {
                return Ok(None);
            }
            filled += read;
        }
        if &header[..8] != MAGIC {
            return Err(FrameError::MalformedTransaction("invalid frame magic"));
        }
        let version = u16::from_le_bytes([header[8], header[9]]);
        if version != FORMAT_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }
        if header[11] != 0 {
            return Err(FrameError::MalformedTransaction(
                "nonzero reserved frame flags",
            ));
        }
        let kind = FrameKind::from_byte(header[10])?;
        let sequence = u64::from_le_bytes(
            header[12..20]
                .try_into()
                .map_err(|_| FrameError::MalformedTransaction("invalid sequence field"))?,
        );
        let transaction_id = header[20..36]
            .try_into()
            .map_err(|_| FrameError::MalformedTransaction("invalid transaction identity"))?;
        if transaction_id == [0; 16] {
            return Err(FrameError::MalformedTransaction(
                "zero transaction identity",
            ));
        }
        let payload_length = u32::from_le_bytes(
            header[36..40]
                .try_into()
                .map_err(|_| FrameError::MalformedTransaction("invalid payload length"))?,
        ) as usize;
        let maximum_frame_payload = maximum_record_bytes.saturating_add(7);
        if payload_length > maximum_frame_payload {
            return Err(FrameError::LimitExceeded("frame payload bytes"));
        }

        payload_original = Some(Vec::new());
        let payload = payload_original
            .as_mut()
            .ok_or(FrameError::MissingRetainedPayload)?;
        let mut staging = [0_u8; FRAME_READ_SCRATCH_BYTES];
        while payload_filled < payload_length {
            let remaining = payload_length - payload_filled;
            let offered = remaining.min(staging.len());
            let read = file.read(&mut staging[..offered])?;
            if read == 0 {
                return Ok(None);
            }

            // Reserve only reached bytes. Capped doubling avoids quadratic
            // copies on fragmented reads without reserving an advertised tail.
            let reached = payload_filled + read;
            if reached > payload.capacity() {
                let capacity = payload
                    .capacity()
                    .saturating_mul(2)
                    .max(reached)
                    .min(payload_length);
                payload.reserve_exact(capacity - payload.len());
            }
            payload.extend_from_slice(&staging[..read]);
            payload_filled = reached;
        }

        let expected_checksum: [u8; 32] = header[CHECKSUM_OFFSET..]
            .try_into()
            .map_err(|_| FrameError::MalformedTransaction("invalid checksum field"))?;
        let actual_checksum = frame_checksum(&header[..CHECKSUM_OFFSET], &payload);
        if expected_checksum != actual_checksum {
            return Err(FrameError::ChecksumMismatch(offset));
        }

        let bytes =
            u64::try_from(HEADER_BYTES + payload_length).map_err(|_| FrameError::JournalTooLarge)?;
        Ok(Some((
            Frame {
                kind,
                sequence,
                transaction_id,
                payload: std::mem::take(payload),
            },
            bytes,
        )))
    })();
    if let Some(destination) = scratch {
        if !matches!(&outcome, Ok(Some(_))) {
            *destination = Some(ReadOnlyFrameScratchV1 {
                header,
                header_filled: filled,
                payload: payload_original,
                payload_filled,
            });
        }
    }
    outcome
}

/// Encodes a native frame without granting commit or domain admission.
///
/// # Errors
///
/// Rejects payload widths exceeding u32 or overflowing the full frame width.
///
/// # Panics
///
/// Panics if the complete frame capacity exceeds the platform's Vec allocation
/// limit. This preserves the existing encoder's allocation behavior.
pub fn encode_frame(
    kind: FrameKind,
    sequence: u64,
    transaction_id: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, FrameError> {
    let layout = EncodedFrameLayout::new(payload.len())?;
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10] = kind as u8;
    header[12..20].copy_from_slice(&sequence.to_le_bytes());
    header[20..36].copy_from_slice(&transaction_id);
    header[36..40].copy_from_slice(&layout.payload_length.to_le_bytes());
    let checksum = frame_checksum(&header[..CHECKSUM_OFFSET], payload);
    header[CHECKSUM_OFFSET..].copy_from_slice(&checksum);

    let mut frame = Vec::with_capacity(layout.frame_bytes);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn frame_checksum(header_prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(FRAME_DOMAIN);
    digest.update(header_prefix);
    digest.update(payload);
    digest.finalize().into()
}

/// Starts the canonical ordered native transaction-payload digest.
pub fn transaction_hasher() -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest
}

/// Writes, flushes, and syncs supplied frames before observing durable length.
///
/// The caller retains writer custody and handles ambiguous failure or poisoning.
/// This function neither opens a journal nor validates domain transitions.
///
/// # Errors
///
/// Returns an unchanged native write, flush, sync, or metadata I/O error.
pub fn append_and_sync(file: &mut File, frames: &[Vec<u8>]) -> Result<u64, FrameError> {
    for frame in frames {
        file.write_all(frame)?;
    }
    file.flush()?;
    file.sync_data()?;
    Ok(file.metadata()?.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    #[test]
    fn scalar_record_bound_preserves_frame_bytes() {
        let payload = b"payload";
        let encoded = encode_frame(FrameKind::Record, 9, [3; 16], payload).unwrap();

        let (decoded, bytes) = read_frame(&mut Cursor::new(&encoded), 17, 0).unwrap().unwrap();

        assert_eq!(&encoded[..8], b"AOSJRN01");
        assert_eq!(&encoded[8..12], &[1, 0, 2, 0]);
        assert_eq!(&encoded[12..20], &9_u64.to_le_bytes());
        assert_eq!(&encoded[20..36], &[3; 16]);
        assert_eq!(&encoded[36..40], &7_u32.to_le_bytes());
        assert_eq!(decoded.kind, FrameKind::Record);
        assert_eq!(decoded.sequence, 9);
        assert_eq!(decoded.transaction_id, [3; 16]);
        assert_eq!(decoded.payload.as_slice(), payload.as_slice());
        assert_eq!(bytes, (HEADER_BYTES + payload.len()) as u64);
    }

    #[test]
    fn oversized_frame_retains_header_without_allocating_payload() {
        let encoded = encode_frame(FrameKind::Record, 9, [3; 16], &[1; 12]).unwrap();
        let mut input = Cursor::new(&encoded);
        let mut retained = None;

        let result = read_frame_retained(&mut input, 17, 4, Some(&mut retained));

        assert!(matches!(
            result,
            Err(FrameError::LimitExceeded("frame payload bytes")),
        ));
        assert_eq!(input.position(), HEADER_BYTES as u64);
        let retained = retained.unwrap();
        assert_eq!(retained.header.as_slice(), &encoded[..HEADER_BYTES]);
        assert_eq!(retained.header_filled, HEADER_BYTES);
        assert!(retained.payload.is_none());
        assert_eq!(retained.payload_filled, 0);
    }

    #[test]
    fn four_byte_incomplete_tail_retains_the_reached_original_header() {
        let mut input = Cursor::new(b"tail");
        let mut scratch = None;

        let frame = read_frame_retained(&mut input, 0, 0, Some(&mut scratch)).unwrap();

        assert!(frame.is_none());
        assert_eq!(input.position(), 4);
        let retained = scratch.as_ref().unwrap();
        assert_eq!(retained.header_filled, 4);
        assert_eq!(&retained.header[..4], b"tail");
        assert!(retained.payload.is_none());
        assert_eq!(retained.payload_filled, 0);
    }

    #[test]
    fn partial_frames_retain_original_header_and_payload_scratch() {
        let payload = b"payload";
        let encoded = encode_frame(FrameKind::Record, 9, [3; 16], payload).unwrap();
        let mut header_scratch = None;
        let mut payload_scratch = None;

        assert!(
            read_frame_retained(
                &mut Cursor::new(&encoded[..13]),
                17,
                0,
                Some(&mut header_scratch),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            read_frame_retained(
                &mut Cursor::new(&encoded[..HEADER_BYTES + 3]),
                17,
                0,
                Some(&mut payload_scratch),
            )
            .unwrap()
            .is_none()
        );

        let header_scratch = header_scratch.unwrap();
        assert_eq!(header_scratch.header_filled, 13);
        assert_eq!(&header_scratch.header[..13], &encoded[..13]);
        assert!(header_scratch.payload.is_none());
        assert_eq!(header_scratch.payload_filled, 0);

        let payload_scratch = payload_scratch.unwrap();
        assert_eq!(payload_scratch.header_filled, HEADER_BYTES);
        assert_eq!(payload_scratch.header.as_slice(), &encoded[..HEADER_BYTES]);
        assert_eq!(payload_scratch.payload_filled, 3);
        let retained_payload = payload_scratch.payload.unwrap();
        assert_eq!(retained_payload.as_slice(), &payload[..3]);
        assert!(retained_payload.capacity() <= 2 * payload_scratch.payload_filled);
    }

    #[test]
    fn advertised_large_truncated_tail_retains_only_reached_bytes() {
        let mut encoded = encode_frame(FrameKind::Record, 9, [3; 16], b"abc").unwrap();
        let advertised = 256 * 1024 * 1024_u32;
        encoded[36..40].copy_from_slice(&advertised.to_le_bytes());
        let mut input = Cursor::new(&encoded);
        let mut retained = None;

        assert!(
            read_frame_retained(&mut input, 17, advertised as usize, Some(&mut retained))
                .unwrap()
                .is_none()
        );

        assert_eq!(input.position(), encoded.len() as u64);
        let retained = retained.unwrap();
        assert_eq!(retained.payload_filled, 3);
        let payload = retained.payload.unwrap();
        assert_eq!(payload.as_slice(), b"abc");
        assert!(payload.capacity() <= 6);
        assert!(
            payload.capacity() + FRAME_READ_SCRATCH_BYTES
                <= reached_frame_read_memory_bound_v1(advertised as usize, 3).unwrap()
        );
    }

    #[test]
    fn missing_advertised_payload_does_not_reserve_a_payload_vec() {
        let mut encoded = encode_frame(FrameKind::Record, 9, [3; 16], b"").unwrap();
        encoded[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut input = Cursor::new(&encoded);
        let mut retained = None;

        assert!(
            read_frame_retained(&mut input, 17, usize::MAX, Some(&mut retained))
                .unwrap()
                .is_none()
        );

        assert_eq!(input.position(), HEADER_BYTES as u64);
        let retained = retained.unwrap();
        assert_eq!(retained.payload_filled, 0);
        let payload = retained.payload.unwrap();
        assert!(payload.is_empty());
        assert_eq!(payload.capacity(), 0);
    }

    #[test]
    fn incremental_payload_reads_preserve_full_frames_and_next_frame_cursor() {
        let payload = vec![19; 2 * FRAME_READ_SCRATCH_BYTES + 9];
        let first = encode_frame(FrameKind::Record, 9, [3; 16], &payload).unwrap();
        let second = encode_frame(FrameKind::Commit, 10, [3; 16], b"next").unwrap();
        let mut encoded = first.clone();
        encoded.extend_from_slice(&second);
        let mut input = Cursor::new(encoded);

        let (decoded, bytes) = read_frame(&mut input, 17, payload.len()).unwrap().unwrap();

        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.kind, FrameKind::Record);
        assert_eq!(bytes, first.len() as u64);
        assert_eq!(input.position(), first.len() as u64);
        let (decoded, bytes) = read_frame(&mut input, 17 + bytes, 0).unwrap().unwrap();
        assert_eq!(decoded.payload, b"next");
        assert_eq!(bytes, second.len() as u64);
        assert_eq!(input.position(), (first.len() + second.len()) as u64);
    }

    struct FailingPayloadReader {
        input: Cursor<Vec<u8>>,
        fail_after: u64,
        kind: io::ErrorKind,
        failures: usize,
    }

    impl Read for FailingPayloadReader {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.input.position() == self.fail_after {
                self.failures += 1;
                return Err(io::Error::new(self.kind, "original injected read failure"));
            }
            let remaining = usize::try_from(self.fail_after - self.input.position()).unwrap();
            let offered = remaining.min(bytes.len()).min(11);
            self.input.read(&mut bytes[..offered])
        }
    }

    #[test]
    fn payload_io_failure_retains_native_cause_reached_prefix_and_cursor() {
        for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
            let payload = vec![19; 2 * FRAME_READ_SCRATCH_BYTES];
            let encoded = encode_frame(FrameKind::Record, 9, [3; 16], &payload).unwrap();
            let mut input = FailingPayloadReader {
                input: Cursor::new(encoded.clone()),
                fail_after: (HEADER_BYTES + 73) as u64,
                kind,
                failures: 0,
            };
            let mut retained = None;

            let failure =
                match read_frame_retained(&mut input, 17, payload.len(), Some(&mut retained)) {
                    Err(cause) => cause,
                    Ok(_) => panic!("injected native read failure was not retained"),
                };

            assert!(
                matches!(failure, FrameError::Io(ref cause) if cause.kind() == kind
                && cause.to_string() == "original injected read failure")
            );
            assert_eq!(input.failures, 1);
            assert_eq!(input.input.position(), (HEADER_BYTES + 73) as u64);
            let retained = retained.unwrap();
            assert_eq!(retained.header.as_slice(), &encoded[..HEADER_BYTES]);
            assert_eq!(retained.header_filled, HEADER_BYTES);
            assert_eq!(retained.payload_filled, 73);
            let retained_payload = retained.payload.unwrap();
            assert_eq!(retained_payload.as_slice(), &payload[..73]);
            assert!(retained_payload.capacity() <= 2 * 73);
        }
    }

    #[test]
    fn corrupt_complete_payload_retains_exact_bytes_and_original_offset() {
        let mut encoded = encode_frame(FrameKind::Record, 9, [3; 16], b"payload").unwrap();
        encoded[HEADER_BYTES + 2] ^= 1;
        let mut input = Cursor::new(&encoded);
        let mut retained = None;

        assert!(matches!(
            read_frame_retained(&mut input, 37, 0, Some(&mut retained)),
            Err(FrameError::ChecksumMismatch(37))
        ));

        assert_eq!(input.position(), encoded.len() as u64);
        let retained = retained.unwrap();
        assert_eq!(retained.payload_filled, 7);
        assert_eq!(
            retained.payload.unwrap().as_slice(),
            &encoded[HEADER_BYTES..]
        );
    }

    #[test]
    fn reached_read_bound_includes_reallocation_peak_and_refuses_overflow() {
        assert_eq!(
            reached_frame_read_memory_bound_v1(0, 0).unwrap(),
            FRAME_READ_SCRATCH_BYTES
        );
        assert_eq!(
            reached_frame_read_memory_bound_v1(1000, 3).unwrap(),
            FRAME_READ_SCRATCH_BYTES + 9
        );
        assert_eq!(
            reached_frame_read_memory_bound_v1(10, 1000).unwrap(),
            FRAME_READ_SCRATCH_BYTES + 20
        );
        assert!(matches!(
            reached_frame_read_memory_bound_v1(usize::MAX, usize::MAX),
            Err(FrameError::LimitExceeded("frame read representation bytes"))
        ));
    }

    #[test]
    fn frame_validation_keeps_original_first_error_order() {
        let mut encoded = encode_frame(FrameKind::Record, 9, [3; 16], &[1; 9]).unwrap();
        encoded[8] = 2;
        encoded[10] = 255;
        encoded[11] = 1;
        encoded[CHECKSUM_OFFSET] ^= 1;

        assert!(matches!(
            read_frame(&mut Cursor::new(&encoded), 17, 1),
            Err(FrameError::UnsupportedVersion(2)),
        ));
        encoded[8] = 1;
        assert!(matches!(
            read_frame(&mut Cursor::new(&encoded), 17, 1),
            Err(FrameError::MalformedTransaction("nonzero reserved frame flags")),
        ));
        encoded[11] = 0;
        assert!(matches!(
            read_frame(&mut Cursor::new(&encoded), 17, 1),
            Err(FrameError::MalformedTransaction("unknown frame kind")),
        ));
        encoded[10] = FrameKind::Record as u8;
        assert!(matches!(
            read_frame(&mut Cursor::new(&encoded), 17, 1),
            Err(FrameError::LimitExceeded("frame payload bytes")),
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new(&encoded), 17, 2),
            Err(FrameError::ChecksumMismatch(17)),
        ));
    }
}
