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
//! The parent journal preserves its existing error classification through an
//! exhaustive adapter. This private module is not yet a separate journal crate.

use std::fs::File;
use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

/// Reports structural framing and append failures without domain authority.
#[derive(Debug, thiserror::Error)]
pub(super) enum FrameError {
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
}

const MAGIC: &[u8; 8] = b"AOSJRN01";
const FORMAT_VERSION: u16 = 1;
pub(super) const HEADER_BYTES: usize = 72;
pub(super) const COMMIT_PAYLOAD_BYTES: usize = 36;
pub(super) const CHECKSUM_OFFSET: usize = 40;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.journal.transaction.v1\0";
const FRAME_DOMAIN: &[u8] = b"aos.sandbox.journal.frame.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum FrameKind {
    Begin = 1,
    Record = 2,
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

pub(super) struct Frame {
    pub(super) kind: FrameKind,
    pub(super) sequence: u64,
    pub(super) transaction_id: [u8; 16],
    pub(super) payload: Vec<u8>,
}

pub(super) struct ReadOnlyFrameScratchV1 {
    header: [u8; HEADER_BYTES],
    header_filled: usize,
    payload: Option<Vec<u8>>,
    payload_filled: usize,
}

/// Shares the frame's u32 payload field and complete serialized width.
pub(super) struct EncodedFrameLayout {
    payload_length: u32,
    pub(super) frame_bytes: usize,
}

impl EncodedFrameLayout {
    pub(super) fn new(payload_bytes: usize) -> Result<Self, FrameError> {
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

pub(super) fn read_frame<R: Read>(
    file: &mut R,
    offset: u64,
    maximum_record_bytes: usize,
) -> Result<Option<(Frame, u64)>, FrameError> {
    read_frame_retained(file, offset, maximum_record_bytes, None)
}

// The sole frame parser retains a selected partial payload before returning.
pub(super) fn read_frame_retained<R: Read>(
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

        payload_original = Some(vec![0_u8; payload_length]);
        let payload = payload_original.as_mut().ok_or(FrameError::MissingRetainedPayload)?;
        while payload_filled < payload_length {
            let read = file.read(&mut payload[payload_filled..])?;
            if read == 0 {
                return Ok(None);
            }
            payload_filled += read;
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

pub(super) fn encode_frame(
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

pub(super) fn transaction_hasher() -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest
}

pub(super) fn append_and_sync(file: &mut File, frames: &[Vec<u8>]) -> Result<u64, FrameError> {
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
        assert_eq!(retained_payload.len(), payload.len());
        assert_eq!(&retained_payload[..3], &payload[..3]);
        assert_eq!(&retained_payload[3..], &[0; 4]);
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
