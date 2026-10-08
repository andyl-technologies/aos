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
//! This private module is an incremental boundary: it still uses its parent's
//! error and limits types. It is not yet an independent lower-layer crate.

use std::fs::File;
use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use super::{JournalError, JournalLimits};

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
    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::Begin),
            2 => Ok(Self::Record),
            3 => Ok(Self::Commit),
            _ => Err(JournalError::MalformedTransaction("unknown frame kind")),
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
    pub(super) fn new(payload_bytes: usize) -> Result<Self, JournalError> {
        let payload_length = u32::try_from(payload_bytes)
            .map_err(|_| JournalError::LimitExceeded("frame payload bytes"))?;
        let frame_bytes = HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or(JournalError::JournalTooLarge)?;

        Ok(Self {
            payload_length,
            frame_bytes,
        })
    }
}

pub(super) fn read_frame<R: Read>(
    file: &mut R,
    offset: u64,
    limits: JournalLimits,
) -> Result<Option<(Frame, u64)>, JournalError> {
    read_frame_retained(file, offset, limits, None)
}

// The sole frame parser retains a selected partial payload before returning.
pub(super) fn read_frame_retained<R: Read>(
    file: &mut R,
    offset: u64,
    limits: JournalLimits,
    scratch: Option<&mut Option<ReadOnlyFrameScratchV1>>,
) -> Result<Option<(Frame, u64)>, JournalError> {
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
            return Err(JournalError::MalformedTransaction("invalid frame magic"));
        }
        let version = u16::from_le_bytes([header[8], header[9]]);
        if version != FORMAT_VERSION {
            return Err(JournalError::UnsupportedVersion(version));
        }
        if header[11] != 0 {
            return Err(JournalError::MalformedTransaction(
                "nonzero reserved frame flags",
            ));
        }
        let kind = FrameKind::from_byte(header[10])?;
        let sequence = u64::from_le_bytes(
            header[12..20]
                .try_into()
                .map_err(|_| JournalError::MalformedTransaction("invalid sequence field"))?,
        );
        let transaction_id = header[20..36]
            .try_into()
            .map_err(|_| JournalError::MalformedTransaction("invalid transaction identity"))?;
        if transaction_id == [0; 16] {
            return Err(JournalError::MalformedTransaction(
                "zero transaction identity",
            ));
        }
        let payload_length = u32::from_le_bytes(
            header[36..40]
                .try_into()
                .map_err(|_| JournalError::MalformedTransaction("invalid payload length"))?,
        ) as usize;
        let maximum_frame_payload = limits.maximum_record_bytes.saturating_add(7);
        if payload_length > maximum_frame_payload {
            return Err(JournalError::LimitExceeded("frame payload bytes"));
        }

        payload_original = Some(vec![0_u8; payload_length]);
        let payload = payload_original.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        while payload_filled < payload_length {
            let read = file.read(&mut payload[payload_filled..])?;
            if read == 0 {
                return Ok(None);
            }
            payload_filled += read;
        }

        let expected_checksum: [u8; 32] = header[CHECKSUM_OFFSET..]
            .try_into()
            .map_err(|_| JournalError::MalformedTransaction("invalid checksum field"))?;
        let actual_checksum = frame_checksum(&header[..CHECKSUM_OFFSET], &payload);
        if expected_checksum != actual_checksum {
            return Err(JournalError::ChecksumMismatch(offset));
        }

        let bytes =
            u64::try_from(HEADER_BYTES + payload_length).map_err(|_| JournalError::JournalTooLarge)?;
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
) -> Result<Vec<u8>, JournalError> {
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

pub(super) fn append_and_sync(file: &mut File, frames: &[Vec<u8>]) -> Result<u64, JournalError> {
    for frame in frames {
        file.write_all(frame)?;
    }
    file.flush()?;
    file.sync_data()?;
    Ok(file.metadata()?.len())
}
