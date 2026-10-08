//! Ordered native transaction construction and incremental structural state.
//!
//! The encoder owns BEGIN/RECORD/COMMIT assembly and payload hashing. Pending
//! state checks one reached frame at a time; the domain owner decodes each
//! record immediately afterward, before reading another frame. Structural
//! COMMIT validation neither admits a transition nor publishes durable state.
//! Journal files, locks, retained read/error custody, and semantic joins remain
//! with the domain owner.
//!
//! ```text
//! BEGIN  = record-count:u32le
//! RECORD = uninterpreted native record payload
//! COMMIT = record-count:u32le | ordered-payload-digest:32
//! ```

use sha2::{Digest, Sha256};

use crate::framing::{
    COMMIT_PAYLOAD_BYTES, Frame, FrameError, FrameKind, encode_frame, transaction_hasher,
};
use crate::record::encode_record_fields;

/// Borrows one ordered record's raw DATA without namespace or semantic admission.
pub struct NativeRecordRef<'a> {
    /// Carries the uninterpreted native namespace byte.
    pub namespace_byte: u8,
    /// Borrows the actual key bytes.
    pub key: &'a [u8],
    /// Borrows a present, possibly empty, value or represents DELETE.
    pub value: Option<&'a [u8]>,
}

/// Encodes ordered native transaction DATA without writing or admitting it.
///
/// The exact-size iterator supplies the actual records and count. Identity,
/// namespace, nonempty-key, aggregate bounds, and transition admission remain
/// separate owner checks. The encoder intentionally does not increment the
/// sequence after COMMIT.
///
/// # Errors
///
/// Rejects unrepresentable counts, record/frame widths, or sequence increments
/// in the original BEGIN, individual RECORD, then COMMIT order.
///
/// # Panics
///
/// Panics if the record count plus framing overflows `usize`, or an existing
/// frame, payload, or collection allocation exceeds the platform's capacity bound.
pub fn encode_transaction<'a>(
    transaction_id: [u8; 16],
    first_sequence: u64,
    records: impl ExactSizeIterator<Item = NativeRecordRef<'a>>,
) -> Result<Vec<Vec<u8>>, FrameError> {
    let record_count = u32::try_from(records.len())
        .map_err(|_| FrameError::LimitExceeded("records per transaction"))?;
    let mut sequence = first_sequence;
    let mut frames = Vec::with_capacity(records.len() + 2);
    frames.push(encode_frame(
        FrameKind::Begin,
        sequence,
        transaction_id,
        &record_count.to_le_bytes(),
    )?);
    sequence = sequence
        .checked_add(1)
        .ok_or(FrameError::SequenceExhausted)?;

    let mut transaction_digest = transaction_hasher();
    for record in records {
        let payload = encode_record_fields(record.namespace_byte, record.key, record.value)?;
        transaction_digest.update(&payload);
        frames.push(encode_frame(
            FrameKind::Record,
            sequence,
            transaction_id,
            &payload,
        )?);
        sequence = sequence
            .checked_add(1)
            .ok_or(FrameError::SequenceExhausted)?;
    }

    let mut commit = Vec::with_capacity(COMMIT_PAYLOAD_BYTES);
    commit.extend_from_slice(&record_count.to_le_bytes());
    commit.extend_from_slice(&transaction_digest.finalize());
    frames.push(encode_frame(
        FrameKind::Commit,
        sequence,
        transaction_id,
        &commit,
    )?);
    Ok(frames)
}

/// Decodes and bounds a reached BEGIN count before the owner's row allocation.
///
/// This decodes DATA only and does not construct a transaction or writer.
///
/// # Errors
///
/// Rejects a non-four-byte count, then a zero or excessive declared row count.
pub fn decode_begin_count(payload: &[u8], maximum_records: usize) -> Result<usize, FrameError> {
    if payload.len() != 4 {
        return Err(FrameError::MalformedTransaction(
            "invalid begin record count",
        ));
    }
    let count = u32::from_le_bytes(
        payload
            .try_into()
            .map_err(|_| FrameError::MalformedTransaction("invalid begin payload"))?,
    ) as usize;
    if count == 0 || count > maximum_records {
        return Err(FrameError::LimitExceeded("records per transaction"));
    }
    Ok(count)
}

/// Owns incremental native transaction DATA, not rows or committed visibility.
///
/// The domain owner retains its actual decoded rows and supplies their length
/// at each reached RECORD and COMMIT. Payload hashing precedes immediate domain
/// decoding; neither a valid hash nor this type admits a semantic transition.
pub struct NativePendingTransaction {
    id: [u8; 16],
    expected_records: usize,
    digest: Sha256,
    begin_sequence: u64,
    begin_offset: u64,
}

impl NativePendingTransaction {
    /// Retains a reached BEGIN's DATA after the owner's bounded row allocation.
    ///
    /// The owner supplies the decoded count and original read coordinates.
    /// This does not inspect a file, acquire custody, or validate a namespace.
    ///
    /// # Errors
    ///
    /// Rejects underflow when recovering the original BEGIN byte offset.
    pub fn begin(
        frame: &Frame,
        declared_count: usize,
        end_offset: u64,
        bytes_read: u64,
    ) -> Result<Self, FrameError> {
        Ok(Self {
            id: frame.transaction_id,
            expected_records: declared_count,
            digest: transaction_hasher(),
            begin_sequence: frame.sequence,
            begin_offset: end_offset
                .checked_sub(bytes_read)
                .ok_or(FrameError::JournalTooLarge)?,
        })
    }

    /// Checks and hashes one reached RECORD before immediate owner decoding.
    ///
    /// `decoded_records` is the length of the owner's actual row collection.
    /// On success the owner must decode and retain this record before reading
    /// another frame; no semantic acceptance is implied by this result.
    ///
    /// # Errors
    ///
    /// Rejects a different transaction identity, then excess record frames.
    pub fn observe_record(
        &mut self,
        frame: &Frame,
        decoded_records: usize,
    ) -> Result<(), FrameError> {
        if self.id != frame.transaction_id {
            return Err(FrameError::MalformedTransaction(
                "record transaction identity mismatch",
            ));
        }
        if decoded_records >= self.expected_records {
            return Err(FrameError::MalformedTransaction("too many record frames"));
        }
        self.digest.update(&frame.payload);
        Ok(())
    }

    /// Checks a reached COMMIT's structural DATA without committing any state.
    ///
    /// The original upper semantic transaction/history joins still precede
    /// visible state, durable-boundary advancement, and any authority issuance.
    ///
    /// # Errors
    ///
    /// Rejects identity or actual-row-count mismatch, then malformed payload,
    /// declared COMMIT count mismatch, or ordered-payload digest mismatch.
    pub fn validate_commit(&self, frame: &Frame, decoded_records: usize) -> Result<(), FrameError> {
        if self.id != frame.transaction_id || decoded_records != self.expected_records {
            return Err(FrameError::MalformedTransaction(
                "commit transaction identity or record count mismatch",
            ));
        }
        let payload = &frame.payload;
        if payload.len() != 36 {
            return Err(FrameError::MalformedTransaction("invalid commit payload"));
        }
        let count = u32::from_le_bytes(
            payload[..4]
                .try_into()
                .map_err(|_| FrameError::MalformedTransaction("invalid commit count"))?,
        ) as usize;
        if count != self.expected_records {
            return Err(FrameError::MalformedTransaction(
                "commit record count mismatch",
            ));
        }
        let expected: [u8; 32] = payload[4..]
            .try_into()
            .map_err(|_| FrameError::MalformedTransaction("invalid commit digest"))?;
        let actual: [u8; 32] = self.digest.clone().finalize().into();
        if expected != actual {
            return Err(FrameError::MalformedTransaction(
                "transaction digest mismatch",
            ));
        }
        Ok(())
    }

    /// Returns the retained transaction identity as DATA.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        self.id
    }

    /// Returns the original BEGIN sequence and byte offset as DATA.
    #[must_use]
    pub const fn begin_position(&self) -> (u64, u64) {
        (self.begin_sequence, self.begin_offset)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::framing::read_frame;

    fn decode_frames(frames: &[Vec<u8>]) -> Vec<Frame> {
        frames
            .iter()
            .map(|bytes| {
                read_frame(&mut Cursor::new(bytes), 0, 1024)
                    .unwrap()
                    .unwrap()
                    .0
            })
            .collect()
    }

    #[test]
    fn ordered_encoding_preserves_literal_payloads_sequences_and_digest() {
        let records = [
            NativeRecordRef {
                namespace_byte: 254,
                key: b"a",
                value: Some(b"v"),
            },
            NativeRecordRef {
                namespace_byte: 255,
                key: b"b",
                value: Some(b""),
            },
            NativeRecordRef {
                namespace_byte: 0,
                key: b"c",
                value: None,
            },
        ];
        let encoded = encode_transaction([7; 16], 9, records.into_iter()).unwrap();

        let frames = decode_frames(&encoded);

        assert_eq!(frames.len(), 5);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.sequence, 9 + index as u64);
            assert_eq!(frame.transaction_id, [7; 16]);
        }
        assert_eq!(frames[0].kind, FrameKind::Begin);
        assert_eq!(frames[0].payload, [3, 0, 0, 0]);
        assert_eq!(frames[1].kind, FrameKind::Record);
        assert_eq!(frames[1].payload, [254, 1, 0, 1, 0, 0, 0, b'a', b'v']);
        assert_eq!(frames[2].payload, [255, 1, 0, 0, 0, 0, 0, b'b']);
        assert_eq!(frames[3].payload, [0, 1, 0, 255, 255, 255, 255, b'c']);
        assert_eq!(frames[4].kind, FrameKind::Commit);
        assert_eq!(&frames[4].payload[..4], &[3, 0, 0, 0]);
        // Golden SHA-256 of the existing transaction domain followed by the
        // three literal payloads above; changes require native-format review.
        assert_eq!(
            &frames[4].payload[4..],
            &[
                123, 110, 58, 3, 120, 150, 252, 11, 72, 57, 134, 99, 6, 50, 237, 227, 199, 185,
                207, 208, 188, 100, 230, 29, 179, 111, 25, 153, 120, 207, 244, 22,
            ]
        );
    }

    #[test]
    fn encoder_preserves_sequence_before_record_width_without_post_commit_increment() {
        let valid = || {
            [NativeRecordRef {
                namespace_byte: 1,
                key: b"key",
                value: None,
            }]
        };
        let oversized_key = vec![1; u16::MAX as usize + 1];
        let invalid = || {
            [NativeRecordRef {
                namespace_byte: 1,
                key: &oversized_key,
                value: None,
            }]
        };

        assert!(encode_transaction([1; 16], u64::MAX - 2, valid().into_iter()).is_ok());
        assert!(matches!(
            encode_transaction([1; 16], u64::MAX - 1, valid().into_iter()),
            Err(FrameError::SequenceExhausted),
        ));
        assert!(matches!(
            encode_transaction([1; 16], u64::MAX, invalid().into_iter()),
            Err(FrameError::SequenceExhausted),
        ));
        assert!(matches!(
            encode_transaction([1; 16], u64::MAX - 1, invalid().into_iter()),
            Err(FrameError::LimitExceeded("record key bytes")),
        ));
    }

    #[test]
    fn begin_count_rejects_width_before_zero_or_excessive_count() {
        assert!(matches!(
            decode_begin_count(&[0; 3], 0),
            Err(FrameError::MalformedTransaction(
                "invalid begin record count"
            )),
        ));
        for count in [0_u32, 2] {
            assert!(matches!(
                decode_begin_count(&count.to_le_bytes(), 1),
                Err(FrameError::LimitExceeded("records per transaction")),
            ));
        }
        assert_eq!(decode_begin_count(&1_u32.to_le_bytes(), 1).unwrap(), 1);
    }

    #[test]
    fn pending_state_retains_coordinates_and_rejects_identity_before_count_or_payload() {
        let encoded = encode_transaction(
            [7; 16],
            9,
            [NativeRecordRef {
                namespace_byte: 254,
                key: b"a",
                value: Some(b"v"),
            }]
            .into_iter(),
        )
        .unwrap();
        let mut frames = decode_frames(&encoded);
        let count = decode_begin_count(&frames[0].payload, 1).unwrap();
        let mut pending = NativePendingTransaction::begin(&frames[0], count, 576, 76).unwrap();

        assert_eq!(pending.transaction_id(), [7; 16]);
        assert_eq!(pending.begin_position(), (9, 500));
        frames[1].transaction_id = [8; 16];
        assert!(matches!(
            pending.observe_record(&frames[1], 1),
            Err(FrameError::MalformedTransaction(
                "record transaction identity mismatch"
            )),
        ));
        frames[1].transaction_id = [7; 16];
        assert!(matches!(
            pending.observe_record(&frames[1], 1),
            Err(FrameError::MalformedTransaction("too many record frames")),
        ));
        pending.observe_record(&frames[1], 0).unwrap();

        // Failed RECORD checks must not alter the digest consumed by COMMIT.
        assert!(pending.validate_commit(&frames[2], 1).is_ok());
        frames[2].transaction_id = [8; 16];
        frames[2].payload.clear();
        assert!(matches!(
            pending.validate_commit(&frames[2], 0),
            Err(FrameError::MalformedTransaction(
                "commit transaction identity or record count mismatch",
            )),
        ));
        frames[2].transaction_id = [7; 16];
        assert!(matches!(
            pending.validate_commit(&frames[2], 0),
            Err(FrameError::MalformedTransaction(
                "commit transaction identity or record count mismatch",
            )),
        ));
        assert!(matches!(
            pending.validate_commit(&frames[2], 1),
            Err(FrameError::MalformedTransaction("invalid commit payload")),
        ));
        assert_eq!(pending.begin_position(), (9, 500));
        assert!(matches!(
            NativePendingTransaction::begin(&frames[0], count, 75, 76),
            Err(FrameError::JournalTooLarge),
        ));
    }

    #[test]
    fn commit_count_error_precedes_digest_mismatch() {
        let encoded = encode_transaction(
            [7; 16],
            1,
            [NativeRecordRef {
                namespace_byte: 254,
                key: b"a",
                value: None,
            }]
            .into_iter(),
        )
        .unwrap();
        let mut frames = decode_frames(&encoded);
        let mut pending = NativePendingTransaction::begin(&frames[0], 1, 76, 76).unwrap();
        pending.observe_record(&frames[1], 0).unwrap();

        frames[2].payload[..4].copy_from_slice(&2_u32.to_le_bytes());
        frames[2].payload[4] ^= 1;

        assert!(matches!(
            pending.validate_commit(&frames[2], 1),
            Err(FrameError::MalformedTransaction(
                "commit record count mismatch"
            )),
        ));
        frames[2].payload[..4].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            pending.validate_commit(&frames[2], 1),
            Err(FrameError::MalformedTransaction(
                "transaction digest mismatch"
            )),
        ));
    }
}
