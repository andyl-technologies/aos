//! Ordered native transaction construction and incremental structural state.
//!
//! The encoder owns BEGIN/RECORD/COMMIT assembly and payload hashing. Pending
//! state checks one reached frame at a time; the domain owner decodes each
//! record immediately afterward, before reading another frame. Structural
//! COMMIT validation neither admits a transition nor publishes durable state.
//! Bounded record validation shares raw extent accounting and duplicate-key
//! custody while leaving the owner's typed checks between those two stages.
//! Journal files, locks, retained read/error custody, and semantic joins remain
//! with the domain owner.
//!
//! ```text
//! BEGIN  = record-count:u32le
//! RECORD = uninterpreted native record payload
//! COMMIT = record-count:u32le | ordered-payload-digest:32
//! ```

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::framing::{
    COMMIT_PAYLOAD_BYTES, Frame, FrameError, FrameKind, encode_frame, transaction_hasher,
};
use crate::geometry::{EncodedRecordLayout, NativeGeometryBounds};
use crate::record::encode_record_fields;

/// Describes bounded raw-record refusals without interpreting namespace DATA.
#[derive(Debug, thiserror::Error)]
pub enum NativeRecordValidationError {
    /// Rejects a zero transaction identity or an empty transaction.
    #[error("invalid native transaction")]
    InvalidTransaction,
    /// Rejects a repeated raw namespace and key in one transaction.
    #[error("duplicate native record key")]
    DuplicateRecordKey,
    /// Preserves the existing configured count, record, or aggregate bound.
    #[error("native transaction limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Preserves native record representation arithmetic errors.
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Owns bounded extent accounting and a duplicate index over original key borrows.
///
/// Callers observe each extent, perform their typed record checks, then register
/// its raw namespace/key pair. These stages grant no namespace admission,
/// currentness, or persistence proof. Ordinary validation owns local index
/// nodes over original key borrows. Retaining validation borrows an owning
/// DATA destination for those same nodes and actual copied key bytes.
pub struct NativeRecordValidation<'keys> {
    keys: NativeRecordKeysV1<'keys>,
    transaction_bytes: usize,
    bounds: NativeGeometryBounds,
}

impl<'keys> NativeRecordValidation<'keys> {
    /// Starts the original identity and configured record-count checks.
    ///
    /// Configuration is supplied DATA, not validated here. This does not add a
    /// representational count check or certify an actual transaction or writer.
    ///
    /// # Errors
    ///
    /// Rejects a zero identity or zero count before an excessive configured count.
    pub fn begin(
        transaction_id: [u8; 16],
        record_count: usize,
        bounds: NativeGeometryBounds,
    ) -> Result<Self, NativeRecordValidationError> {
        if transaction_id == [0; 16] || record_count == 0 {
            return Err(NativeRecordValidationError::InvalidTransaction);
        }
        if record_count > bounds.maximum_records_per_transaction {
            return Err(NativeRecordValidationError::LimitExceeded(
                "records per transaction",
            ));
        }

        Ok(Self {
            keys: NativeRecordKeysV1::Borrowed(BTreeSet::new()),
            transaction_bytes: 0,
            bounds,
        })
    }

    /// Starts the same checks with an owning destination for reached key nodes.
    ///
    /// The destination is representation DATA, never an admitted transaction.
    /// Its caller must retain it after failure and pay before index growth.
    ///
    /// # Errors
    /// Rejects the same identity and configured count as [`Self::begin`].
    pub fn begin_retaining_v1(
        transaction_id: [u8; 16],
        record_count: usize,
        bounds: NativeGeometryBounds,
        original: &'keys mut NativeRecordKeyIndexV1,
    ) -> Result<Self, NativeRecordValidationError> {
        let mut validation = Self::begin(transaction_id, record_count, bounds)?;
        validation.keys = NativeRecordKeysV1::Retained(original);
        Ok(validation)
    }

    /// Checks one raw extent and accumulates its bounded native payload width.
    ///
    /// Typed record validation remains with the caller after this observation
    /// and before key registration. A failed configured aggregate check retains
    /// the reached byte count, just as the original local fold did.
    ///
    /// # Errors
    ///
    /// Rejects an empty or excessive key, then unrepresentable native lengths,
    /// excessive payload width, aggregate overflow, or excessive aggregate width.
    pub fn observe_extent(
        &mut self,
        key: &[u8],
        value_bytes: Option<usize>,
    ) -> Result<(), NativeRecordValidationError> {
        if key.is_empty() || key.len() > self.bounds.maximum_key_bytes {
            return Err(NativeRecordValidationError::LimitExceeded(
                "record key bytes",
            ));
        }
        let payload_bytes = EncodedRecordLayout::new(key.len(), value_bytes)?.payload_bytes;
        if payload_bytes > self.bounds.maximum_record_bytes {
            return Err(NativeRecordValidationError::LimitExceeded(
                "record payload bytes",
            ));
        }
        self.transaction_bytes = self.transaction_bytes.checked_add(payload_bytes).ok_or(
            NativeRecordValidationError::LimitExceeded("transaction bytes"),
        )?;
        if self.transaction_bytes > self.bounds.maximum_transaction_bytes {
            return Err(NativeRecordValidationError::LimitExceeded(
                "transaction bytes",
            ));
        }
        Ok(())
    }

    /// Registers one original key after the caller's typed checks.
    ///
    /// Raw namespace bytes have no semantic interpretation. Insertion neither
    /// rechecks an extent nor establishes that any prior owner check succeeded.
    ///
    /// # Errors
    ///
    /// Rejects a repeated namespace/key pair by byte equality.
    pub fn register_key(
        &mut self,
        namespace_byte: u8,
        key: &'keys [u8],
    ) -> Result<(), NativeRecordValidationError> {
        let inserted = match &mut self.keys {
            NativeRecordKeysV1::Borrowed(keys) => keys.insert((namespace_byte, key)),
            NativeRecordKeysV1::Retained(original) => {
                original.current = Some((namespace_byte, key.to_vec()));
                let current = original.current.as_ref()
                    .ok_or(NativeRecordValidationError::InvalidTransaction)?;
                if original.keys.contains(current) {
                    false
                } else {
                    let current = original.current.take()
                        .ok_or(NativeRecordValidationError::InvalidTransaction)?;
                    original.keys.insert(current)
                }
            }
        };
        if !inserted {
            return Err(NativeRecordValidationError::DuplicateRecordKey);
        }
        Ok(())
    }
}

enum NativeRecordKeysV1<'keys> {
    Borrowed(BTreeSet<(u8, &'keys [u8])>),
    Retained(&'keys mut NativeRecordKeyIndexV1),
}

/// Owns reached duplicate-index nodes and the current comparison key.
///
/// The ordinary validator keeps original key borrows. A retaining caller uses
/// this owning representation to avoid references into its own transaction.
/// This DATA cannot validate, persist or admit any transaction by itself.
#[derive(Default)]
pub struct NativeRecordKeyIndexV1 {
    keys: BTreeSet<(u8, Vec<u8>)>,
    current: Option<(u8, Vec<u8>)>,
}

impl NativeRecordKeyIndexV1 {
    /// Creates an empty destination without heap allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { keys: BTreeSet::new(), current: None }
    }

    /// Counts reached unique key nodes without granting acceptance.
    #[must_use]
    pub fn retained_key_count_v1(&self) -> usize { self.keys.len() }

    /// Borrows the actual current comparison key left by a duplicate refusal.
    #[must_use]
    pub fn current_key_v1(&self) -> Option<(u8, &[u8])> {
        self.current.as_ref().map(|(namespace, key)| (*namespace, key.as_slice()))
    }

    /// Counts the fixed tree-root and current-key owning destinations.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize { 2 }

    /// Bounds owned index backing plus the current comparison key as DATA.
    ///
    /// One full eleven-key node and twelve links per reached key dominates
    /// native tree occupancy. Key bytes and the current duplicate are distinct.
    #[must_use]
    pub fn dynamic_bytes_v1(keys: usize, key_bytes: usize, current_bytes: usize) -> Option<usize> {
        crate::geometry::conservative_btree_node_bytes_v1::<(u8, Vec<u8>), ()>(keys)?
            .checked_add(key_bytes)?.checked_add(current_bytes)
    }
}

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
    encode_transaction_engine(transaction_id, first_sequence, records, None)
}

/// Retains failed encoder locals without admitting a transaction or native owner.
///
/// Successful iteration payloads and the successful final COMMIT scratch retire
/// at their existing last-borrow boundaries. On error the actual reached frame
/// prefix, current payload/COMMIT and still-live digest state remain here.
/// The actual returned FrameError belongs to the caller's whole stage result.
pub struct NativeTransactionEncodeOriginalsV1 {
    frames: Option<Vec<Vec<u8>>>,
    payload: Option<Vec<u8>>,
    commit: Option<Vec<u8>>,
    digest: Option<Sha256>,
    sequence: u64,
    count: Option<u32>,
    attempted: bool,
    closed: bool,
}

impl NativeTransactionEncodeOriginalsV1 {
    /// Creates empty fixed destinations without allocation.
    pub const fn new() -> Self {
        Self {
            frames: None, payload: None, commit: None, digest: None,
            sequence: 0, count: None, attempted: false, closed: false,
        }
    }

    /// Borrows the actual completed frame prefix retained on an encoder refusal.
    pub fn frames(&self) -> Option<&[Vec<u8>]> { self.frames.as_deref() }

    /// Borrows the actual current RECORD payload retained on a later refusal.
    pub fn payload(&self) -> Option<&[u8]> { self.payload.as_deref() }

    /// Borrows the actual COMMIT scratch retained on a later refusal.
    pub fn commit(&self) -> Option<&[u8]> { self.commit.as_deref() }

    /// Counts the eight named owning/result-control destinations as DATA.
    pub const fn receiving_metadata_cells_v1() -> usize { 8 }
}

impl Default for NativeTransactionEncodeOriginalsV1 {
    fn default() -> Self { Self::new() }
}

/// Uses the same encoder while retaining every reached failed allocation prefix.
///
/// # Errors
/// Returns the identical count/layout/sequence error at its existing frontier;
/// repeated entry refuses without replacing any prior destination. Callers must
/// retain this owner AND the returned original error on a selected negative.
///
/// # Panics
/// Preserves the ordinary encoder's allocation/count panic conditions.
pub fn encode_transaction_retaining_v1<'a>(
    transaction_id: [u8; 16],
    first_sequence: u64,
    records: impl ExactSizeIterator<Item = NativeRecordRef<'a>>,
    original: &mut NativeTransactionEncodeOriginalsV1,
) -> Result<Vec<Vec<u8>>, FrameError> {
    if original.attempted {
        original.closed = true;
        return Err(FrameError::MissingRetainedPayload);
    }
    original.attempted = true;
    encode_transaction_engine(transaction_id, first_sequence, records, Some(original))
}

fn encode_transaction_engine<'a>(
    transaction_id: [u8; 16],
    first_sequence: u64,
    records: impl ExactSizeIterator<Item = NativeRecordRef<'a>>,
    mut original: Option<&mut NativeTransactionEncodeOriginalsV1>,
) -> Result<Vec<Vec<u8>>, FrameError> {
    let record_count = u32::try_from(records.len())
        .map_err(|_| FrameError::LimitExceeded("records per transaction"))?;
    // The iterator stays in its parameter position until the original for-loop
    // frontier. BEGIN failure drops frames before this still-unentered iterator;
    // a reached loop failure drops its iterator before digest/frame locals.
    let mut records = Some(records);
    let mut sequence = first_sequence;
    let mut frames = Vec::with_capacity(
        records.as_ref().ok_or(FrameError::MissingRetainedPayload)?.len() + 2,
    );
    // Options preserve the old native activation/drop order: the digest is
    // created only after BEGIN's sequence step; COMMIT only after all records.
    let mut transaction_digest = None;
    let mut commit = None;
    let outcome = (|| {
        frames.push(encode_frame(
            FrameKind::Begin, sequence, transaction_id, &record_count.to_le_bytes(),
        )?);
        sequence = sequence.checked_add(1).ok_or(FrameError::SequenceExhausted)?;
        transaction_digest = Some(transaction_hasher());
        for record in records.take().ok_or(FrameError::MissingRetainedPayload)? {
            let payload = encode_record_fields(record.namespace_byte, record.key, record.value)?;
            let digest = transaction_digest.as_mut().ok_or(FrameError::MissingRetainedPayload)?;
            digest.update(&payload);
            let encoded = encode_frame(FrameKind::Record, sequence, transaction_id, &payload);
            let encoded = match encoded {
                Ok(encoded) => encoded,
                Err(cause) => {
                    if let Some(original) = original.as_deref_mut() {
                        original.payload = Some(payload);
                    }
                    return Err(cause);
                }
            };
            frames.push(encoded);
            sequence = match sequence.checked_add(1) {
                Some(next) => next,
                None => {
                    if let Some(original) = original.as_deref_mut() {
                        original.payload = Some(payload);
                    }
                    return Err(FrameError::SequenceExhausted);
                }
            };
            // The current payload drops here after its complete iteration,
            // before the next record, exactly as in the ordinary encoder.
        }

        commit = Some(Vec::with_capacity(COMMIT_PAYLOAD_BYTES));
        let commit = commit.as_mut().ok_or(FrameError::MissingRetainedPayload)?;
        commit.extend_from_slice(&record_count.to_le_bytes());
        let digest = transaction_digest.take().ok_or(FrameError::MissingRetainedPayload)?;
        commit.extend_from_slice(&digest.finalize());
        frames.push(encode_frame(FrameKind::Commit, sequence, transaction_id, commit)?);
        Ok(())
    })();
    if let Err(cause) = outcome {
        if let Some(original) = original {
            original.frames = Some(frames);
            original.commit = commit;
            original.digest = transaction_digest;
            original.sequence = sequence;
            original.count = Some(record_count);
        }
        // Ordinary locals drop COMMIT, live digest, then frames. A failed
        // selected branch instead moves those same originals to its owner.
        return Err(cause);
    }
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
mod validation_tests;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::framing::read_frame_retained;

    fn decode_frames(frames: &[Vec<u8>]) -> Vec<Frame> {
        frames
            .iter()
            .map(|bytes| {
                read_frame_retained(&mut Cursor::new(bytes), 0, 1024, None)
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

#[cfg(test)]
mod encoder_retaining_tests {
    use super::*;

    fn records() -> impl ExactSizeIterator<Item = NativeRecordRef<'static>> {
        [NativeRecordRef { namespace_byte: 1, key: b"key", value: Some(b"value") }].into_iter()
    }

    #[test]
    fn begin_and_record_sequence_refusals_keep_the_exact_reached_frame_prefix() {
        for (sequence, frames, payload) in [
            (u64::MAX, 1, None),
            (u64::MAX - 1, 2, Some(encode_record_fields(1, b"key", Some(b"value")).unwrap())),
        ] {
            let ordinary = encode_transaction([1; 16], sequence, records());
            let mut original = NativeTransactionEncodeOriginalsV1::new();
            let retained = encode_transaction_retaining_v1([1; 16], sequence, records(), &mut original);

            assert!(matches!(ordinary, Err(FrameError::SequenceExhausted)));
            assert!(matches!(retained, Err(FrameError::SequenceExhausted)));
            assert_eq!(original.frames().unwrap().len(), frames);
            assert_eq!(original.payload(), payload.as_deref());
            assert_eq!(original.sequence, u64::MAX);
            assert_eq!(original.count, Some(1));
            assert_eq!(original.digest.is_some(), frames == 2);
            let prefix = original.frames().unwrap().as_ptr();
            assert!(encode_transaction_retaining_v1([1; 16], 1, records(), &mut original).is_err());
            assert_eq!(original.frames().unwrap().as_ptr(), prefix);
        }
    }

    #[test]
    fn later_unrepresentable_record_keeps_begin_and_live_digest_without_a_second_encoder() {
        let key = vec![1; usize::from(u16::MAX) + 1];
        let records = || [NativeRecordRef { namespace_byte: 1, key: &key, value: Some(b"v") }].into_iter();
        let ordinary = encode_transaction([1; 16], 1, records());
        let mut original = NativeTransactionEncodeOriginalsV1::new();
        let retained = encode_transaction_retaining_v1([1; 16], 1, records(), &mut original);

        assert_eq!(ordinary.unwrap_err().to_string(), retained.unwrap_err().to_string());
        assert_eq!(original.frames().unwrap().len(), 1);
        assert!(original.payload().is_none());
        assert!(original.digest.is_some());
    }

    #[test]
    fn positive_retained_encoding_moves_same_complete_output_and_retires_leaf_scratch() {
        let ordinary = encode_transaction([1; 16], 1, records()).unwrap();
        let mut original = NativeTransactionEncodeOriginalsV1::new();
        let retained = encode_transaction_retaining_v1([1; 16], 1, records(), &mut original).unwrap();

        assert_eq!(retained, ordinary);
        assert!(original.frames().is_none());
        assert!(original.payload().is_none());
        assert!(original.commit().is_none());
        assert!(original.digest.is_none());
    }
}
