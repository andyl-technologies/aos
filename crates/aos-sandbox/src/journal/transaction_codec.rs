//! Domain journal transaction DATA, bounded validation, and canonical codecs.
//!
//! The module keeps the journal's typed record and transaction model with its
//! native encoding, preparation wrapper, and representation/configuration
//! checks. Closed namespace decoding and the Idempotency record schema remain
//! domain-owned here; they are not generic lower-journal admission. Protected
//! namespaces, before-image/currentness checks, semantic publication, and file
//! custody remain with the journal and its actual role owners.
//!
//! Preparation is ordinary transaction DATA, never a committed journal,
//! protected persistence proof, or authority. Wrapper integers are big endian;
//! native record fields retain their existing little-endian layout.
//!
//! ```text
//! native: namespace:u8 | key-length:u16le | value-length:u32le | key | value
//! preparation: AOSJPT01 | version:u16be=1 | reserved:u16be=0 |
//!              transaction-ID:16 | record-count:u32be |
//!              repeated(record-length:u32be | native-record-payload)
//! ```

use std::collections::BTreeSet;

use aos_sandbox_core::OperationId;
use aos_sandbox_journal::geometry::{
    EncodedRecordLayout, PREPARED_HEADER_BYTES as HEADER_BYTES, RecordShape,
};
use aos_sandbox_journal::record::{self, RecordHeader};
use aos_sandbox_journal::transaction::{self, NativeRecordRef};

use super::{IdempotencyKey, JournalError, JournalLimits, RecordNamespace};

const IDEMPOTENCY_VALUE_BYTES: usize = 48;

/// Describes one value replacement or deletion inside a journal transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    pub(super) namespace: RecordNamespace,
    pub(super) key: Vec<u8>,
    pub(super) value: Option<Vec<u8>>,
}

impl JournalRecord {
    /// Constructs a value replacement.
    #[must_use]
    pub fn put(namespace: RecordNamespace, key: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            namespace,
            key,
            value: Some(value),
        }
    }

    /// Constructs an idempotent deletion.
    #[must_use]
    pub fn delete(namespace: RecordNamespace, key: Vec<u8>) -> Self {
        Self {
            namespace,
            key,
            value: None,
        }
    }

    /// Constructs an idempotency decision record.
    #[must_use]
    pub fn idempotency(
        key: &IdempotencyKey,
        request_digest: [u8; 32],
        operation_id: OperationId,
    ) -> Self {
        let mut value = Vec::with_capacity(IDEMPOTENCY_VALUE_BYTES);
        value.extend_from_slice(&request_digest);
        value.extend_from_slice(operation_id.as_bytes());
        Self::put(RecordNamespace::Idempotency, key.as_bytes().to_vec(), value)
    }

    /// Returns the record keyspace.
    #[must_use]
    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    /// Returns the opaque record key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the replacement value, or `None` for a deletion.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

/// Carries one atomic group of desired-state and operation mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalTransaction {
    pub(super) id: [u8; 16],
    pub(super) records: Vec<JournalRecord>,
}

impl JournalTransaction {
    /// Constructs a transaction with a nonzero stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidTransaction`] when `id` is all zeroes or
    /// the transaction has no records.
    pub fn new(id: [u8; 16], records: Vec<JournalRecord>) -> Result<Self, JournalError> {
        if id == [0; 16] || records.is_empty() {
            return Err(JournalError::InvalidTransaction);
        }
        Ok(Self { id, records })
    }

    /// Returns the stable transaction identity.
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Returns the ordered records committed by this transaction.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }
}

pub(super) fn validate_transaction(
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if transaction.id == [0; 16] || transaction.records.is_empty() {
        return Err(JournalError::InvalidTransaction);
    }
    if transaction.records.len() > limits.maximum_records_per_transaction {
        return Err(JournalError::LimitExceeded("records per transaction"));
    }
    let mut keys = BTreeSet::new();
    let mut transaction_bytes = 0_usize;
    for record in &transaction.records {
        if record.key.is_empty() || record.key.len() > limits.maximum_key_bytes {
            return Err(JournalError::LimitExceeded("record key bytes"));
        }
        let payload_bytes = EncodedRecordLayout::new(
            record.key.len(),
            record.value.as_ref().map(|value| value.len()),
        )?
        .payload_bytes;
        if payload_bytes > limits.maximum_record_bytes {
            return Err(JournalError::LimitExceeded("record payload bytes"));
        }
        transaction_bytes = transaction_bytes
            .checked_add(payload_bytes)
            .ok_or(JournalError::LimitExceeded("transaction bytes"))?;
        if transaction_bytes > limits.maximum_transaction_bytes {
            return Err(JournalError::LimitExceeded("transaction bytes"));
        }
        if record.namespace == RecordNamespace::Idempotency {
            let value = record.value.as_ref().ok_or(JournalError::MalformedRecord(
                "idempotency records cannot be deleted",
            ))?;
            if IdempotencyKey::new(record.key.clone()).is_err()
                || value.len() != IDEMPOTENCY_VALUE_BYTES
                || value[32..] == [0; 16]
            {
                return Err(JournalError::MalformedRecord(
                    "invalid idempotency decision",
                ));
            }
        }
        if !keys.insert((record.namespace, record.key.clone())) {
            return Err(JournalError::DuplicateRecordKey);
        }
    }
    Ok(())
}

pub(crate) fn encoded_transaction_record_bytes(
    transaction: &JournalTransaction,
) -> Result<u64, JournalError> {
    transaction
        .records()
        .iter()
        .try_fold(0_u64, |total, record| {
            let layout = EncodedRecordLayout::new(
                record.key.len(),
                record.value.as_ref().map(|value| value.len()),
            )?;
            total
                .checked_add(layout.payload_bytes as u64)
                .ok_or(JournalError::JournalTooLarge)
        })
}

/// Measures canonical append framing without granting admission or capacity.
///
/// The measurement includes the begin and commit frames, every record frame,
/// and their checksums. It does not inspect a journal, reserve space, or validate
/// an owner's proposed transition.
///
/// The shared encoder layouts are checked without allocating buffers or hashing.
///
/// # Errors
///
/// Returns an error when a record length, record count, sequence, or aggregate
/// append length cannot be represented by the journal format.
pub fn encoded_transaction_append_bytes(
    transaction: &JournalTransaction,
) -> Result<u64, JournalError> {
    aos_sandbox_journal::geometry::encoded_transaction_append_bytes(
        transaction.records().iter().map(|record| RecordShape {
            key_bytes: record.key().len(),
            value_bytes: record.value().map(<[u8]>::len),
        }),
    )
    .map_err(JournalError::from)
}

pub(super) fn encode_record(record: &JournalRecord) -> Result<Vec<u8>, JournalError> {
    encode_record_fields(record.namespace, &record.key, record.value.as_deref())
}

// The private borrowed field view uses the same measured layout and encoder;
// retained Q04 before rows need not clone a temporary JournalRecord graph.
pub(super) fn encode_record_fields(
    namespace: RecordNamespace,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<Vec<u8>, JournalError> {
    record::encode_record_fields(namespace as u8, key, value).map_err(JournalError::from)
}

pub(super) fn decode_record(
    payload: &[u8],
    limits: JournalLimits,
) -> Result<JournalRecord, JournalError> {
    let header = RecordHeader::read(payload)?;
    let namespace = RecordNamespace::from_byte(header.namespace_byte())?;
    let fields = header.decode_fields(limits.maximum_key_bytes, limits.maximum_record_bytes)?;
    let key = fields.key.to_vec();
    let value = fields.value.map(<[u8]>::to_vec);
    Ok(JournalRecord {
        namespace,
        key,
        value,
    })
}

pub(super) fn encode_transaction(
    transaction: &JournalTransaction,
    first_sequence: u64,
) -> Result<Vec<Vec<u8>>, JournalError> {
    transaction::encode_transaction(
        transaction.id,
        first_sequence,
        transaction.records.iter().map(|record| NativeRecordRef {
            namespace_byte: record.namespace as u8,
            key: &record.key,
            value: record.value.as_deref(),
        }),
    )
    .map_err(JournalError::from)
}

const MAGIC: &[u8; 8] = b"AOSJPT01";

impl JournalTransaction {
    /// Returns the maximum bounded preparation width for the supplied native limits.
    ///
    /// This is sizing only and reserves no disk, memory, or journal capacity.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits or overflowing framing arithmetic.
    #[doc(hidden)]
    pub fn maximum_prepared_bytes_v1(limits: JournalLimits) -> Result<usize, JournalError> {
        aos_sandbox_journal::geometry::maximum_prepared_bytes(limits.into())
            .map_err(JournalError::from)
    }

    /// Encodes one exact bounded transaction without writing or committing it.
    ///
    /// Reuses the ordinary journal record encoder and validation, including
    /// namespace codes, put/delete representation, keys, and aggregate limits.
    ///
    /// # Errors
    ///
    /// Rejects invalid or oversized native records, duplicate keys, a zero ID,
    /// and framing fields exceeding their integer widths.
    #[doc(hidden)]
    pub fn encode_prepared_v1(&self, limits: JournalLimits) -> Result<Vec<u8>, JournalError> {
        let maximum_bytes = Self::maximum_prepared_bytes_v1(limits)?;
        validate_transaction(self, limits)?;
        let count = u32::try_from(self.records.len())
            .map_err(|_| JournalError::LimitExceeded("prepared record count"))?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&count.to_be_bytes());
        for record in &self.records {
            let payload = encode_record(record)?;
            let length = u32::try_from(payload.len())
                .map_err(|_| JournalError::LimitExceeded("prepared record bytes"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&payload);
        }
        if bytes.len() > maximum_bytes {
            return Err(JournalError::LimitExceeded("prepared transaction bytes"));
        }
        Ok(bytes)
    }

    /// Decodes only an exact bounded preparation, not a committed journal frame.
    ///
    /// The result is ordinary transaction data. A protected owner must separately
    /// validate provenance, exact predecessor/current HEAD, and admission limits.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing/version/reserved bytes, truncation or padding,
    /// zero IDs, count/record/aggregate overflow, and malformed native records.
    #[doc(hidden)]
    pub fn decode_prepared_v1(bytes: &[u8], limits: JournalLimits) -> Result<Self, JournalError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > Self::maximum_prepared_bytes_v1(limits)?
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[8..12] != [0, 1, 0, 0]
        {
            return Err(JournalError::MalformedTransaction(
                "invalid preparation framing",
            ));
        }
        let id = read_array(bytes, 12)?;
        if id == [0; 16] {
            return Err(JournalError::InvalidTransaction);
        }
        let count = usize::try_from(u32::from_be_bytes(read_array(bytes, 28)?))
            .map_err(|_| JournalError::LimitExceeded("prepared record count"))?;
        if count == 0
            || count > limits.maximum_records_per_transaction
            || count
                .checked_mul(12)
                .and_then(|minimum| minimum.checked_add(HEADER_BYTES))
                .is_none_or(|minimum| minimum > bytes.len())
        {
            return Err(JournalError::LimitExceeded("prepared record count"));
        }
        let mut cursor = HEADER_BYTES;
        let mut records = Vec::with_capacity(count);
        let mut payload_bytes = 0_usize;
        for _ in 0..count {
            let length = usize::try_from(u32::from_be_bytes(read_array(bytes, cursor)?))
                .map_err(|_| JournalError::LimitExceeded("prepared record bytes"))?;
            cursor = cursor
                .checked_add(4)
                .ok_or(JournalError::LimitExceeded("prepared transaction bytes"))?;
            if length < 7 || length > limits.maximum_record_bytes {
                return Err(JournalError::LimitExceeded("prepared record bytes"));
            }
            let end = cursor
                .checked_add(length)
                .ok_or(JournalError::LimitExceeded("prepared transaction bytes"))?;
            let payload = bytes
                .get(cursor..end)
                .ok_or(JournalError::MalformedTransaction("truncated preparation"))?;
            payload_bytes = payload_bytes
                .checked_add(length)
                .filter(|total| *total <= limits.maximum_transaction_bytes)
                .ok_or(JournalError::LimitExceeded("transaction bytes"))?;
            records.push(decode_record(payload, limits)?);
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(JournalError::MalformedTransaction("padded preparation"));
        }
        let transaction = Self::new(id, records)?;
        validate_transaction(&transaction, limits)?;
        Ok(transaction)
    }
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    let end = offset
        .checked_add(N)
        .ok_or(JournalError::LimitExceeded("prepared transaction bytes"))?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(JournalError::MalformedTransaction("truncated preparation"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalRecord, RecordNamespace};

    fn transaction() -> JournalTransaction {
        JournalTransaction::new(
            [7; 16],
            vec![
                JournalRecord::put(RecordNamespace::BrokerSessionTraffic, b"a".to_vec(), vec![]),
                JournalRecord::delete(RecordNamespace::BrokerSessionTraffic, b"b".to_vec()),
            ],
        )
        .unwrap()
    }

    #[test]
    fn journal_prepared_transaction_roundtrip_preserves_identity_order_and_empty_put() {
        let transaction = transaction();
        let bytes = transaction
            .encode_prepared_v1(JournalLimits::default())
            .unwrap();
        assert_eq!(
            JournalTransaction::decode_prepared_v1(&bytes, JournalLimits::default()).unwrap(),
            transaction
        );
        assert_eq!(
            &bytes[..32],
            &[
                b"AOSJPT01".as_slice(),
                &[0, 1, 0, 0],
                &[7; 16],
                &[0, 0, 0, 2]
            ]
            .concat()
        );
        // Literal native payloads, independently laid out from the existing
        // record format: namespace47, key length LE, value length LE (or delete).
        assert_eq!(
            &bytes[32..],
            &[
                0, 0, 0, 8, 47, 1, 0, 0, 0, 0, 0, b'a', 0, 0, 0, 8, 47, 1, 0, 255, 255, 255, 255,
                b'b',
            ]
        );
    }

    #[test]
    fn journal_prepared_transaction_rejects_hostile_framing_and_native_payload() {
        let bytes = transaction()
            .encode_prepared_v1(JournalLimits::default())
            .unwrap();
        for offset in [0, 8, 9, 10, 11, 31] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                JournalTransaction::decode_prepared_v1(&changed, JournalLimits::default()).is_err(),
                "offset {offset}"
            );
        }
        for end in 0..bytes.len() {
            assert!(
                JournalTransaction::decode_prepared_v1(&bytes[..end], JournalLimits::default())
                    .is_err()
            );
        }
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(JournalTransaction::decode_prepared_v1(&padded, JournalLimits::default()).is_err());
        let mut zero_id = bytes.clone();
        zero_id[12..28].fill(0);
        assert!(
            JournalTransaction::decode_prepared_v1(&zero_id, JournalLimits::default()).is_err()
        );
        let mut overflowing = bytes;
        overflowing[32..36].fill(255);
        assert!(
            JournalTransaction::decode_prepared_v1(&overflowing, JournalLimits::default()).is_err()
        );
    }

    #[test]
    fn journal_prepared_transaction_checks_actual_native_and_aggregate_limits() {
        let transaction = transaction();
        let bytes = transaction
            .encode_prepared_v1(JournalLimits::default())
            .unwrap();
        for limits in [
            JournalLimits {
                maximum_records_per_transaction: 1,
                ..JournalLimits::default()
            },
            JournalLimits {
                maximum_record_bytes: 7,
                ..JournalLimits::default()
            },
            JournalLimits {
                maximum_transaction_bytes: 7,
                ..JournalLimits::default()
            },
        ] {
            assert!(transaction.encode_prepared_v1(limits).is_err());
            assert!(JournalTransaction::decode_prepared_v1(&bytes, limits).is_err());
        }
    }
}
