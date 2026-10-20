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

mod preflight_digest;
pub use preflight_digest::transaction_preflight_comparison_digest_v1;

use aos_sandbox_core::{OperationId, RecordNamespace};
use aos_sandbox_journal::geometry::NativeGeometryBounds;
use aos_sandbox_journal::materialized::RecordMutationRef;

use super::JournalTransactionDataError;
use aos_sandbox_journal::geometry::{
    EncodedRecordLayout, PREPARED_HEADER_BYTES as HEADER_BYTES, RecordShape,
};
use aos_sandbox_journal::record::{self, RecordHeader};
use aos_sandbox_journal::transaction::{
    self, NativeRecordRef, NativeRecordValidation, NativeRecordValidationError, NativeRecordKeyIndexV1,
};

/// Bounds all disk input and in-memory work performed while opening a journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
    /// Maximum journal length accepted during replay.
    pub maximum_journal_bytes: u64,
    /// Maximum payload bytes in one record frame.
    pub maximum_record_bytes: usize,
    /// Maximum key bytes in one record.
    pub maximum_key_bytes: usize,
    /// Maximum records admitted in one transaction.
    pub maximum_records_per_transaction: usize,
    /// Maximum aggregate encoded record bytes admitted in one transaction.
    pub maximum_transaction_bytes: usize,
    /// Maximum committed transactions accepted during replay.
    pub maximum_transactions: usize,
    /// Maximum logical key and value bytes retained by the materialized view.
    pub maximum_materialized_bytes: usize,
    /// Maximum entries retained by the materialized view.
    pub maximum_materialized_records: usize,
}

// This scalar view carries no owner, reserved capacity, or admission result.
impl From<JournalLimits> for NativeGeometryBounds {
    fn from(limits: JournalLimits) -> Self {
        Self {
            maximum_journal_bytes: limits.maximum_journal_bytes,
            maximum_record_bytes: limits.maximum_record_bytes,
            maximum_key_bytes: limits.maximum_key_bytes,
            maximum_records_per_transaction: limits.maximum_records_per_transaction,
            maximum_transaction_bytes: limits.maximum_transaction_bytes,
            maximum_transactions: limits.maximum_transactions,
            maximum_materialized_bytes: limits.maximum_materialized_bytes,
            maximum_materialized_records: limits.maximum_materialized_records,
        }
    }
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_key_bytes: 1024,
            maximum_records_per_transaction: 4096,
            maximum_transaction_bytes: 64 * 1024 * 1024,
            maximum_transactions: 1_000_000,
            maximum_materialized_bytes: 512 * 1024 * 1024,
            maximum_materialized_records: 1_000_000,
        }
    }
}

/// Stores a bounded, nonempty opaque client idempotency key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(Vec<u8>);

impl IdempotencyKey {
    /// Validates a client idempotency key.
    ///
    /// # Errors
    ///
    /// Returns [`JournalTransactionDataError::InvalidIdempotencyKey`] for an empty key or a
    /// key longer than 128 bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, JournalTransactionDataError> {
        let bytes = bytes.into();
        Self::validate_bytes(&bytes)?;
        Ok(Self(bytes))
    }

    fn validate_bytes(bytes: &[u8]) -> Result<(), JournalTransactionDataError> {
        if bytes.is_empty() || bytes.len() > 128 {
            return Err(JournalTransactionDataError::InvalidIdempotencyKey);
        }
        Ok(())
    }

    fn from_retained_input(bytes: &mut Option<Vec<u8>>) -> Result<Self, JournalTransactionDataError> {
        Self::validate_bytes(bytes.as_deref().ok_or(JournalTransactionDataError::InvalidIdempotencyKey)?)?;
        Ok(Self(bytes.take().ok_or(JournalTransactionDataError::InvalidIdempotencyKey)?))
    }

    /// Returns the exact opaque key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

const IDEMPOTENCY_VALUE_BYTES: usize = 48;

/// Returns the canonical idempotency decision's fixed value width.
#[must_use]
pub const fn idempotency_value_encoded_bytes_v1() -> usize { IDEMPOTENCY_VALUE_BYTES }

/// Describes one value replacement or deletion inside a journal transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    namespace: RecordNamespace,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

impl<'a> From<&'a JournalRecord> for RecordMutationRef<'a, RecordNamespace> {
    fn from(record: &'a JournalRecord) -> Self {
        Self {
            namespace: record.namespace(),
            key: record.key(),
            value: record.value(),
        }
    }
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
    id: [u8; 16],
    records: Vec<JournalRecord>,
}

impl JournalTransaction {
    /// Constructs a transaction with a nonzero stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`JournalTransactionDataError::InvalidTransaction`] when `id` is all zeroes or
    /// the transaction has no records.
    pub fn new(
        id: [u8; 16],
        records: Vec<JournalRecord>,
    ) -> Result<Self, JournalTransactionDataError> {
        if id == [0; 16] || records.is_empty() {
            return Err(JournalTransactionDataError::InvalidTransaction);
        }
        Ok(Self { id, records })
    }

    /// Constructs explicitly unvalidated transaction DATA without admission.
    ///
    /// The caller must run ordinary transaction validation at the physical owner's
    /// original boundary. This does not establish currentness, capacity, or commit.
    #[must_use]
    pub fn from_unvalidated_data(id: [u8; 16], records: Vec<JournalRecord>) -> Self {
        Self { id, records }
    }

    /// Returns the stable transaction identity.
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Returns the ordered transaction record DATA.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }
}

/// Validates bounded typed transaction DATA without physical admission.
///
/// # Errors
///
/// Rejects zero identity, empty or oversized records, invalid Idempotency DATA, and duplicate keys.
pub fn validate_transaction(
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalTransactionDataError> {
    validate_transaction_engine(transaction, limits, None)
}

fn validate_transaction_engine(
    transaction: &JournalTransaction,
    limits: JournalLimits,
    retained: Option<&mut TransactionValidationCaptureV1>,
) -> Result<(), JournalTransactionDataError> {
    let (index, mut idempotency) = match retained {
        Some(retained) => (Some(&mut retained.index), Some(&mut retained.idempotency)),
        None => (None, None),
    };
    let mut validation = match index {
        Some(retained) => NativeRecordValidation::begin_retaining_v1(
            transaction.id, transaction.records.len(), limits.into(), retained),
        None => NativeRecordValidation::begin(transaction.id, transaction.records.len(), limits.into()),
    }.map_err(native_record_validation_error)?;
    for record in &transaction.records {
        validate_finality_admission_fields(record.namespace, &record.key, record.value.as_deref())?;
        validation
            .observe_extent(&record.key, record.value.as_ref().map(|value| value.len()))
            .map_err(native_record_validation_error)?;

        if record.namespace == RecordNamespace::Idempotency {
            let value =
                record
                    .value
                    .as_ref()
                    .ok_or(JournalTransactionDataError::MalformedRecord(
                        "idempotency records cannot be deleted",
                    ))?;
            let invalid_key = match idempotency.as_deref_mut() {
                None => IdempotencyKey::new(record.key.clone()).is_err(),
                Some(original) => {
                    original.input = Some(record.key.clone());
                    original.outcome = Some(IdempotencyKey::from_retained_input(&mut original.input));
                    matches!(original.outcome, Some(Err(_)))
                }
            };
            if invalid_key
                || value.len() != IDEMPOTENCY_VALUE_BYTES
                || value[32..] == [0; 16]
            {
                return Err(JournalTransactionDataError::MalformedRecord(
                    "invalid idempotency decision",
                ));
            }
        }

        validation
            .register_key(record.namespace as u8, &record.key)
            .map_err(native_record_validation_error)?;
    }
    Ok(())
}

/// Retains the actual structural validator's index and returned classification.
///
/// This owns DATA only. It neither binds a file nor grants record admission.
#[derive(Default)]
pub struct TransactionValidationCaptureV1 {
    index: NativeRecordKeyIndexV1,
    idempotency: IdempotencyValidationCaptureV1,
    outcome: Option<Result<(), JournalTransactionDataError>>,
    reentered: bool,
}

impl TransactionValidationCaptureV1 {
    /// Creates empty fixed destinations without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { index: NativeRecordKeyIndexV1::new(),
            idempotency: IdempotencyValidationCaptureV1 { input: None, outcome: None },
            outcome: None, reentered: false }
    }

    /// Counts all added fixed capture and native-stage control destinations.
    ///
    /// Besides the lower tree/current owners, this counts Idempotency input
    /// and typed Result, final Result and reentry flag, and the transient
    /// native validation carrier and its constructor Result. Inline bytes are
    /// separately included by the actual replay owner layout.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        NativeRecordKeyIndexV1::receiving_metadata_cells_v1().checked_add(2)?
            .checked_add(2)?.checked_add(2)
    }

    /// Borrows the actual reached key index even after a later typed refusal.
    #[must_use]
    pub fn index_v1(&self) -> &NativeRecordKeyIndexV1 { &self.index }

    /// Borrows the original returned structural refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&JournalTransactionDataError> {
        self.idempotency.outcome.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err()))
    }
}

#[derive(Default)]
struct IdempotencyValidationCaptureV1 {
    input: Option<Vec<u8>>,
    outcome: Option<Result<IdempotencyKey, JournalTransactionDataError>>,
}

/// Runs the sole transaction validator with an actual once-owned index.
///
/// # Errors
/// Retains the same identity, extent, Idempotency or duplicate failure; repeated
/// entry refuses without replacing the first reached index or outcome.
pub fn validate_transaction_retaining_v1(
    transaction: &JournalTransaction,
    limits: JournalLimits,
    capture: &mut TransactionValidationCaptureV1,
) -> Result<(), JournalTransactionDataError> {
    if capture.outcome.is_some() {
        capture.reentered = true;
        return Err(JournalTransactionDataError::InvalidTransaction);
    }
    let result = validate_transaction_engine(transaction, limits, Some(&mut *capture));
    capture.outcome = Some(result);
    if matches!(capture.outcome, Some(Ok(()))) { Ok(()) }
    else { Err(JournalTransactionDataError::InvalidTransaction) }
}

fn native_record_validation_error(
    error: NativeRecordValidationError,
) -> JournalTransactionDataError {
    match error {
        NativeRecordValidationError::InvalidTransaction => {
            JournalTransactionDataError::InvalidTransaction
        }
        NativeRecordValidationError::DuplicateRecordKey => {
            JournalTransactionDataError::DuplicateRecordKey
        }
        NativeRecordValidationError::LimitExceeded(bound) => {
            JournalTransactionDataError::LimitExceeded(bound)
        }
        NativeRecordValidationError::Frame(
            aos_sandbox_journal::framing::FrameError::LimitExceeded(bound),
        ) => JournalTransactionDataError::LimitExceeded(bound),
        NativeRecordValidationError::Frame(error) => JournalTransactionDataError::from(error),
    }
}

/// Measures aggregate canonical record-payload DATA without allocating encodings.
///
/// # Errors
///
/// Rejects unrepresentable record extents or aggregate byte overflow.
pub fn encoded_transaction_record_bytes(
    transaction: &JournalTransaction,
) -> Result<u64, JournalTransactionDataError> {
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
                .ok_or(JournalTransactionDataError::JournalTooLarge)
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
) -> Result<u64, JournalTransactionDataError> {
    aos_sandbox_journal::geometry::encoded_transaction_append_bytes(
        transaction.records().iter().map(|record| RecordShape {
            key_bytes: record.key().len(),
            value_bytes: record.value().map(<[u8]>::len),
        }),
    )
    .map_err(JournalTransactionDataError::from)
}

/// Encodes one typed record as canonical native payload DATA.
///
/// # Errors
///
/// Rejects unrepresentable key or value lengths.
pub fn encode_record(record: &JournalRecord) -> Result<Vec<u8>, JournalTransactionDataError> {
    encode_record_fields(record.namespace, &record.key, record.value.as_deref())
}

// The private borrowed field view uses the same measured layout and encoder;
// retained Q04 before rows need not clone a temporary JournalRecord graph.
/// Encodes a borrowed typed record without cloning its key or value.
///
/// # Errors
///
/// Rejects unrepresentable key or value lengths.
pub fn encode_record_fields(
    namespace: RecordNamespace,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<Vec<u8>, JournalTransactionDataError> {
    record::encode_record_fields(namespace as u8, key, value)
        .map_err(JournalTransactionDataError::from)
}

/// Decodes one canonical native payload using closed domain namespaces.
///
/// # Errors
///
/// Rejects a truncated header, unknown namespace, or invalid bounded key/value layout.
pub fn decode_record(
    payload: &[u8],
    limits: JournalLimits,
) -> Result<JournalRecord, JournalTransactionDataError> {
    let header = RecordHeader::read(payload)?;
    let namespace = RecordNamespace::from_byte(header.namespace_byte())?;
    let fields = header.decode_fields(limits.maximum_key_bytes, limits.maximum_record_bytes)?;
    validate_finality_admission_fields(namespace, fields.key, fields.value)?;
    let key = fields.key.to_vec();
    let value = fields.value.map(<[u8]>::to_vec);
    Ok(JournalRecord {
        namespace,
        key,
        value,
    })
}

// This newly introduced family is borrowed and allocation-free at the sole
// typed native decoder. Role authority and all other schemas stay separate.
fn validate_finality_admission_fields(namespace: RecordNamespace, key: &[u8], value: Option<&[u8]>)
    -> Result<(), JournalTransactionDataError> {
    use super::provisioning_root::finality_recover::CreateFinalityObservationAdmissionDataV1 as Data;
    if namespace == RecordNamespace::OperatorRecovery && Data::is_admission_key_v1(key) {
        Data::require_record_v1(key, value.ok_or(JournalTransactionDataError::MalformedRecord(
            "finality observation admission cannot be deleted"))?)
            .map_err(|_|JournalTransactionDataError::MalformedRecord("finality observation admission"))?;
    }
    Ok(())
}

/// Encodes canonical transaction frames without appending them.
///
/// # Errors
///
/// Rejects sequence, count, record, or aggregate framing overflow.
pub fn encode_transaction(
    transaction: &JournalTransaction,
    first_sequence: u64,
) -> Result<Vec<Vec<u8>>, JournalTransactionDataError> {
    transaction::encode_transaction(
        transaction.id,
        first_sequence,
        transaction.records.iter().map(|record| NativeRecordRef {
            namespace_byte: record.namespace as u8,
            key: &record.key,
            value: record.value.as_deref(),
        }),
    )
    .map_err(JournalTransactionDataError::from)
}

mod prepared;
pub use prepared::PreparedTransactionDecodeCaptureV1;

const MAGIC: &[u8; 8] = b"AOSJPT01";

/// Retains the sole preparation encoder's validation and failed byte prefix.
///
/// Construction is inert DATA. No Journal, writer, framing acceptance, capacity
/// or native completion is issued. A real caller prepays receiving_demand_v2
/// and retains this original plus its complete returned classification.
#[derive(Default)]
pub struct PreparedTransactionEncodeCaptureV2 {
    validation: TransactionValidationCaptureV1,
    bytes: Vec<u8>,
    record: Option<Result<Vec<u8>, JournalTransactionDataError>>,
    completed: Option<Vec<u8>>,
    result: Option<Result<(), JournalTransactionDataError>>,
    entered: bool,
}

impl PreparedTransactionEncodeCaptureV2 {
    /// Creates empty validation and encoding destinations without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { validation: TransactionValidationCaptureV1::new(), bytes: Vec::new(),
            record: None, completed: None, result: None, entered: false }
    }

    /// Prices exact output, one record scratch and the actual owned key index.
    ///
    /// This uses the source transaction's real widths before growth. Only
    /// duplicate-index entries count as names; control and codec fields add
    /// bytes, and the opaque preparation bytes add no namespace entries.
    ///
    /// Returns `None` on invalid geometry or checked arithmetic overflow.
    #[must_use]
    pub fn receiving_demand_v2(transaction: &JournalTransaction, limits: JournalLimits)
        -> Option<aos_sandbox_core::ResourceVector>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let encoded = transaction.prepared_encoded_bytes_v2(limits).ok()?;
        let mut keys = 0usize;
        let mut largest_key = 0usize;
        let mut largest_payload = 0usize;
        for record in transaction.records() {
            keys = keys.checked_add(record.key.len())?;
            largest_key = largest_key.max(record.key.len());
            let payload = EncodedRecordLayout::new(record.key.len(),
                record.value.as_ref().map(Vec::len)).ok()?.payload_bytes;
            largest_payload = largest_payload.max(payload);
        }
        let index = NativeRecordKeyIndexV1::dynamic_bytes_v1(
            transaction.records().len(), keys, largest_key,
        )?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(index)?.checked_add(encoded)?.checked_add(largest_payload)?
            .checked_add(largest_key)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::MetadataEntries, u64::try_from(transaction.records().len()).ok()?))
    }

    /// Runs the same bounded encoder once while retaining a failed prefix.
    ///
    /// # Errors
    /// Returns the existing coarse invalid-transaction refusal while failure()
    /// borrows the original validation, record or framing cause. Reentry keeps
    /// all first results and allocated prefixes unchanged.
    pub fn encode_once_v2(&mut self, transaction: &JournalTransaction, limits: JournalLimits)
        -> Result<(), JournalTransactionDataError>
    {
        if self.entered { return Err(JournalTransactionDataError::InvalidTransaction); }
        self.entered = true;
        match transaction.encode_prepared_engine_v2(limits, Some(&mut *self)) {
            Ok(bytes) => {
                self.completed = Some(bytes);
                self.result = Some(Ok(()));
                Ok(())
            }
            Err(cause) => {
                self.result = Some(Err(cause));
                Err(JournalTransactionDataError::InvalidTransaction)
            }
        }
    }

    /// Moves the exact positive encoded DATA once, leaving the one-shot fence.
    #[must_use]
    pub fn take_completed_v2(&mut self) -> Option<Vec<u8>> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        self.completed.take()
    }

    /// Borrows the earliest actual validator, record or encoder refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&JournalTransactionDataError> {
        self.validation.failure()
            .or_else(|| self.record.as_ref()?.as_ref().err())
            .or_else(|| self.result.as_ref()?.as_ref().err())
    }
}

impl JournalTransaction {
    /// Returns the maximum bounded preparation width for the supplied native limits.
    ///
    /// This is sizing only and reserves no disk, memory, or journal capacity.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits or overflowing framing arithmetic.
    #[doc(hidden)]
    pub fn maximum_prepared_bytes_v1(
        limits: JournalLimits,
    ) -> Result<usize, JournalTransactionDataError> {
        aos_sandbox_journal::geometry::maximum_prepared_bytes(limits.into())
            .map_err(JournalTransactionDataError::from)
    }

    /// Measures this actual transaction's owned record and byte capacities.
    ///
    /// This passive resident bound includes the transaction inline layout, its
    /// real ordered record allocation, and each actual key/value allocation.
    /// It performs no allocation, clone, parse, observation or admission.
    ///
    /// Returns `None` on checked width overflow.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_receiving_bytes_v2(&self) -> Option<usize> {
        let records = self.records.capacity().checked_mul(std::mem::size_of::<JournalRecord>())?;
        self.records.iter().try_fold(std::mem::size_of::<Self>().checked_add(records)?,
            |bytes, record| bytes.checked_add(record.key.capacity())?
                .checked_add(record.value.as_ref().map_or(0, Vec::capacity)))
    }

    /// Measures this transaction's exact preparation wrapper without encoding.
    ///
    /// The shared native record layout and preparation framing supply these
    /// passive bytes. This performs no allocation, namespace/duplicate-key
    /// admission, capacity reservation, hashing or journal observation.
    ///
    /// # Errors
    /// Rejects invalid limits, unrepresentable native fields/counts or a width
    /// exceeding the format's bounded preparation maximum.
    #[doc(hidden)]
    pub fn prepared_encoded_bytes_v2(&self, limits: JournalLimits)
        -> Result<usize, JournalTransactionDataError>
    {
        let maximum = Self::maximum_prepared_bytes_v1(limits)?;
        let bytes = aos_sandbox_journal::geometry::encoded_prepared_bytes(
            self.records.iter().map(|record| RecordShape {
                key_bytes: record.key.len(), value_bytes: record.value.as_ref().map(Vec::len),
            }),
        )?;
        if bytes > maximum {
            return Err(JournalTransactionDataError::LimitExceeded("prepared transaction bytes"));
        }
        Ok(bytes)
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
    pub fn encode_prepared_v1(
        &self,
        limits: JournalLimits,
    ) -> Result<Vec<u8>, JournalTransactionDataError> {
        self.encode_prepared_engine_v2(limits, None)
    }

    fn encode_prepared_engine_v2(&self, limits: JournalLimits,
        mut capture: Option<&mut PreparedTransactionEncodeCaptureV2>)
        -> Result<Vec<u8>, JournalTransactionDataError>
    {
        let maximum_bytes = Self::maximum_prepared_bytes_v1(limits)?;
        match capture.as_deref_mut() {
            Some(original) => validate_transaction_retaining_v1(self, limits, &mut original.validation)?,
            None => validate_transaction(self, limits)?,
        }
        let encoded_bytes = self.prepared_encoded_bytes_v2(limits)?;
        let count = u32::try_from(self.records.len())
            .map_err(|_| JournalTransactionDataError::LimitExceeded("prepared record count"))?;
        // Ordinary encoding owns only its original byte/payload locals. A
        // selected encoding borrows disjoint actual destinations; no complete
        // capture-sized owner is constructed on the ordinary stack.
        let mut ordinary_bytes;
        let (bytes, mut record_slot) = match capture {
            Some(original) => {
                original.bytes = Vec::with_capacity(encoded_bytes);
                (&mut original.bytes, Some(&mut original.record))
            }
            None => {
                ordinary_bytes = Vec::with_capacity(encoded_bytes);
                (&mut ordinary_bytes, None)
            }
        };
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&count.to_be_bytes());
        for record in &self.records {
            let ordinary_payload;
            let payload = match record_slot.as_deref_mut() {
                Some(slot) => {
                    *slot = Some(encode_record(record));
                    match slot.as_ref() {
                        Some(Ok(payload)) => payload,
                        _ => return Err(JournalTransactionDataError::InvalidTransaction),
                    }
                }
                None => {
                    ordinary_payload = encode_record(record)?;
                    &ordinary_payload
                }
            };
            let length = u32::try_from(payload.len())
                .map_err(|_| JournalTransactionDataError::LimitExceeded("prepared record bytes"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(payload);
            // A copied positive record ends at the same iteration boundary.
            if let Some(slot) = record_slot.as_deref_mut() { *slot = None; }
        }
        if bytes.len() > maximum_bytes || bytes.len() != encoded_bytes {
            return Err(JournalTransactionDataError::LimitExceeded(
                "prepared transaction bytes",
            ));
        }
        Ok(std::mem::take(bytes))
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
    pub fn decode_prepared_v1(
        bytes: &[u8],
        limits: JournalLimits,
    ) -> Result<Self, JournalTransactionDataError> {
        Self::decode_prepared_engine(bytes, limits, None)
    }

    fn decode_prepared_engine(
        bytes: &[u8], limits: JournalLimits,
        mut capture: Option<&mut PreparedTransactionDecodeCaptureV1>,
    ) -> Result<Self, JournalTransactionDataError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > Self::maximum_prepared_bytes_v1(limits)?
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[8..12] != [0, 1, 0, 0]
        {
            return Err(JournalTransactionDataError::MalformedTransaction(
                "invalid preparation framing",
            ));
        }
        let id = read_array(bytes, 12)?;
        if id == [0; 16] {
            return Err(JournalTransactionDataError::InvalidTransaction);
        }
        let count = usize::try_from(u32::from_be_bytes(read_array(bytes, 28)?))
            .map_err(|_| JournalTransactionDataError::LimitExceeded("prepared record count"))?;
        if count == 0
            || count > limits.maximum_records_per_transaction
            || count
                .checked_mul(12)
                .and_then(|minimum| minimum.checked_add(HEADER_BYTES))
                .is_none_or(|minimum| minimum > bytes.len())
        {
            return Err(JournalTransactionDataError::LimitExceeded(
                "prepared record count",
            ));
        }
        let mut cursor = HEADER_BYTES;
        let mut ordinary_records;
        let records = match capture.as_deref_mut() {
            Some(original) => {
                original.records = Vec::with_capacity(count);
                &mut original.records
            }
            None => {
                ordinary_records = Vec::with_capacity(count);
                &mut ordinary_records
            }
        };
        let mut payload_bytes = 0_usize;
        for _ in 0..count {
            let length = usize::try_from(u32::from_be_bytes(read_array(bytes, cursor)?))
                .map_err(|_| JournalTransactionDataError::LimitExceeded("prepared record bytes"))?;
            cursor = cursor
                .checked_add(4)
                .ok_or(JournalTransactionDataError::LimitExceeded(
                    "prepared transaction bytes",
                ))?;
            if length < 7 || length > limits.maximum_record_bytes {
                return Err(JournalTransactionDataError::LimitExceeded(
                    "prepared record bytes",
                ));
            }
            let end =
                cursor
                    .checked_add(length)
                    .ok_or(JournalTransactionDataError::LimitExceeded(
                        "prepared transaction bytes",
                    ))?;
            let payload =
                bytes
                    .get(cursor..end)
                    .ok_or(JournalTransactionDataError::MalformedTransaction(
                        "truncated preparation",
                    ))?;
            payload_bytes = payload_bytes
                .checked_add(length)
                .filter(|total| *total <= limits.maximum_transaction_bytes)
                .ok_or(JournalTransactionDataError::LimitExceeded(
                    "transaction bytes",
                ))?;
            records.push(decode_record(payload, limits)?);
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(JournalTransactionDataError::MalformedTransaction(
                "padded preparation",
            ));
        }
        let transaction = Self::new(id, std::mem::take(records))?;
        match capture {
            Some(original) => {
                // All framing is complete. Park the actual transaction before
                // the same validator can retain a later semantic refusal.
                original.transaction = Some(transaction);
                let transaction = original.transaction.as_ref()
                    .ok_or(JournalTransactionDataError::InvalidTransaction)?;
                validate_transaction_retaining_v1(transaction, limits, &mut original.validation)?;
                original.transaction.take().ok_or(JournalTransactionDataError::InvalidTransaction)
            }
            None => {
                validate_transaction(&transaction, limits)?;
                Ok(transaction)
            }
        }
    }
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], JournalTransactionDataError> {
    let end = offset
        .checked_add(N)
        .ok_or(JournalTransactionDataError::LimitExceeded(
            "prepared transaction bytes",
        ))?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(JournalTransactionDataError::MalformedTransaction(
            "truncated preparation",
        ))
}

#[cfg(test)]
mod tests {
    use super::JournalTransactionDataError as JournalError;
    use super::*;
    use super::{JournalRecord, RecordNamespace};

    #[test]
    fn idempotency_semantics_precede_duplicate_key_after_native_extent_checks() {
        let key = b"request".to_vec();
        let valid = vec![3; IDEMPOTENCY_VALUE_BYTES];
        let mut zero_operation = valid.clone();
        zero_operation[32..].fill(0);

        for (value, expected) in [
            (None, "idempotency records cannot be deleted"),
            (
                Some(vec![3; IDEMPOTENCY_VALUE_BYTES - 1]),
                "invalid idempotency decision",
            ),
            (Some(zero_operation), "invalid idempotency decision"),
        ] {
            let second = match value {
                Some(value) => JournalRecord::put(RecordNamespace::Idempotency, key.clone(), value),
                None => JournalRecord::delete(RecordNamespace::Idempotency, key.clone()),
            };
            let transaction = JournalTransaction::new(
                [1; 16],
                vec![
                    JournalRecord::put(RecordNamespace::Idempotency, key.clone(), valid.clone()),
                    second,
                ],
            )
            .unwrap();

            assert!(matches!(
                validate_transaction(&transaction, JournalLimits::default()),
                Err(JournalError::MalformedRecord(message)) if message == expected,
            ));
        }

        let duplicate = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(RecordNamespace::Idempotency, key.clone(), valid.clone()); 2],
        )
        .unwrap();
        assert!(matches!(
            validate_transaction(&duplicate, JournalLimits::default()),
            Err(JournalError::DuplicateRecordKey),
        ));

        let excessive = JournalTransaction::new(
            [1; 16],
            vec![
                JournalRecord::put(RecordNamespace::Idempotency, key.clone(), valid),
                JournalRecord::put(
                    RecordNamespace::Idempotency,
                    key,
                    vec![3; IDEMPOTENCY_VALUE_BYTES + 1],
                ),
            ],
        )
        .unwrap();
        let limits = JournalLimits {
            maximum_record_bytes: 7 + b"request".len() + IDEMPOTENCY_VALUE_BYTES,
            ..JournalLimits::default()
        };
        assert!(matches!(
            validate_transaction(&excessive, limits),
            Err(JournalError::LimitExceeded("record payload bytes")),
        ));
    }

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
        assert_eq!(transaction.prepared_encoded_bytes_v2(JournalLimits::default()).unwrap(), bytes.len());
        let mut retained = PreparedTransactionEncodeCaptureV2::new();
        retained.encode_once_v2(&transaction, JournalLimits::default()).unwrap();
        assert_eq!(retained.take_completed_v2().unwrap(), bytes);
        assert!(retained.take_completed_v2().is_none());
        assert!(retained.failure().is_none());
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

#[cfg(test)]
mod retaining_tests {
    use super::*;

    #[test]
    fn duplicate_refusal_keeps_actual_index_and_current_key_on_reentry() {
        let transaction = JournalTransaction::from_unvalidated_data([1; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![1]),
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![2]),
        ]);
        let mut capture = TransactionValidationCaptureV1::new();

        assert!(validate_transaction_retaining_v1(&transaction, JournalLimits::default(), &mut capture).is_err());

        assert!(matches!(validate_transaction(&transaction, JournalLimits::default()),
            Err(JournalTransactionDataError::DuplicateRecordKey)));
        assert!(matches!(capture.failure(), Some(JournalTransactionDataError::DuplicateRecordKey)));
        assert_eq!(capture.index_v1().retained_key_count_v1(), 1);
        assert_eq!(capture.index_v1().current_key_v1(), Some((RecordNamespace::Operation as u8, &[7][..])));
        let first = capture.failure().unwrap() as *const JournalTransactionDataError;
        assert!(validate_transaction_retaining_v1(&transaction, JournalLimits::default(), &mut capture).is_err());
        assert!(std::ptr::eq(first, capture.failure().unwrap()));
        assert_eq!(capture.index_v1().retained_key_count_v1(), 1);
    }

    #[test]
    fn later_extent_failure_keeps_previously_reached_original_keys() {
        let transaction = JournalTransaction::from_unvalidated_data([2; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![1]),
            JournalRecord::put(RecordNamespace::DesiredState, Vec::new(), vec![2]),
        ]);
        let mut capture = TransactionValidationCaptureV1::new();

        assert!(validate_transaction_retaining_v1(&transaction, JournalLimits::default(), &mut capture).is_err());

        assert!(matches!(capture.failure(), Some(JournalTransactionDataError::LimitExceeded("record key bytes"))));
        assert_eq!(capture.index_v1().retained_key_count_v1(), 1);
        assert!(capture.index_v1().current_key_v1().is_none());
    }

    #[test]
    fn invalid_idempotency_constructor_keeps_actual_cloned_input() {
        let transaction = JournalTransaction::from_unvalidated_data([4; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![1]),
            JournalRecord::put(RecordNamespace::Idempotency, vec![8; 129], vec![1; 48]),
        ]);
        let mut capture = TransactionValidationCaptureV1::new();

        assert!(validate_transaction_retaining_v1(&transaction, JournalLimits::default(), &mut capture).is_err());

        assert!(matches!(capture.failure(), Some(JournalTransactionDataError::InvalidIdempotencyKey)));
        assert_eq!(capture.idempotency.input.as_deref(), Some(&[8; 129][..]));
        assert_eq!(capture.index_v1().retained_key_count_v1(), 1);
    }

    #[test]
    fn later_idempotency_shape_keeps_original_typed_key_and_prior_index() {
        let transaction = JournalTransaction::from_unvalidated_data([3; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![1]),
            JournalRecord::put(RecordNamespace::Idempotency, vec![8], vec![0; 47]),
        ]);
        let mut capture = TransactionValidationCaptureV1::new();

        assert!(validate_transaction_retaining_v1(&transaction, JournalLimits::default(), &mut capture).is_err());

        assert!(matches!(capture.failure(), Some(JournalTransactionDataError::MalformedRecord("invalid idempotency decision"))));
        assert_eq!(capture.index_v1().retained_key_count_v1(), 1);
        assert_eq!(capture.idempotency.outcome.as_ref().unwrap().as_ref().unwrap().as_bytes(), &[8]);
        assert!(capture.idempotency.input.is_none());
    }
}


#[cfg(test)]
mod prepared_encoding_retention_tests {
    use super::*;

    #[test]
    fn duplicate_preparation_keeps_its_actual_index_and_original_cause() {
        let transaction = JournalTransaction::new([1; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![1]),
            JournalRecord::put(RecordNamespace::Operation, vec![7], vec![2]),
        ]).unwrap();
        let mut original = PreparedTransactionEncodeCaptureV2::new();

        assert!(original.encode_once_v2(&transaction, JournalLimits::default()).is_err());

        assert!(matches!(original.failure(), Some(JournalTransactionDataError::DuplicateRecordKey)));
        assert_eq!(original.validation.index_v1().retained_key_count_v1(), 1);
        assert_eq!(original.validation.index_v1().current_key_v1(),
            Some((RecordNamespace::Operation as u8, &[7][..])));
        assert!(original.bytes.is_empty());
        assert!(original.take_completed_v2().is_none());
        let first = original.failure().unwrap() as *const JournalTransactionDataError;

        assert!(original.encode_once_v2(&transaction, JournalLimits::default()).is_err());

        assert!(std::ptr::eq(first, original.failure().unwrap()));
        assert_eq!(original.validation.index_v1().retained_key_count_v1(), 1);
        assert!(original.take_completed_v2().is_none());
    }
}
