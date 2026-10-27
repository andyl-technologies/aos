//! Retains advisory preflight representation without role authority.
//!
//! This DATA sink owns actual metadata/allocation results, canonical validator
//! and encoder originals, frames and prospective models. Upper role owners
//! retain their genuine semantic recipe, error selection, currentness and
//! payment before growth. No method creates a writer, token or paid loan.

pub mod schedule;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::transaction::{
    NativeRecordKeyIndexV1, NativeRecordRef, NativeTransactionEncodeOriginalsV1,
    encode_transaction_retaining_v1,
};
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalTransaction, TransactionValidationCaptureV1,
    encoded_transaction_append_bytes, validate_transaction_retaining_v1,
};

use super::CanonicalJournalMechanicalErrorV1 as JournalError;

/// Keeps the exact prospective canonical models as nonauthoritative DATA.
pub struct CanonicalPreflightModelsDataV1 {
    /// Keeps the prospective materialized rows.
    pub state: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    /// Keeps the prospective idempotency decisions.
    pub idempotency: BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    /// Keeps the prospective committed transaction identities.
    pub transaction_ids: BTreeSet<[u8; 16]>,
    /// Counts the prospective materialized bytes.
    pub materialized_bytes: usize,
    /// Keeps the prospective next native sequence.
    pub next_sequence: u64,
    /// Counts the prospective committed transactions.
    pub committed_transactions: usize,
}

struct TransactionOriginalV2 {
    validation: TransactionValidationCaptureV1,
    encoder: NativeTransactionEncodeOriginalsV1,
    frames: Option<Vec<Vec<u8>>>,
}

impl TransactionOriginalV2 {
    const fn new() -> Self {
        Self {
            validation: TransactionValidationCaptureV1::new(),
            encoder: NativeTransactionEncodeOriginalsV1::new(),
            frames: None,
        }
    }
}

/// Separates exact incoming representation from the upper future-map invoice.
pub struct CanonicalPreflightReceivingDataV1 {
    /// Includes every incoming transaction's canonical append width.
    pub future_native_bytes: u64,
    /// Prices this sink's actual carriers, validator indices and encoded work.
    pub additional: ResourceVector,
}

/// Keeps native representation originals without interpreting an upper result.
///
/// Construction is inert. The caller pays before reservation/encoding and
/// retains its original semantic outcome beside this sink. Public model DATA
/// cannot establish a protected claim or native completion.
#[must_use = "retain the reached DATA beside the actual upper result"]
pub struct CanonicalPreflightDataOriginalV1 {
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    transactions: Vec<TransactionOriginalV2>,
    models: Option<CanonicalPreflightModelsDataV1>,
}

impl Default for CanonicalPreflightDataOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalPreflightDataOriginalV1 {
    /// Creates vacant DATA destinations without native observation or growth.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            metadata: None,
            allocation: None,
            transactions: Vec::new(),
            models: None,
        }
    }

    /// Prices the exact validator/encoder terms and prospective prefix width.
    ///
    /// Upper callers separately add their own result carriers and the SAME
    /// actual future native/semantic models. This split cannot fund or select
    /// a cheaper parser, semantic recipe or native original.
    ///
    /// # Errors
    /// Preserves canonical encoding geometry errors and checked overflow.
    pub fn receiving_data_v1(
        native_bytes: u64,
        transactions: &[JournalTransaction],
    ) -> Result<CanonicalPreflightReceivingDataV1, JournalError> {
        let invalid = || JournalError::LimitExceeded("retained advisory preflight geometry");
        let mut bytes = size_of::<CanonicalPreflightDataOriginalV1>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(schedule::model_receiving_bytes_v1()?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<(
                        CanonicalPreflightReceivingDataV1,
                        Result<CanonicalPreflightReceivingDataV1, JournalError>,
                    )>()
                    .checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    transactions
                        .len()
                        .checked_mul(size_of::<TransactionOriginalV2>())?,
                )
            })
            .ok_or_else(invalid)?;
        bytes = bytes.checked_add(schedule::mechanical_control_receiving_bytes_v1()
            .ok_or_else(invalid)?).ok_or_else(invalid)?;
        let mut names = 0usize;
        let mut future_prefix = native_bytes;
        for transaction in transactions {
            let mut keys = 0usize;
            let mut largest_key = 0usize;
            let mut largest_payload = 0usize;
            let mut largest_value = 0usize;
            for record in transaction.records() {
                keys = keys.checked_add(record.key().len()).ok_or_else(invalid)?;
                largest_key = largest_key.max(record.key().len());
                largest_value = largest_value.max(record.value().map_or(0, <[u8]>::len));
                let payload = aos_sandbox_journal::geometry::EncodedRecordLayout::new(
                    record.key().len(),
                    record.value().map(<[u8]>::len),
                )
                .map_err(JournalError::from)?
                .payload_bytes;
                largest_payload = largest_payload.max(payload);
            }
            let rows = transaction.records().len();
            let index = NativeRecordKeyIndexV1::dynamic_bytes_v1(rows, keys, largest_key)
                .ok_or_else(invalid)?;
            let encoded = encoded_transaction_append_bytes(transaction)?;
            future_prefix = future_prefix.checked_add(encoded).ok_or_else(invalid)?;
            let encoded = usize::try_from(encoded).map_err(|_| invalid())?;
            let frames = rows
                .checked_add(2)
                .and_then(|rows| rows.checked_mul(size_of::<Vec<u8>>()))
                .ok_or_else(invalid)?;
            // The lower encoder has exact-capacity frame slots, completed
            // frame bytes, one reached RECORD payload and COMMIT scratch.
            // The validator separately owns its key index and input copy.
            bytes = bytes
                .checked_add(size_of::<TransactionOriginalV2>())
                .and_then(|bytes| bytes.checked_add(index))
                .and_then(|bytes| bytes.checked_add(largest_value))
                .and_then(|bytes| bytes.checked_add(frames))
                .and_then(|bytes| bytes.checked_add(encoded))
                .and_then(|bytes| bytes.checked_add(largest_payload))
                .and_then(|bytes| {
                    bytes.checked_add(aos_sandbox_journal::framing::COMMIT_PAYLOAD_BYTES)
                })
                .ok_or_else(invalid)?;
            names = names.checked_add(rows).ok_or_else(invalid)?;
        }
        let extra = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(
                D::MetadataEntries,
                u64::try_from(names).map_err(|_| invalid())?,
            );
        Ok(CanonicalPreflightReceivingDataV1 {
            future_native_bytes: future_prefix,
            additional: extra,
        })
    }

    /// Borrows the actual first reached mechanical/native representation cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.metadata
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                self.allocation
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.transactions.iter().find_map(|transaction| {
                    transaction.validation.failure().map(|cause| cause as _)
                })
            })
    }

    /// Parks the actual exact-reservation result before any transaction grows.
    ///
    /// # Errors
    /// Retains allocation refusal and returns the original coarse limit class.
    pub fn reserve_transactions_v2(&mut self, count: usize) -> Result<(), JournalError> {
        self.allocation = Some(self.transactions.try_reserve_exact(count));
        if matches!(self.allocation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::LimitExceeded(
                "retained advisory preflight allocation",
            ))
        }
    }

    /// Moves the actual upper native metadata Result into its original slot.
    ///
    /// # Errors
    /// Retains the supplied native error and returns the original boundary marker.
    pub fn capture_metadata_v2(
        &mut self,
        metadata: std::io::Result<std::fs::Metadata>,
    ) -> Result<u64, JournalError> {
        self.metadata = Some(metadata);
        self.metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|metadata| metadata.len())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Adds a vacant transaction destination after the actual caller's reserve.
    pub fn begin_transaction_v2(&mut self) {
        self.transactions.push(TransactionOriginalV2::new());
    }

    /// Uses the sole canonical validator with this transaction's retained keys.
    ///
    /// # Errors
    /// Preserves canonical validation failure or a missing transaction slot.
    pub fn validate_transaction_v2(
        &mut self,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let original = self
            .transactions
            .last_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        validate_transaction_retaining_v1(transaction, limits, &mut original.validation)
            .map_err(JournalError::from)
    }

    /// Uses the sole native encoder while retaining its reached original work.
    ///
    /// # Errors
    /// Preserves canonical encoding failure or a missing transaction slot.
    pub fn encode_transaction_v2(
        &mut self,
        transaction: &JournalTransaction,
        sequence: u64,
    ) -> Result<Vec<Vec<u8>>, JournalError> {
        let original = self
            .transactions
            .last_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        encode_transaction_retaining_v1(
            *transaction.id(),
            sequence,
            transaction.records().iter().map(|record| NativeRecordRef {
                namespace_byte: record.namespace() as u8,
                key: record.key(),
                value: record.value(),
            }),
            &mut original.encoder,
        )
        .map_err(JournalError::from)
    }

    /// Moves completed frames beside the current transaction's encoder original.
    pub fn retain_frames_v2(&mut self, frames: Option<Vec<Vec<u8>>>) {
        if let Some(original) = self.transactions.last_mut() {
            original.frames = frames;
        }
    }

    /// Moves the actual upper prospective models into their retained destination.
    pub fn retain_models_v2(&mut self, models: CanonicalPreflightModelsDataV1) {
        self.models = Some(models);
    }

    /// Borrows the actual retained prospective models as passive DATA.
    #[must_use]
    pub fn models(&self) -> Option<&CanonicalPreflightModelsDataV1> {
        self.models.as_ref()
    }

    /// Borrows an actual retained encoder's completed frames as passive DATA.
    #[must_use]
    pub fn frames(&self, index: usize) -> Option<&[Vec<u8>]> {
        self.transactions.get(index)?.frames.as_deref()
    }

    /// Counts the actual reached transaction destinations, including refusal.
    #[must_use]
    pub fn reached_transactions(&self) -> usize {
        self.transactions.len()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::io;

    use super::*;

    #[derive(Debug)]
    struct MetadataCause;

    impl fmt::Display for MetadataCause {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("original metadata cause")
        }
    }

    impl Error for MetadataCause {}

    #[test]
    fn original_metadata_failure_precedes_later_validation_without_losing_custody() {
        let error = io::Error::other(MetadataCause);
        let address = error.get_ref().unwrap() as *const _;
        let mut original = CanonicalPreflightDataOriginalV1::new();

        assert!(original.capture_metadata_v2(Err(error)).is_err());
        original.reserve_transactions_v2(1).unwrap();
        original.begin_transaction_v2();
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![super::super::JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                vec![1, 2],
                vec![3],
            )],
        )
        .unwrap();
        let limits = JournalLimits {
            maximum_key_bytes: 1,
            ..JournalLimits::default()
        };
        assert!(
            original
                .validate_transaction_v2(&transaction, limits)
                .is_err()
        );

        let retained = original
            .failure()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert!(std::ptr::addr_eq(
            retained.get_ref().unwrap() as *const _,
            address
        ));
        assert!(retained.get_ref().unwrap().is::<MetadataCause>());
        assert_eq!(original.reached_transactions(), 1);
        assert!(original.frames(0).is_none());
        assert!(original.models().is_none());
    }
}
