//! Retains one real recovered observation through encoding and native append.
//!
//! Ordinary and paid recovery use the same mutation engine. The selected
//! caller prepays its row/model and slot before entry, keeps this complete
//! owner on the Store on failure, and completes independent original posts.

use super::*;
use super::encoding::StateEncodingLoanV1;
use crate::catalog_transition::PreparedCatalogTransition;

#[derive(Clone, Copy)]
enum Failure {
    Record,
    RecordValidation,
    Transition,
    Snapshot,
    Verified,
    Validate,
    Result,
    Additional,
    Encode,
    Transaction,
    Repair,
    Payment,
    Native,
    OrdinaryNative,
}

// Field order follows the former inner-to-outer local destruction boundaries:
// Native/transaction before the publication record, then result/verification,
// transition and the original cloned record. No ordinary native owner escapes.
pub(super) struct StorageRecoveryMutationOriginalV1 {
    native: aos_sandbox::journal::StorageStateNativeCommitAttemptV1,
    native_status: Option<Result<(), aos_sandbox::journal::StorageStateNativeCommitClosedV1>>,
    ordinary_native: Option<Result<(), StorageStateError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    repair: Option<Result<(), StorageStateError>>,
    transaction: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    encoded: Option<Result<Vec<u8>, StorageStateError>>,
    additional: Option<Result<Vec<JournalRecord>, StorageStateError>>,
    result: Option<Result<CommittedStorageResultV1, StorageStateError>>,
    validation: Option<Result<(), StorageStateError>>,
    verified: Option<Result<VerifiedStorageResultV1, StorageStateError>>,
    snapshot: Option<Result<(), StorageStateError>>,
    transition: Option<Result<PreparedCatalogTransition, StorageStateError>>,
    codec: super::encoding::StateCodecOriginalV1,
    transition_preparation: crate::catalog_transition::CatalogTransitionPreparationOriginalV1,
    physical_preparation: crate::catalog_transition::CatalogPhysicalApplicationOriginalV1,
    record_validation: Option<Result<(), StorageStateError>>,
    record: Option<Result<DurableRecord, StorageStateError>>,
    first: Option<Failure>,
    publication_entered: bool,
    armed: bool,
}

impl StorageRecoveryMutationOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            native: aos_sandbox::journal::StorageStateNativeCommitAttemptV1::new(),
            native_status: None,
            ordinary_native: None,
            payment: None,
            repair: None,
            transaction: None,
            encoded: None,
            additional: None,
            result: None,
            validation: None,
            verified: None,
            snapshot: None,
            transition: None,
            codec: super::encoding::StateCodecOriginalV1::default(),
            transition_preparation: crate::catalog_transition::CatalogTransitionPreparationOriginalV1::new(),
            physical_preparation: crate::catalog_transition::CatalogPhysicalApplicationOriginalV1::new(),
            record_validation: None,
            record: None,
            first: None,
            publication_entered: false,
            armed: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn run(
        &mut self,
        store: &mut StorageTransactionStore,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        observed: &PostconditionPolicyV1,
        observed_object_guid: Option<u64>,
        zfs_observation_digest: ObjectDigest,
        supplement: CatalogCommitSupplementV1,
        mut receiving: Option<&mut StateEncodingLoanV1<'_, '_>>,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        self.armed = receiving.is_some();
        self.first = Some(Failure::Record);
        self.record = Some((|| {
            store.ensure_authority_readable()?;
            Ok(store.exact_current(operation_id, mutation_digest)?.clone())
        })());
        let Some(Ok(record)) = self.record.as_ref() else {
            return Err(StorageStateError::Receiving);
        };

        // Keep the actual cloned bytes resident before a post-clone predicate
        // can reject them. The ordinary adapter still returns InvalidTransition
        // after dropping this same clone at the enclosing local boundary.
        self.first = Some(Failure::RecordValidation);
        self.record_validation = Some(if record.phase != DurableStoragePhase::Ambiguous
            || record.catalog != catalog.binding()
            || record.catalog_bytes != catalog.canonical_bytes()
        {
            Err(StorageStateError::InvalidTransition)
        } else {
            Ok(())
        });
        if !matches!(self.record_validation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }

        self.first = Some(Failure::Transition);
        self.transition = Some({
            let mut context = receiving.as_deref_mut().map(|receiving| {
                super::encoding::StateEncodingContextV1::new(receiving, &mut self.codec)
            });
            store.catalog_transitions.prepare_transition_with_supplement_receiving_v1(
                operation_id, mutation_digest, catalog, observed_object_guid,
                zfs_observation_digest, supplement, store.key.key_id,
                &store.key.secret, context.as_mut(), &mut self.transition_preparation,
                &mut self.physical_preparation,
            )
        });
        let Some(Ok(transition)) = self.transition.as_ref() else {
            return Err(StorageStateError::Receiving);
        };

        if let Some(metadata) = transition.snapshot_metadata() {
            self.first = Some(Failure::Snapshot);
            self.snapshot = Some(store.validate_snapshot_metadata_authority(metadata, record, catalog));
            if !matches!(self.snapshot, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
        }
        self.first = Some(Failure::Verified);
        self.verified = Some(VerifiedStorageResultV1::verify_observation(
            operation_id, record.request_digest, catalog, observed,
            observed_object_guid, transition.result_binding(), transition.observation_digest(),
        ));
        let Some(Ok(verified)) = self.verified.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        self.first = Some(Failure::Validate);
        self.validation = Some(store.validate_verified_result(record, verified));
        if !matches!(self.validation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        self.first = Some(Failure::Result);
        self.result = Some(store.committed_result(verified));
        let Some(result) = self.result.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            return Err(StorageStateError::Receiving);
        };
        let Some(Ok(record)) = self.record.as_mut() else {
            return Err(StorageStateError::Receiving);
        };
        record.phase = DurableStoragePhase::Committed;
        record.result = Some(result);

        self.first = Some(Failure::Additional);
        self.additional = Some(match receiving.as_deref_mut() {
            Some(receiving) => transition.records_receiving_v1(receiving),
            None => Ok(transition.records()),
        });
        if !matches!(self.additional, Some(Ok(_))) {
            return Err(StorageStateError::Receiving);
        }
        self.publish_record(store, receiving)?;
        let Some(Ok(transition)) = self.transition.take() else {
            return Err(StorageStateError::Receiving);
        };
        store.catalog_transitions.install_transition(transition);
        self.first = None;
        Ok(result)
    }

    pub(super) fn publish_record(
        &mut self,
        store: &mut StorageTransactionStore,
        mut receiving: Option<&mut StateEncodingLoanV1<'_, '_>>,
    ) -> Result<(), StorageStateError> {
        let Some(Ok(record)) = self.record.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        self.publication_entered = true;
        self.first = Some(Failure::Encode);
        self.encoded = Some(encode_record_receiving_v1(record, &store.key, receiving.as_deref_mut()));
        if !matches!(self.encoded, Some(Ok(_))) {
            return Err(StorageStateError::Receiving);
        }
        // The selected row and Vec carriers were paid before their allocation.
        // These moves create the same actual transaction, not a forecast copy.
        let Some(Ok(mut records)) = self.additional.take() else {
            return Err(StorageStateError::Receiving);
        };
        let Some(Ok(bytes)) = self.encoded.take() else {
            return Err(StorageStateError::Receiving);
        };
        records.push(JournalRecord::put(
            RecordNamespace::Operation, record.operation_id.to_vec(), bytes,
        ));
        self.first = Some(Failure::Transaction);
        self.transaction = Some(JournalTransaction::new(
            transaction_id(record.operation_id, record.phase), records,
        ));
        let Some(Ok(transaction)) = self.transaction.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        self.first = Some(Failure::Repair);
        self.repair = Some(store.require_no_held_repair_guard_v1());
        if !matches!(self.repair, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        if let Some(receiving) = receiving {
            self.first = Some(Failure::Payment);
            self.payment = Some(receiving.reserve_append_v1(&store.journal, transaction));
            if !matches!(self.payment, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
            self.first = Some(Failure::Native);
            self.native_status = Some(self.native.commit_once_v1(&mut store.journal, transaction));
            if !matches!(self.native_status, Some(Ok(()))) {
                store.commit_failed = true;
                return Err(StorageStateError::Receiving);
            }
        } else {
            self.first = Some(Failure::OrdinaryNative);
            self.ordinary_native = Some(store.commit_journal_unfenced(transaction));
            if !matches!(self.ordinary_native, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
        }
        let Some(Ok(record)) = self.record.take() else {
            return Err(StorageStateError::Receiving);
        };
        store.records.insert(record.operation_id, record);
        self.first = None;
        Ok(())
    }

    pub(super) fn publish_ordinary(
        store: &mut StorageTransactionStore,
        record: DurableRecord,
        additional: Vec<JournalRecord>,
    ) -> Result<(), StorageStateError> {
        let mut attempt = Self::new();
        attempt.record = Some(Ok(record));
        attempt.additional = Some(Ok(additional));
        let result = attempt.publish_record(store, None);
        result.map_err(|_| attempt.take_ordinary_failure())
    }

    pub(super) fn take_ordinary_failure(&mut self) -> StorageStateError {
        match self.first {
            Some(Failure::Record) => self.record.take().and_then(Result::err),
            Some(Failure::RecordValidation) => self.record_validation.take().and_then(Result::err),
            Some(Failure::Transition) => self.transition.take().and_then(Result::err),
            Some(Failure::Snapshot) => self.snapshot.take().and_then(Result::err),
            Some(Failure::Verified) => self.verified.take().and_then(Result::err),
            Some(Failure::Validate) => self.validation.take().and_then(Result::err),
            Some(Failure::Result) => self.result.take().and_then(Result::err),
            Some(Failure::Additional) => self.additional.take().and_then(Result::err),
            Some(Failure::Encode) => self.encoded.take().and_then(Result::err),
            Some(Failure::Transaction) => self.transaction.take().and_then(Result::err)
                .map(StorageStateError::from),
            Some(Failure::Repair) => self.repair.take().and_then(Result::err),
            Some(Failure::OrdinaryNative) => self.ordinary_native.take().and_then(Result::err),
            Some(Failure::Payment | Failure::Native) | None => None,
        }.unwrap_or(StorageStateError::Receiving)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn failure(
            result: Option<&Result<(), StorageStateError>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            result.and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
        }

        match self.first? {
            Failure::Record => self.record.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::RecordValidation => failure(self.record_validation.as_ref()),
            Failure::Transition => self.codec.failure()
                .or_else(|| self.physical_preparation.failure())
                .or_else(|| self.transition_preparation.failure()
                    .map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.transition.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Snapshot => failure(self.snapshot.as_ref()),
            Failure::Verified => self.verified.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Validate => failure(self.validation.as_ref()),
            Failure::Result => self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Additional => self.additional.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Encode => self.encoded.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Transaction => self.transaction.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Repair => failure(self.repair.as_ref()),
            Failure::Payment => self.payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Native => self.native.failure(),
            Failure::OrdinaryNative => failure(self.ordinary_native.as_ref()),
        }
    }
}

impl Drop for StorageRecoveryMutationOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            // A selected local is resident before IO and moves infallibly to
            // the Store. Unwind cannot dispose it before the outer fence runs.
            std::process::abort();
        }
        if self.publication_entered {
            // Inner publish locals precede the moved publication record;
            // remaining outer verification/transition locals follow it.
            drop(self.transaction.take());
            drop(self.encoded.take());
            drop(self.additional.take());
            drop(self.record.take());
        }
    }
}

#[derive(Clone, Copy)]
enum RecordAppendFailure {
    Codec,
    Repair,
    Payment,
    Native,
    Readback,
}

// Only the actual native interval/error and its input survive failure. Pure
// record/decoder scratch remains under the same dominant prepaid byte peak.
struct RecoveryRecordAppendV1 {
    native: aos_sandbox::journal::StorageStateNativeCommitAttemptV1,
    native_status: Option<Result<(), aos_sandbox::journal::StorageStateNativeCommitClosedV1>>,
    transaction: Option<JournalTransaction>,
    codec: super::encoding::StateCodecOriginalV1,
    repair: Option<Result<(), StorageStateError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    readback: Option<Result<(), StorageStateError>>,
    first: Option<RecordAppendFailure>,
}

impl RecoveryRecordAppendV1 {
    fn new() -> Self {
        Self {
            native: aos_sandbox::journal::StorageStateNativeCommitAttemptV1::new(),
            native_status: None,
            transaction: None,
            codec: super::encoding::StateCodecOriginalV1::default(),
            repair: None,
            payment: None,
            readback: None,
            first: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            RecordAppendFailure::Codec => self.codec.failure(),
            RecordAppendFailure::Repair => self.repair.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            RecordAppendFailure::Payment => self.payment.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            RecordAppendFailure::Native => self.native.failure(),
            RecordAppendFailure::Readback => self.readback.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
        }
    }
}

enum RecoveryMutationOriginalV1 {
    Observation(Box<StorageRecoveryMutationOriginalV1>),
    Atomic(Box<super::atomic_recovery::AtomicRecoveryOriginalV1>),
    RecordAppend(Box<RecoveryRecordAppendV1>),
}

impl RecoveryMutationOriginalV1 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Observation(original) => original.failure(),
            Self::Atomic(original) => original.failure(),
            Self::RecordAppend(original) => original.failure(),
        }
    }

    fn can_dispose(&self) -> bool {
        match self {
            Self::Observation(original) => original.first.is_none()
                && original.codec.is_complete_v1()
                && original.transition_preparation.failure().is_none()
                && original.physical_preparation.failure().is_none()
                && matches!(original.native_status, Some(Ok(())))
                && original.native.failure().is_none(),
            Self::Atomic(original) => original.can_dispose(),
            Self::RecordAppend(original) => original.first.is_none()
                && original.codec.is_complete_v1()
                && matches!(original.native_status, Some(Ok(())))
                && original.native.failure().is_none(),
        }
    }

    fn complete_disposal(&mut self) {
        match self {
            Self::Observation(original) => {
                if original.native.settle_positive_once_v1().is_err() {
                    std::process::abort();
                }
                original.armed = false;
            }
            Self::Atomic(original) => original.complete_disposal(),
            Self::RecordAppend(original) => {
                if original.native.settle_positive_once_v1().is_err() {
                    std::process::abort();
                }
            }
        }
    }
}

pub(super) struct StorageRecoveryMutationCaptureV1 {
    attempts: Vec<RecoveryMutationOriginalV1>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    model_demand: Option<Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>>,
    slot_shape: Option<Result<usize, aos_sandbox_core::AccountingError>>,
    slot_payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    first: Option<usize>,
}

impl StorageRecoveryMutationCaptureV1 {
    pub(super) const fn new() -> Self {
        Self {
            attempts: Vec::new(),
            allocation: None,
            model_demand: None,
            slot_shape: None,
            slot_payment: None,
            first: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.model_demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.slot_shape.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.slot_payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.allocation.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.first.and_then(|index| self.attempts.get(index))
                .and_then(RecoveryMutationOriginalV1::failure))
    }
}

impl StorageTransactionStore {
    pub(crate) fn recovery_encoding_journal_v1(&self) -> &aos_sandbox::Journal {
        &self.journal
    }

    /// Counts the actual held rows before recovery carrier allocation.
    pub(crate) fn recovery_row_counts_v1(&self) -> (usize, usize) {
        (self.records.len(), self.atomic_snapshots.len())
    }

    pub(crate) fn prepare_recovery_models_v1(
        &mut self,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        if self.recovery_mutations.model_demand.is_some() {
            return Err(StorageStateError::Receiving);
        }
        self.recovery_mutations.model_demand = Some(self.recovery_model_demand_v1());
        let Some(demand) = self.recovery_mutations.model_demand.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving);
        };
        receiving.reserve_models_once_v1(&self.journal, demand)
            .map_err(|_| StorageStateError::Receiving)
    }

    fn recovery_model_demand_v1(&self)
        -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>
    {
        use crate::receiving_demand::{add, count, multiply};
        use aos_sandbox_core::{ResourceDimension as Dimension, ResourceVector};
        let geometry = self.receiving_inventory_geometry_v1()?;
        let rows = add(geometry.journal_rows, add(geometry.lifecycle_rows,
            add(geometry.transition_rows, add(geometry.atomic_rows, geometry.repair_rows)?)?)?)?;
        let cells = count(crate::catalog_transition::recovery_model_cell_bytes_v1()
            + std::mem::size_of::<DurableRecord>()
            + std::mem::size_of::<crate::ZfsTransaction>()
            + std::mem::size_of::<crate::ZfsPrecondition>()
            + std::mem::size_of::<StorageRecoveryMutationOriginalV1>())?;
        // Thirty-two related map/wire/projection carriers and encoded128 use
        // the same bounded State codec geometry as startup. Actual encoder
        // buffers are separately paid from their reached serialization widths.
        let models = add(multiply(geometry.encoded_bytes, 128)?,
            multiply(multiply(rows, cells)?, 32)?)?;
        // Each actual recovery row can keep the worker's returned stdout/stderr
        // after the independent positive transport disposal (64KiB each).
        let output_rows = add(count(self.records.len())?, count(self.atomic_snapshots.len())?)?;
        let memory = add(models, multiply(output_rows, 128 * 1024)?)?;
        let memory = add(memory, count(std::mem::size_of::<Self>())?)?;
        // Canonical JSON/string/byte-vector nodes and their reached empty Vec
        // floors need the same encoded-carrier term as startup replay models.
        // Related fixed model headers remain row-based; later codec/attempt
        // collectors independently pay their actual reached carrier widths.
        let metadata = geometry.encoded_bytes.checked_mul(8)
            .zip(rows.checked_mul(32))
            .and_then(|(encoded, rows)| encoded.checked_add(rows))
            .and_then(|cells| cells.checked_add(4))
            .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: Dimension::MetadataEntries,
            })?;
        Ok(ResourceVector::ZERO.with(Dimension::MemoryBytes, memory)
            .with(Dimension::MetadataEntries, metadata))
    }

    // The genuine models stage prepays this actual native-result slot before
    // Box/Vec construction. There is no detached account or caller permit.
    pub(super) fn prepare_recovery_record_append_v1(
        &mut self,
        records: usize,
        keys: usize,
        values: usize,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<usize, StorageStateError> {
        let capture = &mut self.recovery_mutations;
        if capture.failure().is_some() {
            return Err(StorageStateError::Receiving);
        }
        capture.slot_shape = Some((|| {
            let overflow = || aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
            };
            let index = aos_sandbox_journal::transaction::NativeRecordKeyIndexV1
                ::dynamic_bytes_v1(records, keys, 0).ok_or_else(overflow)?;
            capture.attempts.len().checked_add(1)
                .and_then(|slots| slots.checked_mul(std::mem::size_of::<RecoveryMutationOriginalV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RecoveryRecordAppendV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<JournalTransaction>()))
                .and_then(|bytes| records.checked_mul(std::mem::size_of::<JournalRecord>())
                    .and_then(|rows| rows.checked_add(keys)).and_then(|rows| bytes.checked_add(rows)))
                .and_then(|bytes| bytes.checked_add(index))
                .and_then(|bytes| bytes.checked_add(values))
                .ok_or_else(overflow)
        })());
        let Some(bytes) = capture.slot_shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving);
        };
        capture.slot_payment = Some(receiving.reserve_encoded_capacity_v1(bytes, 0));
        if !matches!(capture.slot_payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        capture.allocation = Some(capture.attempts.try_reserve_exact(1));
        if !matches!(capture.allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        let index = capture.attempts.len();
        capture.attempts.push(RecoveryMutationOriginalV1::RecordAppend(Box::new(RecoveryRecordAppendV1::new())));
        Ok(index)
    }

    pub(super) fn publish_recovery_record_v1(
        &mut self,
        record: DurableRecord,
        additional: Vec<JournalRecord>,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        let capture = &mut self.recovery_mutations;
        if capture.failure().is_some() {
            return Err(StorageStateError::Receiving);
        }
        capture.slot_shape = Some(capture.attempts.len().checked_add(1)
            .and_then(|slots| slots.checked_mul(std::mem::size_of::<RecoveryMutationOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StorageRecoveryMutationOriginalV1>()))
            .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
            }));
        let Some(bytes) = capture.slot_shape.as_ref().and_then(|shape| shape.as_ref().ok()).copied() else {
            return Err(StorageStateError::Receiving);
        };
        capture.slot_payment = Some(receiving.reserve_encoded_capacity_v1(bytes, 0));
        if !matches!(capture.slot_payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        capture.allocation = Some(capture.attempts.try_reserve_exact(1));
        if !matches!(capture.allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        let mut original = Box::new(StorageRecoveryMutationOriginalV1::new());
        original.armed = true;
        original.record = Some(Ok(record));
        original.additional = Some(Ok(additional));
        let result = original.publish_record(self, Some(receiving));
        let index = self.recovery_mutations.attempts.len();
        self.recovery_mutations.attempts.push(RecoveryMutationOriginalV1::Observation(original));
        if result.is_err() {
            self.recovery_mutations.first.get_or_insert(index);
        }
        result
    }

    pub(super) fn pin_attempt_record_receiving_v1(
        &mut self,
        index: usize,
        attempt: &WorkspacePinAttemptV1,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<JournalRecord, StorageStateError> {
        let Some(RecoveryMutationOriginalV1::RecordAppend(original)) = self.recovery_mutations.attempts.get_mut(index)
        else {
            return Err(StorageStateError::Receiving);
        };
        original.first = Some(RecordAppendFailure::Codec);
        let mut context = super::encoding::StateEncodingContextV1::new(receiving, &mut original.codec);
        let result = crate::workspace_pin::attempt_record_receiving_v1(
            attempt, self.key.key_id, &self.key.secret, &mut context,
        );
        if result.is_err() {
            self.recovery_mutations.first.get_or_insert(index);
        }
        result
    }

    pub(super) fn commit_recovery_record_receiving_v1(
        &mut self,
        index: usize,
        transaction: &JournalTransaction,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        self.commit_recovery_record_inner_v1(index, transaction, receiving, None)
    }

    pub(super) fn commit_recovery_preparation_receiving_v1(
        &mut self,
        index: usize,
        transaction: &JournalTransaction,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
        clock: Result<aos_sandbox_broker::StoragePrepareNativeClockLoanV1<'_>,
            aos_sandbox_broker::BrokerAdmissionError>,
    ) -> Result<(), StorageStateError> {
        self.commit_recovery_record_inner_v1(index, transaction, receiving, Some(clock))
    }

    fn commit_recovery_record_inner_v1(
        &mut self,
        index: usize,
        transaction: &JournalTransaction,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
        clock: Option<Result<aos_sandbox_broker::StoragePrepareNativeClockLoanV1<'_>,
            aos_sandbox_broker::BrokerAdmissionError>>,
    ) -> Result<(), StorageStateError> {
        let repair = self.require_no_held_repair_guard_v1();
        let Some(RecoveryMutationOriginalV1::RecordAppend(original)) = self.recovery_mutations.attempts.get_mut(index)
        else {
            return Err(StorageStateError::Receiving);
        };
        original.first = Some(RecordAppendFailure::Repair);
        original.repair = Some(repair);
        if !matches!(original.repair, Some(Ok(()))) {
            self.recovery_mutations.first.get_or_insert(index);
            return Err(StorageStateError::Receiving);
        }
        original.first = Some(RecordAppendFailure::Payment);
        original.payment = Some(receiving.reserve_append_v1(&self.journal, transaction));
        if !matches!(original.payment, Some(Ok(()))) {
            self.recovery_mutations.first.get_or_insert(index);
            return Err(StorageStateError::Receiving);
        }
        // The actual reached immutable transaction is paid before this copy.
        // Keep it with its whole native attempt through the outer State posts.
        original.transaction = Some(transaction.clone());
        let Some(transaction) = original.transaction.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        original.first = Some(RecordAppendFailure::Native);
        original.native_status = Some(match clock {
            Some(clock) => original.native.commit_preparation_once_v1(&mut self.journal, transaction, clock),
            None => original.native.commit_once_v1(&mut self.journal, transaction),
        });
        if !matches!(original.native_status, Some(Ok(()))) {
            self.commit_failed = true;
            self.recovery_mutations.first.get_or_insert(index);
            return Err(StorageStateError::Receiving);
        }
        original.first = None;
        Ok(())
    }

    pub(super) fn verify_recovery_transaction_v1(
        &mut self,
        index: usize,
        transaction: &JournalTransaction,
    ) -> Result<(), StorageStateError> {
        let readback = self.verify_journal_transaction_v1(transaction);
        let Some(RecoveryMutationOriginalV1::RecordAppend(original)) = self.recovery_mutations.attempts.get_mut(index)
        else {
            return Err(StorageStateError::Receiving);
        };
        original.readback = Some(readback);
        if !matches!(original.readback, Some(Ok(()))) {
            original.first = Some(RecordAppendFailure::Readback);
            self.recovery_mutations.first.get_or_insert(index);
            return Err(StorageStateError::Receiving);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_observed_with_supplement_receiving_v1(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        observed: &PostconditionPolicyV1,
        observed_object_guid: Option<u64>,
        zfs_observation_digest: ObjectDigest,
        supplement: CatalogCommitSupplementV1,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        let capture = &mut self.recovery_mutations;
        if capture.failure().is_some() {
            return Err(StorageStateError::Receiving);
        }
        capture.slot_shape = Some(capture.attempts.len().checked_add(1)
            .and_then(|slots| slots.checked_mul(std::mem::size_of::<RecoveryMutationOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StorageRecoveryMutationOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<JournalRecord>() + 16))
            .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
            }));
        let Some(carriers) = capture.slot_shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving);
        };
        // Three simultaneous twenty-one-field mutation destinations, nine-field
        // preparation destinations and nine-field codec/archive destinations
        // cover local plus old/new Vec backing. Six capture fields, four
        // three-field publication records, four Vec containers, one local
        // result, six context fields, five Native Results and three two-field
        // boxed enum carriers add the remaining forty controls.
        // The names sampler remains separately priced by Native append demand.
        const MUTATION_FIELDS: usize = 21;
        const PREPARATION_FIELDS: usize = 9;
        const CODEC_AND_ARCHIVE_FIELDS: usize = 9;
        const OTHER_CARRIERS: usize = 6 + 4 * 3 + 4 + 1 + 6 + 5 + 3 * 2;
        // Physical16/Canonical8/Normalizer5; plan's three root slots and
        // seven other fields plus three Vec headers; canonical binding2,
        // three metadata payloads3 each and one lookup key2 are distinct.
        // Actual reached Root/Hold/Origin row fields are in the graph shape.
        const PLAN_FIELDS_AND_VECS: usize = 3 + 7 + 3;
        const PHYSICAL_FIELDS: usize = 16 + 8 + 5 + PLAN_FIELDS_AND_VECS
            + 2 + 3 * 3 + 2;
        const CELLS: usize = 3 * (MUTATION_FIELDS + PREPARATION_FIELDS
            + CODEC_AND_ARCHIVE_FIELDS + PHYSICAL_FIELDS) + OTHER_CARRIERS
            + crate::catalog_transition::SINGULAR_APPLICATION_CALL_CELLS;
        capture.slot_payment = Some(receiving.reserve_encoded_capacity_v1(carriers, CELLS));
        if !matches!(capture.slot_payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        capture.allocation = Some(capture.attempts.try_reserve_exact(1));
        if !matches!(capture.allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }

        // The genuine slot debit includes this real Box before any native IO.
        let mut attempt = Box::new(StorageRecoveryMutationOriginalV1::new());
        let result = attempt.run(
            self, operation_id, mutation_digest, catalog, observed,
            observed_object_guid, zfs_observation_digest, supplement, Some(receiving),
        );
        // Capacity was acquired before any native crossing. No fallible work
        // lies between the real returned attempt and this resident transfer.
        let capture = &mut self.recovery_mutations;
        if result.is_err() {
            capture.first = Some(capture.attempts.len());
        }
        capture.attempts.push(RecoveryMutationOriginalV1::Observation(attempt));
        result
    }

    pub(crate) fn commit_atomic_dataset_snapshot_receiving_v1(
        &mut self,
        operation: [u8; 16],
        program: ObjectDigest,
        observation: ObjectDigest,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        self.commit_atomic_recovery_receiving_inner_v1(operation, program, observation,
            super::atomic_recovery::AtomicCommitEvidenceV1::Legacy, receiving)
    }

    pub(crate) fn commit_atomic_dataset_snapshot_with_evidence_receiving_v1(
        &mut self,
        operation: [u8; 16],
        program: ObjectDigest,
        observation: ObjectDigest,
        member_guids: &[u64],
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        self.commit_atomic_recovery_receiving_inner_v1(operation, program, observation,
            super::atomic_recovery::AtomicCommitEvidenceV1::Group(member_guids), receiving)
    }

    fn commit_atomic_recovery_receiving_inner_v1(
        &mut self,
        operation: [u8; 16],
        program: ObjectDigest,
        observation: ObjectDigest,
        evidence: super::atomic_recovery::AtomicCommitEvidenceV1<'_>,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageStateError> {
        let capture = &mut self.recovery_mutations;
        if capture.failure().is_some() {
            return Err(StorageStateError::Receiving);
        }
        capture.slot_shape = Some(capture.attempts.len().checked_add(1)
            .and_then(|slots| slots.checked_mul(std::mem::size_of::<RecoveryMutationOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                super::atomic_recovery::AtomicRecoveryOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<JournalRecord>()
                + 32 + std::mem::size_of::<[u8; 16]>()))
            .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
            }));
        let Some(bytes) = capture.slot_shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving);
        };
        // Atomic19 +group8 +named physical/canonical owners +preparation9 +codec/archive9
        // +encoder10, two program encoders5 and digest encoder5, three carriers.
        // Physical application/canonicalization contributes named operands,
        // result projections, successor tuple/hash and disposition controls.
        // Capture6, record fields12,
        // Vecs4, result1, context6, Native5, boxed enum controls6 and the
        // actual publication-operation selection1 follow.
        const CELLS: usize = 3 * (19 + 8 + crate::catalog_transition::PHYSICAL_APPLICATION_OWNED_CELLS
            + 9 + 9 + 10 + 2 * 5 + 5) + 6 + 12 + 4 + 1 + 6 + 5 + 6 + 1
            + crate::catalog_transition::PHYSICAL_APPLICATION_CALL_CELLS;
        capture.slot_payment = Some(receiving.reserve_encoded_capacity_v1(bytes, CELLS));
        if !matches!(capture.slot_payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        capture.allocation = Some(capture.attempts.try_reserve_exact(1));
        if !matches!(capture.allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        let mut attempt = Box::new(super::atomic_recovery::AtomicRecoveryOriginalV1::new());
        let result = attempt.run(self, operation, program, observation, evidence, Some(receiving));
        let capture = &mut self.recovery_mutations;
        if result.is_err() {
            capture.first = Some(capture.attempts.len());
        }
        capture.attempts.push(RecoveryMutationOriginalV1::Atomic(attempt));
        result
    }

    /// Disposes successful temporary append carriers after the enclosing posts.
    ///
    /// The continuously held State stage completes its real names/original
    /// observations first. This private caller then checks every unchanged
    /// retained result while all carriers are resident before dropping any.
    pub(crate) fn require_positive_recovery_mutations_v1(&self) -> Result<(), StorageStateError> {
        let capture = &self.recovery_mutations;
        if capture.failure().is_some()
            || capture.attempts.iter().any(|attempt| !attempt.can_dispose())
        {
            return Err(StorageStateError::Receiving);
        }
        Ok(())
    }

    pub(crate) fn complete_positive_recovery_mutations_v1(&mut self) {
        for attempt in &mut self.recovery_mutations.attempts {
            // Every status was checked before any sibling owner disposed.
            attempt.complete_disposal();
        }
        // The actual native attempts are now disposed. Only this closed
        // completion may clear the per-interval representation receipts.
        self.recovery_mutations = StorageRecoveryMutationCaptureV1::new();
    }

    pub(crate) fn dispose_positive_recovery_mutations_v1(&mut self)
        -> Result<(), StorageStateError>
    {
        self.require_positive_recovery_mutations_v1()?;
        self.complete_positive_recovery_mutations_v1();
        Ok(())
    }

    pub(crate) fn recovery_mutation_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.recovery_mutations.failure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::{catalog, digest, initialize, key};

    #[test]
    fn invalid_prepared_recovery_retains_the_actual_cloned_record_before_rejection() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        let operation = [31; 16];
        let mutation = match store.begin(operation, digest(32), &catalog).unwrap() {
            BeginStorageTransaction::Prepared { mutation_digest } => mutation_digest,
            other => panic!("unexpected preparation: {other:?}"),
        };
        let program = crate::ZfsTransaction::from_catalog(catalog.plan().operation(), &catalog).unwrap();
        let path = directory.path().join("storage-state.journal");
        let before = std::fs::read(&path).unwrap();
        let mut attempt = StorageRecoveryMutationOriginalV1::new();

        assert!(attempt.run(
            &mut store, operation, mutation, &catalog, program.postcondition(),
            None, digest(33), CatalogCommitSupplementV1::None, None,
        ).is_err());

        let record = attempt.record.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(record.operation_id, operation);
        assert_eq!(record.phase, DurableStoragePhase::Prepared);
        assert_eq!(record.catalog_bytes, catalog.canonical_bytes());
        assert!(!record.catalog_bytes.is_empty());
        assert!(matches!(attempt.record_validation,
            Some(Err(StorageStateError::InvalidTransition))));
        let cause = attempt.failure().unwrap().downcast_ref::<StorageStateError>().unwrap();
        let original = attempt.record_validation.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(cause, original));
        assert!(!attempt.publication_entered);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(matches!(attempt.take_ordinary_failure(), StorageStateError::InvalidTransition));
        assert!(attempt.record.as_ref().unwrap().is_ok());
    }
}
