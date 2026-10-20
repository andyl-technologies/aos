//! Retains the actual atomic recovery candidate through encoding and append.
//!
//! The two fixed existing atomic histories share one publisher. Selected calls
//! borrow the genuine State stage and retain every completed actual carrier.

use super::*;
use super::encoding::StateEncodingLoanV1;

pub(super) enum AtomicCommitEvidenceV1<'a> {
    Legacy,
    Group(&'a [u64]),
}

#[derive(Clone, Copy)]
enum Failure {
    Record,
    Validation,
    Transition,
    Encode,
    Additional,
    Transaction,
    Repair,
    Payment,
    Native,
    OrdinaryNative,
}

pub(super) struct AtomicRecoveryOriginalV1 {
    native: aos_sandbox::journal::StorageStateNativeCommitAttemptV1,
    native_status: Option<Result<(), aos_sandbox::journal::StorageStateNativeCommitClosedV1>>,
    ordinary_native: Option<Result<(), StorageStateError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    repair: Option<Result<(), StorageStateError>>,
    transaction: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    records: Option<Vec<JournalRecord>>,
    additional: Option<Result<Vec<JournalRecord>, StorageStateError>>,
    encoded: Option<Result<Vec<u8>, StorageStateError>>,
    record_key: Option<Vec<u8>>,
    record: Option<Result<AtomicDatasetSnapshotRecordV1, StorageStateError>>,
    validation: Option<Result<(), StorageStateError>>,
    transition: Option<Result<crate::catalog_transition::PreparedCatalogTransition, StorageStateError>>,
    transition_preparation: crate::catalog_transition::AtomicGroupPreparationOriginalV1,
    codec: super::encoding::StateCodecOriginalV1,
    encoding: super::atomic_encoding::AtomicEncodingOriginalV1,
    first: Option<Failure>,
    armed: bool,
    entered: bool,
}

impl AtomicRecoveryOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            native: aos_sandbox::journal::StorageStateNativeCommitAttemptV1::new(),
            native_status: None,
            ordinary_native: None,
            payment: None,
            repair: None,
            transaction: None,
            records: None,
            additional: None,
            encoded: None,
            record_key: None,
            record: None,
            validation: None,
            transition: None,
            transition_preparation: crate::catalog_transition::AtomicGroupPreparationOriginalV1::new(),
            codec: super::encoding::StateCodecOriginalV1::default(),
            encoding: super::atomic_encoding::AtomicEncodingOriginalV1::new(),
            first: None,
            armed: false,
            entered: false,
        }
    }

    pub(super) fn run(
        &mut self,
        store: &mut StorageTransactionStore,
        operation: [u8; 16],
        program: ObjectDigest,
        observation: ObjectDigest,
        evidence: AtomicCommitEvidenceV1<'_>,
        mut receiving: Option<&mut StateEncodingLoanV1<'_, '_>>,
    ) -> Result<(), StorageStateError> {
        if self.entered {
            return Err(StorageStateError::Receiving);
        }
        self.entered = true;
        self.armed = receiving.is_some();
        let legacy = matches!(evidence, AtomicCommitEvidenceV1::Legacy);
        self.first = Some(Failure::Record);
        self.record = Some((|| {
            store.ensure_authority_readable()?;
            if legacy && observation.as_bytes() == &[0; 32] {
                return Err(StorageStateError::InvalidValue);
            }
            store.atomic_snapshots.get(&operation).filter(|record| {
                record.phase == AtomicDatasetSnapshotPhaseV1::Ambiguous
                    && record.program.commitment() == program
                    && (legacy || record.program.format_version() == 2)
                    && record.observation.is_none()
            }).cloned().ok_or(StorageStateError::InvalidTransition)
        })());
        let Some(Ok(record)) = self.record.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        if legacy {
            // Legacy format validation follows its actual record clone.
            self.first = Some(Failure::Validation);
            self.validation = Some(if record.program.format_version() == 1 {
                Ok(())
            } else {
                Err(StorageStateError::InvalidTransition)
            });
            if !matches!(self.validation, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
        }
        if let AtomicCommitEvidenceV1::Group(member_guids) = evidence {
            self.first = Some(Failure::Transition);
            self.transition = Some({
                let mut context = receiving.as_deref_mut().map(|receiving| {
                    super::encoding::StateEncodingContextV1::new(receiving, &mut self.codec)
                });
                let selected = context.is_some();
                let result = store.catalog_transitions.prepare_atomic_group_transition_receiving_v1(
                    &record.program, record.semantic_digest, observation, member_guids,
                    store.key.key_id, &store.key.secret, context.as_mut(),
                    &mut self.transition_preparation,
                );
                if !selected {
                    // The former provider-local preparation ended before this
                    // caller's current record, including provider errors.
                    self.transition_preparation =
                        crate::catalog_transition::AtomicGroupPreparationOriginalV1::new();
                }
                result
            });
            if !matches!(self.transition, Some(Ok(_))) {
                return Err(StorageStateError::Receiving);
            }
        }
        let post_head = self.transition.as_ref().and_then(|result| result.as_ref().ok())
            .map(crate::catalog_transition::PreparedCatalogTransition::result_binding);
        let Some(Ok(record)) = self.record.as_mut() else {
            std::process::abort();
        };
        record.phase = AtomicDatasetSnapshotPhaseV1::Committed;
        record.observation = Some(observation);
        record.post_head = post_head;

        // The original record constructor evaluates its key argument before
        // entering the encoder. Keep that actual allocation on later refusal.
        let publication_operation = if legacy {
            record.program.operation()
        } else {
            operation
        };
        self.record_key = Some(atomic_snapshot_record_key(publication_operation));
        self.first = Some(Failure::Encode);
        let selected = receiving.is_some();
        let encoded = self.encoding.encode(record, &store.key, receiving.as_deref_mut());
        let encoded = if selected {
            encoded
        } else {
            encoded.map_err(|_| self.encoding.take_ordinary_failure())
        };
        if !selected {
            // The former encoder-local program ended before publication Vec
            // creation, on success and every error.
            self.encoding.dispose_ordinary_program();
        }
        self.encoded = Some(encoded);
        if !matches!(self.encoded, Some(Ok(_))) {
            return Err(StorageStateError::Receiving);
        }
        let Some(Ok(bytes)) = self.encoded.take() else {
            std::process::abort();
        };
        let Some(record_key) = self.record_key.take() else {
            std::process::abort();
        };
        self.records = Some(vec![JournalRecord::put(
            RecordNamespace::Effect, record_key, bytes,
        )]);
        if let Some(Ok(transition)) = self.transition.as_ref() {
            self.first = Some(Failure::Additional);
            self.additional = Some(match receiving.as_deref_mut() {
                Some(receiving) => transition.records_receiving_v1(receiving),
                None => Ok(transition.records()),
            });
            if !matches!(self.additional, Some(Ok(_))) {
                return Err(StorageStateError::Receiving);
            }
            let Some(Ok(additional)) = self.additional.take() else {
                std::process::abort();
            };
            let Some(records) = self.records.as_mut() else {
                std::process::abort();
            };
            records.extend(additional);
        }
        let Some(records) = self.records.take() else {
            std::process::abort();
        };
        self.first = Some(Failure::Transaction);
        self.transaction = Some(JournalTransaction::new(
            atomic_snapshot_transaction_id(
                publication_operation, AtomicDatasetSnapshotPhaseV1::Committed,
            ),
            records,
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
            if legacy {
                // Legacy publication was a nested function whose transaction
                // ended before the materialized atomic map insertion.
                drop(self.transaction.take());
            }
        }
        if let Some(Ok(transition)) = self.transition.take() {
            store.catalog_transitions.install_transition(transition);
        }
        let Some(Ok(record)) = self.record.take() else {
            std::process::abort();
        };
        store.atomic_snapshots.insert(operation, record);
        self.first = None;
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Record => self.record.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Validation => self.validation.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Transition => self.codec.failure()
                .or_else(|| self.transition_preparation.failure()
                    .map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.transition.as_ref()?.as_ref().err()
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Encode => self.encoding.failure()
                .or_else(|| self.encoded.as_ref()?.as_ref().err()
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Additional => self.additional.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Transaction => self.transaction.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Repair => self.repair.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Payment => self.payment.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Native => self.native.failure()
                .or_else(|| self.native_status.as_ref()?.as_ref().err()
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::OrdinaryNative => self.ordinary_native.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
        }
    }

    pub(super) fn take_ordinary_failure(&mut self) -> StorageStateError {
        let cause = match self.first.take() {
            Some(Failure::Record) => self.record.take().and_then(Result::err),
            Some(Failure::Validation) => self.validation.take().and_then(Result::err),
            Some(Failure::Transition) => self.transition.take().and_then(Result::err),
            Some(Failure::Encode) => self.encoded.take().and_then(Result::err),
            Some(Failure::Additional) => self.additional.take().and_then(Result::err),
            Some(Failure::Transaction) => self.transaction.take().and_then(Result::err)
                .map(aos_sandbox::JournalError::from).map(Into::into),
            Some(Failure::Repair) => self.repair.take().and_then(Result::err),
            Some(Failure::OrdinaryNative) => self.ordinary_native.take().and_then(Result::err),
            Some(Failure::Payment | Failure::Native) | None => None,
        };
        match cause {
            Some(cause) => cause,
            None => std::process::abort(),
        }
    }

    pub(super) fn can_dispose(&self) -> bool {
        self.first.is_none() && self.codec.is_complete_v1()
            && self.transition_preparation.failure().is_none()
            && matches!(self.native_status, Some(Ok(()))) && self.native.failure().is_none()
    }

    pub(super) fn complete_disposal(&mut self) {
        if self.native.settle_positive_once_v1().is_err() {
            std::process::abort();
        }
        self.armed = false;
    }
}

impl Drop for AtomicRecoveryOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_commit_rejection_keeps_the_actual_group_record_and_first_cause() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = StorageTransactionStore::open_for_test(
            directory.path(), super::super::tests::key(51), 0,
        ).unwrap();
        let program = crate::lifecycle_atomic_snapshot::sample_atomic_snapshot_program_for_test();
        let operation = program.operation();
        let commitment = program.commitment();
        let canonical = program.canonical_bytes().unwrap();
        store.atomic_snapshots.insert(operation, AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Ambiguous,
            program,
            observation: None,
            sandbox_id: [52; 16],
            request_id: [53; 16],
            semantic_digest: ObjectDigest::from_bytes([54; 32]),
            transport_digest: ObjectDigest::from_bytes([55; 32]),
            post_head: None,
        });
        let path = directory.path().join("storage-state.journal");
        let before = std::fs::read(&path).unwrap();
        let mut original = AtomicRecoveryOriginalV1::new();

        assert!(original.run(
            &mut store, operation, commitment, ObjectDigest::from_bytes([56; 32]),
            AtomicCommitEvidenceV1::Legacy, None,
        ).is_err());

        let retained = original.record.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(retained.program.canonical_bytes().unwrap(), canonical);
        assert_eq!(retained.phase, AtomicDatasetSnapshotPhaseV1::Ambiguous);
        assert!(original.transaction.is_none());
        assert!(original.record_key.is_none());
        let cause = original.failure().unwrap().downcast_ref::<StorageStateError>().unwrap();
        let validation = original.validation.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(cause, validation));
        assert!(matches!(validation, StorageStateError::InvalidTransition));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let validation_address = validation as *const StorageStateError;
        assert!(original.run(
            &mut store, operation, commitment, ObjectDigest::from_bytes([57; 32]),
            AtomicCommitEvidenceV1::Legacy, None,
        ).is_err());
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<StorageStateError>().unwrap(),
            validation_address,
        ));
    }
}
