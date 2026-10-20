//! Owns the completed models and actual response of recovery observation.
//!
//! The ordinary adapter and selected State caller share the same recipe. This
//! passive destination cannot construct a resource original or worker grant.

use super::*;

#[derive(Clone, Copy)]
enum ContextFailureV1 {
    Entry,
    Catalog,
    Transaction,
}

pub(super) struct ContextOriginalV1 {
    transaction: Option<Result<ZfsTransaction, ZfsTransactionError>>,
    catalog: Option<Result<ResolvedCatalogCommitmentV1, StorageStateError>>,
    entry: Option<Result<StorageRecoveryEntry, StorageStateError>>,
    first: Option<ContextFailureV1>,
}

impl ContextOriginalV1 {
    const fn new() -> Self {
        Self {
            transaction: None,
            catalog: None,
            entry: None,
            first: None,
        }
    }

    fn prepare(
        &mut self,
        store: &StorageTransactionStore,
        operation_id: [u8; 16],
    ) -> Result<(), ()> {
        self.entry = Some(store.current_recovery_entry(operation_id));
        let Some(entry) = self.entry.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.first = Some(ContextFailureV1::Entry);
            return Err(());
        };
        self.catalog = Some(store.recover_catalog(entry));
        let Some(Ok(catalog)) = self.catalog.as_ref() else {
            self.first = Some(ContextFailureV1::Catalog);
            return Err(());
        };
        self.transaction = Some(ZfsTransaction::from_catalog(catalog.plan().operation(), catalog));
        if !matches!(self.transaction, Some(Ok(_))) {
            self.first = Some(ContextFailureV1::Transaction);
            return Err(());
        }
        Ok(())
    }

    fn take_context(&mut self) -> PersistedZfsMutation {
        let Some(Ok(entry)) = self.entry.take() else { std::process::abort(); };
        let Some(Ok(catalog)) = self.catalog.take() else { std::process::abort(); };
        PersistedZfsMutation {
            entry,
            operation: catalog.plan().operation(),
            catalog,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            ContextFailureV1::Entry => self.entry.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            ContextFailureV1::Catalog => self.catalog.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            ContextFailureV1::Transaction => self.transaction.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
        }
    }

    fn take_failure(&mut self) -> ZfsHelperError {
        let cause = match self.first.take() {
            Some(ContextFailureV1::Entry) => self.entry.take().and_then(Result::err)
                .map(ZfsHelperError::State),
            Some(ContextFailureV1::Catalog) => self.catalog.take().and_then(Result::err)
                .map(ZfsHelperError::State),
            Some(ContextFailureV1::Transaction) => self.transaction.take().and_then(Result::err)
                .map(ZfsHelperError::Transaction),
            None => None,
        };
        match cause {
            Some(cause) => cause,
            None => std::process::abort(),
        }
    }
}

pub(super) fn context_ordinary(
    store: &StorageTransactionStore,
    operation_id: [u8; 16],
) -> Result<PersistedZfsMutation, ZfsHelperError> {
    let mut original = ContextOriginalV1::new();
    match original.prepare(store, operation_id) {
        Ok(()) => {
            // The former temporary transaction ended before Context creation.
            drop(original.transaction.take());
            Ok(original.take_context())
        }
        Err(()) => Err(original.take_failure()),
    }
}

#[derive(Clone, Copy)]
enum PostFailureV1 {
    Transaction,
    Observation,
    Comparison,
    Snapshot,
    Supplement,
    Commit,
}

/// Keeps the returned observation before transaction in ordinary drop order.
pub(super) struct PostOriginalV1 {
    commit: Option<Result<crate::CommittedStorageResultV1, StorageStateError>>,
    supplement: Option<Result<crate::snapshot_metadata::CatalogCommitSupplementV1, ZfsHelperError>>,
    snapshot: Option<Result<Option<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1>, ZfsHelperError>>,
    comparison: Option<Result<(), ZfsHelperError>>,
    observation: Option<Result<Option<ZfsPostconditionObservation>, ZfsHelperError>>,
    transaction: Option<Result<ZfsTransaction, ZfsTransactionError>>,
    first: Option<PostFailureV1>,
}

impl PostOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            commit: None,
            supplement: None,
            snapshot: None,
            comparison: None,
            observation: None,
            transaction: None,
            first: None,
        }
    }

    pub(super) fn run<B: ZfsProcessBackend>(
        &mut self,
        backend: &mut B,
        contract: &ZfsHelperContract,
        store: &mut StorageTransactionStore,
        context: &PersistedZfsMutation,
        phase: DurableStoragePhase,
        mut receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<ZfsHelperOutcome, ()> {
        self.transaction = Some(ZfsTransaction::from_catalog(context.operation, &context.catalog));
        let Some(Ok(transaction)) = self.transaction.as_ref() else {
            self.first = Some(PostFailureV1::Transaction);
            return Err(());
        };
        let program = sealed_program(contract, context);
        self.observation = Some(match receiving.as_deref_mut() {
            Some(receiving) => {
                let mut physical = crate::process::receiving_stage::StoragePhysicalWorkerStageV1
                    ::state(receiving, store.recovery_encoding_journal_v1());
                backend.observe_postcondition_receiving_v1(
                    &program, transaction.postcondition(),
                    transaction.ancestor_transaction().map(AncestorPolicyTransaction::postcondition),
                    &mut physical,
                )
            }
            None => backend.observe_postcondition(
                &program, transaction.postcondition(),
                transaction.ancestor_transaction().map(AncestorPolicyTransaction::postcondition),
            ),
        });
        let Some(Ok(observation)) = self.observation.as_ref() else {
            self.first = Some(PostFailureV1::Observation);
            return Err(());
        };
        let Some(observation) = observation.as_ref() else {
            return Ok(ZfsHelperOutcome::ObservationRequired {
                phase,
                mutation_digest: context.entry.mutation_digest(),
            });
        };
        self.comparison = Some(if phase == DurableStoragePhase::Prepared {
            Err(ZfsHelperError::PreparedPostconditionConflict)
        } else if observation.ancestor.as_ref()
            != transaction.ancestor_transaction().map(AncestorPolicyTransaction::postcondition)
        {
            Err(ZfsHelperError::PostconditionMismatch)
        } else {
            Ok(())
        });
        if !matches!(self.comparison, Some(Ok(()))) {
            self.first = Some(PostFailureV1::Comparison);
            return Err(());
        }
        self.supplement = Some(match context.catalog.plan() {
            crate::CatalogPlanV1::Snapshot { .. } => {
                self.snapshot = Some(match receiving.as_deref_mut() {
                    Some(receiving) => backend.snapshot_metadata_receiving_v1(
                        context.entry.operation_id(), store.recovery_encoding_journal_v1(), receiving,
                    ),
                    None => backend.snapshot_metadata(context.entry.operation_id()),
                });
                let Some(Ok(metadata)) = self.snapshot.as_ref() else {
                    self.first = Some(PostFailureV1::Snapshot);
                    return Err(());
                };
                metadata.map(crate::snapshot_metadata::SnapshotCommitEvidenceV1::from_checked_record)
                    .map(crate::snapshot_metadata::CatalogCommitSupplementV1::Snapshot)
                    .ok_or(ZfsHelperError::PostconditionMismatch)
            }
            _ => Ok(crate::snapshot_metadata::CatalogCommitSupplementV1::None),
        });
        if !matches!(self.supplement, Some(Ok(_))) {
            self.first = Some(PostFailureV1::Supplement);
            return Err(());
        }
        let Some(Ok(supplement)) = self.supplement.take() else { std::process::abort(); };
        self.commit = Some(match receiving {
            Some(receiving) => store.commit_observed_with_supplement_receiving_v1(
                context.entry.operation_id(), context.entry.mutation_digest(), &context.catalog,
                &observation.observed, observation.object_guid, observation.digest, supplement,
                receiving,
            ),
            None => store.commit_observed_with_supplement(
                context.entry.operation_id(), context.entry.mutation_digest(), &context.catalog,
                &observation.observed, observation.object_guid, observation.digest, supplement,
            ),
        });
        let Some(result) = self.commit.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.first = Some(PostFailureV1::Commit);
            return Err(());
        };
        Ok(ZfsHelperOutcome::Committed(result))
    }

    fn snapshot_failed(&self) -> bool {
        matches!(self.first, Some(PostFailureV1::Snapshot))
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            PostFailureV1::Transaction => self.transaction.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            PostFailureV1::Observation => self.observation.as_ref()?.as_ref().err()
                .map(super::recovery_results::resolve_helper_cause),
            PostFailureV1::Comparison => self.comparison.as_ref()?.as_ref().err()
                .map(super::recovery_results::resolve_helper_cause),
            PostFailureV1::Snapshot => self.snapshot.as_ref()?.as_ref().err()
                .map(super::recovery_results::resolve_helper_cause),
            PostFailureV1::Supplement => self.supplement.as_ref()?.as_ref().err()
                .map(super::recovery_results::resolve_helper_cause),
            PostFailureV1::Commit => self.commit.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
        }
    }

    pub(super) fn take_failure(&mut self) -> ZfsHelperError {
        let cause = match self.first.take() {
            Some(PostFailureV1::Transaction) => self.transaction.take().and_then(Result::err)
                .map(ZfsHelperError::Transaction),
            Some(PostFailureV1::Observation) => self.observation.take().and_then(Result::err),
            Some(PostFailureV1::Comparison) => self.comparison.take().and_then(Result::err),
            Some(PostFailureV1::Snapshot) => self.snapshot.take().and_then(Result::err),
            Some(PostFailureV1::Supplement) => self.supplement.take().and_then(Result::err),
            Some(PostFailureV1::Commit) => self.commit.take().and_then(Result::err)
                .map(ZfsHelperError::State),
            None => None,
        };
        match cause {
            Some(cause) => cause,
            None => std::process::abort(),
        }
    }
}

/// Orders completed post owners before the context they borrow during entry.
pub(super) struct ObservationOriginalV1 {
    post: PostOriginalV1,
    phase: Option<Result<(), ZfsHelperError>>,
    context: Option<PersistedZfsMutation>,
    source: ContextOriginalV1,
    result: Option<Result<ZfsHelperOutcome, ()>>,
    armed: bool,
}

impl ObservationOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            post: PostOriginalV1::new(),
            phase: None,
            context: None,
            source: ContextOriginalV1::new(),
            result: None,
            armed: false,
        }
    }

    pub(super) fn run<B: ZfsProcessBackend>(
        &mut self,
        backend: &mut B,
        contract: &ZfsHelperContract,
        store: &mut StorageTransactionStore,
        operation_id: [u8; 16],
        receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) {
        if self.result.is_some() {
            return;
        }
        self.armed = receiving.is_some();
        self.result = Some((|| {
            self.source.prepare(store, operation_id)?;
            if receiving.is_none() {
                // Ordinary context validation's temporary ended here.
                drop(self.source.transaction.take());
            }
            self.context = Some(self.source.take_context());
            let Some(context) = self.context.as_ref() else { std::process::abort(); };
            self.phase = Some(if matches!(context.entry.phase(),
                DurableStoragePhase::Prepared | DurableStoragePhase::Ambiguous)
            {
                Ok(())
            } else {
                Err(StorageStateError::InvalidTransition.into())
            });
            if !matches!(self.phase, Some(Ok(()))) {
                return Err(());
            }
            self.post.run(backend, contract, store, context, context.entry.phase(), receiving)
        })());
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.failure()
            .or_else(|| self.phase.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.post.failure())
    }

    pub(super) fn take_ordinary_result(&mut self) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        if let Some(Ok(outcome)) = self.result.take() {
            return Ok(outcome);
        }
        if self.source.failure().is_some() {
            return Err(self.source.take_failure());
        }
        if let Some(Err(cause)) = self.phase.take() {
            return Err(cause);
        }
        Err(self.post.take_failure())
    }
}

#[derive(Default)]
pub(super) struct RecoveryObservationsV1 {
    attempts: Vec<ObservationOriginalV1>,
    shape: Option<Result<(usize, usize), aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    armed: bool,
}

impl RecoveryObservationsV1 {
    pub(super) fn capture<B: ZfsProcessBackend>(
        &mut self,
        backend: &mut B,
        contract: &ZfsHelperContract,
        store: &mut StorageTransactionStore,
        operation_id: [u8; 16],
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<ZfsHelperOutcome, ZfsHelperError> {
        if self.failure(backend).is_some() {
            return Err(StorageStateError::Receiving.into());
        }
        self.shape = Some(self.shape(contract));
        let Some((bytes, cells)) = self.shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving.into());
        };
        self.payment = Some(receiving.reserve_encoded_capacity_v1(bytes, cells));
        if !matches!(self.payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving.into());
        }
        self.allocation = Some(self.attempts.try_reserve_exact(1));
        if !matches!(self.allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving.into());
        }
        self.armed = true;
        let mut attempt = ObservationOriginalV1::new();
        attempt.run(backend, contract, store, operation_id, Some(receiving));
        self.attempts.push(attempt);
        self.attempts.last().and_then(|attempt| attempt.result.as_ref())
            .and_then(|result| result.as_ref().ok()).cloned()
            .ok_or_else(|| StorageStateError::Receiving.into())
    }

    fn shape(&self, contract: &ZfsHelperContract)
        -> Result<(usize, usize), aos_sandbox_model::AccountingError>
    {
        use aos_sandbox_model::{AccountingError, ResourceDimension};
        let bytes = self.attempts.len().checked_add(1)
            .and_then(|slots| slots.checked_mul(std::mem::size_of::<ObservationOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(
                contract.executable().as_os_str().as_encoded_bytes().len(),
            ))
            .ok_or(AccountingError::ArithmeticOverflow {
                dimension: ResourceDimension::MemoryBytes,
            })?;
        // The model-paid State stage covers actual catalog/transaction graphs.
        // Three copies of owner5 + attempt6 + context4 + post7 are joined
        // by program1/guard1/input1/output1/move1/shape2, enclosing helper
        // destinations2/disposition1, and current argument references2.
        Ok((bytes, 3 * (5 + 6 + 4 + 7) + 12))
    }

    pub(super) fn failure<'a, B: ZfsProcessBackend>(
        &'a self,
        backend: &'a B,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        self.shape.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.allocation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.attempts.iter().find_map(|attempt| {
                if attempt.post.snapshot_failed() {
                    // This exact stage alone can project a coarse Snapshot
                    // error after its backend retained the earlier raw cause.
                    backend.snapshot_receiving_failure_v1().or_else(|| attempt.failure())
                } else {
                    attempt.failure()
                }
            }))
    }

    pub(super) fn require_positive<B: ZfsProcessBackend>(&self, backend: &B)
        -> Result<(), ZfsHelperError>
    {
        if self.failure(backend).is_some()
            || self.attempts.iter().any(|attempt| !matches!(attempt.result, Some(Ok(_))))
        {
            return Err(StorageStateError::Receiving.into());
        }
        Ok(())
    }

    pub(super) fn complete_positive_disposal(&mut self) {
        self.armed = false;
        for attempt in &mut self.attempts {
            attempt.armed = false;
        }
        self.attempts = Vec::new();
    }
}

impl Drop for RecoveryObservationsV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

impl Drop for ObservationOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{backend, fixture, open_store, prepare};

    #[test]
    fn prepared_conflict_keeps_completed_context_transaction_and_actual_observation() {
        let directory = tempfile::TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        prepare(&mut store, &catalog);
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let mut backend = backend(&catalog);
        let mut original = ObservationOriginalV1::new();

        original.run(&mut backend, &contract, &mut store, [3; 16], None);

        assert!(matches!(original.result, Some(Err(()))));
        assert!(matches!(original.post.transaction, Some(Ok(_))));
        assert!(matches!(original.post.observation, Some(Ok(Some(_)))));
        assert_eq!(original.context.as_ref().unwrap().catalog.binding(), catalog.binding());
        let actual_catalog = original.context.as_ref().unwrap().catalog.canonical_bytes().as_ptr();
        let cause = original.failure().unwrap().downcast_ref::<ZfsHelperError>().unwrap();
        assert!(matches!(cause, ZfsHelperError::PreparedPostconditionConflict));
        let actual_cause = cause as *const ZfsHelperError;

        original.run(&mut backend, &contract, &mut store, [8; 16], None);
        assert_eq!(original.context.as_ref().unwrap().catalog.canonical_bytes().as_ptr(), actual_catalog);
        assert_eq!(original.failure().unwrap().downcast_ref::<ZfsHelperError>().unwrap()
            as *const ZfsHelperError, actual_cause);
        assert!(original.post.commit.is_none());
        assert!(matches!(original.take_ordinary_result(),
            Err(ZfsHelperError::PreparedPostconditionConflict)));
    }

    #[test]
    fn missing_actual_entry_keeps_its_borrowed_state_cause_until_ordinary_projection() {
        let directory = tempfile::TempDir::new().unwrap();
        let (catalog, _) = fixture();
        let mut store = open_store(&directory);
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let mut backend = backend(&catalog);
        let mut original = ObservationOriginalV1::new();

        original.run(&mut backend, &contract, &mut store, [99; 16], None);

        let native = original.source.entry.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(native,
            original.failure().unwrap().downcast_ref::<StorageStateError>().unwrap()));
        assert!(original.context.is_none());
        assert!(original.post.observation.is_none());
        assert!(matches!(original.take_ordinary_result(),
            Err(ZfsHelperError::State(StorageStateError::InvalidTransition))));
    }
}
