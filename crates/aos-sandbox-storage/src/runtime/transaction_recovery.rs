//! Retains actual startup recovery rows through the enclosing State posts.
//!
//! Ordinary and selected passes share one observation/commit schedule. Only a
//! genuine model-paid State guard enters the selected collectors and workers.

use super::*;
use crate::helper::{ObservedAtomicSnapshotGroupV1, ZfsHelperError};
use crate::state::encoding::StateEncodingLoanV1;

#[derive(Clone, Copy)]
enum Failure {
    Shape,
    Payment,
    EntryAllocation,
    AtomicAllocation,
    Entries,
    Entry(usize),
    AtomicInventory,
    Atomic(usize),
}

struct EntryOriginalV1 {
    outcome: Option<Result<ZfsHelperOutcome, ZfsHelperError>>,
    verdict: Option<Result<usize, StorageRuntimeError>>,
    armed: bool,
}

impl EntryOriginalV1 {
    fn new(selected: bool) -> Self {
        Self {
            outcome: None,
            verdict: None,
            armed: selected,
        }
    }

    fn run<B: ZfsProcessBackend>(
        &mut self,
        coordinator: &mut StorageAdmissionCoordinator,
        helper: &mut StorageMutationHelper<B>,
        entry: crate::StorageRecoveryEntry,
        receiving: Option<&mut StateEncodingLoanV1<'_, '_>>,
    ) -> Result<usize, StorageRuntimeError> {
        self.outcome = Some(match receiving {
            Some(receiving) => coordinator.reconcile_recovery_receiving_v1(helper, entry, receiving),
            None => coordinator.reconcile_recovery(helper, entry),
        });
        let Some(Ok(outcome)) = self.outcome.as_ref() else {
            return Err(StorageRuntimeError::Recovery);
        };
        self.verdict = Some(match outcome {
            ZfsHelperOutcome::Committed(_) => Ok(0),
            ZfsHelperOutcome::Aborted { .. } => Err(StorageRuntimeError::Recovery),
            ZfsHelperOutcome::ObservationRequired { .. } => Ok(1),
        });
        match self.verdict.as_ref() {
            Some(Ok(pending)) => Ok(*pending),
            _ => Err(StorageRuntimeError::Recovery),
        }
    }

    fn failure<'a, B: ZfsProcessBackend>(
        &'a self,
        coordinator: &'a StorageAdmissionCoordinator,
        helper: &'a StorageMutationHelper<B>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        self.outcome
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| resolve_helper_failure(cause, coordinator, helper))
            .or_else(|| {
                self.verdict.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)
            })
    }

    fn is_positive(&self) -> bool {
        matches!(self.outcome, Some(Ok(_))) && matches!(self.verdict, Some(Ok(_)))
    }
}

impl Drop for EntryOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[derive(Clone, Copy)]
enum AtomicFailure {
    Evidence,
    Commit,
}

struct AtomicOriginalV1 {
    // The original map_err consumed a commit error before its evidence local.
    commit: Option<Result<(), StorageBrokerError>>,
    evidence: Option<Result<ObservedAtomicSnapshotGroupV1, ZfsHelperError>>,
    first: Option<AtomicFailure>,
    armed: bool,
}

impl AtomicOriginalV1 {
    fn new(selected: bool) -> Self {
        Self {
            commit: None,
            evidence: None,
            first: None,
            armed: selected,
        }
    }

    fn run<B: ZfsProcessBackend>(
        &mut self,
        coordinator: &mut StorageAdmissionCoordinator,
        helper: &mut StorageMutationHelper<B>,
        record: &crate::state::AtomicDatasetSnapshotInventoryV1,
        mut receiving: Option<&mut StateEncodingLoanV1<'_, '_>>,
    ) -> Result<usize, StorageRuntimeError> {
        let program = record.program();
        let selected = receiving.is_some();
        self.first = Some(AtomicFailure::Evidence);
        self.evidence = Some(match receiving.as_deref_mut() {
            Some(receiving) => helper.atomic_snapshot_once_receiving_v1(
                program,
                false,
                coordinator.recovery_encoding_journal_v1(),
                receiving,
            ),
            None => helper.atomic_snapshot_once(program, false),
        });
        let Some(Ok(evidence)) = self.evidence.as_ref() else {
            // Ordinary recovery leaves a failed physical probe pending. The
            // selected interval keeps its actual uncertainty and closes.
            return if selected {
                Err(StorageRuntimeError::Recovery)
            } else {
                Ok(1)
            };
        };
        self.first = Some(AtomicFailure::Commit);
        self.commit = Some(match receiving {
            Some(receiving) if program.format_version() == 1 => coordinator
                .commit_atomic_dataset_snapshot_receiving_v1(
                    program.operation(), program.commitment(), evidence.digest(), receiving,
                ),
            Some(receiving) => coordinator.commit_atomic_dataset_snapshot_with_evidence_receiving_v1(
                program.operation(), program.commitment(), evidence.digest(), evidence.member_guids(),
                receiving,
            ),
            None if program.format_version() == 1 => coordinator.commit_atomic_dataset_snapshot(
                program.operation(), program.commitment(), evidence.digest(),
            ),
            None => coordinator.commit_atomic_dataset_snapshot_with_evidence(
                program.operation(), program.commitment(), evidence.digest(), evidence.member_guids(),
            ),
        });
        if !matches!(self.commit, Some(Ok(()))) {
            return Err(StorageRuntimeError::Recovery);
        }
        self.first = None;
        Ok(0)
    }

    fn failure<'a, B: ZfsProcessBackend>(
        &'a self,
        coordinator: &'a StorageAdmissionCoordinator,
        helper: &'a StorageMutationHelper<B>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        match self.first? {
            AtomicFailure::Evidence => self.evidence.as_ref()?.as_ref().err()
                .map(|cause| resolve_helper_failure(cause, coordinator, helper)),
            AtomicFailure::Commit => self.commit.as_ref()?.as_ref().err().map(|cause| {
                if matches!(cause, StorageBrokerError::State(StorageStateError::Receiving)) {
                    coordinator.recovery_receiving_failure_v1()
                        .unwrap_or(cause as &dyn std::error::Error)
                } else {
                    cause as &dyn std::error::Error
                }
            }),
        }
    }

    fn is_positive(&self) -> bool {
        self.first.is_none()
            && matches!(self.evidence, Some(Ok(_)))
            && matches!(self.commit, Some(Ok(())))
    }
}

impl Drop for AtomicOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

pub(super) fn resolve_helper_failure<'a, B: ZfsProcessBackend>(
    cause: &'a ZfsHelperError,
    coordinator: &'a StorageAdmissionCoordinator,
    helper: &'a StorageMutationHelper<B>,
) -> &'a (dyn std::error::Error + 'static) {
    if matches!(cause, ZfsHelperError::State(StorageStateError::Receiving)) {
        coordinator.recovery_receiving_failure_v1()
            .or_else(|| helper.recovery_receiving_failure_v1())
            .unwrap_or(cause as &dyn std::error::Error)
    } else if let ZfsHelperError::Backend(worker) = cause {
        match worker.physical_native_refusal_v1() {
            Some(marker) => marker as &dyn std::error::Error,
            None => cause as &dyn std::error::Error,
        }
    } else {
        cause as &dyn std::error::Error
    }
}

pub(super) struct TransactionRecoveryOriginalV1 {
    entries: Option<Result<Vec<crate::StorageRecoveryEntry>, ZfsHelperError>>,
    atomic_inventory: Option<Result<
        Vec<crate::state::AtomicDatasetSnapshotInventoryV1>,
        StorageBrokerError,
    >>,
    ordinary_atomic_inventory:
        Option<std::vec::IntoIter<crate::state::AtomicDatasetSnapshotInventoryV1>>,
    entry_outcomes: Vec<EntryOriginalV1>,
    atomic_outcomes: Vec<AtomicOriginalV1>,
    shape: Option<Result<(usize, usize), aos_sandbox_core::AccountingError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    entry_allocation: Option<Result<(), std::collections::TryReserveError>>,
    atomic_allocation: Option<Result<(), std::collections::TryReserveError>>,
    first: Option<Failure>,
    entered: bool,
    armed: bool,
}

impl TransactionRecoveryOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            entries: None,
            atomic_inventory: None,
            ordinary_atomic_inventory: None,
            entry_outcomes: Vec::new(),
            atomic_outcomes: Vec::new(),
            shape: None,
            payment: None,
            entry_allocation: None,
            atomic_allocation: None,
            first: None,
            entered: false,
            armed: false,
        }
    }

    // The selected caller must retain this owner until its same State posts
    // and every sibling positive disposition have completed. An unfinished
    // selected interval cannot unwind through and dispose its originals.
    pub(super) fn run<B: ZfsProcessBackend>(
        &mut self,
        coordinator: &mut StorageAdmissionCoordinator,
        helper: &mut StorageMutationHelper<B>,
        mut receiving: Option<&mut StateEncodingLoanV1<'_, '_>>,
    ) -> Result<usize, StorageRuntimeError> {
        if self.entered {
            return Err(StorageRuntimeError::Receiving);
        }
        self.entered = true;
        let selected = receiving.is_some();
        self.armed = selected;
        if let Some(receiving) = receiving.as_deref_mut() {
            let (entries, atomic) = coordinator.recovery_row_counts_v1();
            self.first = Some(Failure::Shape);
            self.shape = Some(shape(entries, atomic));
            let Some(Ok((bytes, cells))) = self.shape.as_ref() else {
                return Err(StorageRuntimeError::Receiving);
            };
            self.first = Some(Failure::Payment);
            self.payment = Some(receiving.reserve_encoded_capacity_v1(*bytes, *cells));
            if !matches!(self.payment, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
            self.first = Some(Failure::EntryAllocation);
            self.entry_allocation = Some(self.entry_outcomes.try_reserve_exact(entries));
            if !matches!(self.entry_allocation, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
            self.first = Some(Failure::AtomicAllocation);
            self.atomic_allocation = Some(self.atomic_outcomes.try_reserve_exact(atomic));
            if !matches!(self.atomic_allocation, Some(Ok(()))) {
                return Err(StorageRuntimeError::Receiving);
            }
        }

        self.first = Some(Failure::Entries);
        self.entries = Some(coordinator.recovery_entries());
        let Some(Ok(entries)) = self.entries.as_ref() else {
            return Err(StorageRuntimeError::Recovery);
        };
        let mut pending = 0;
        for entry in entries.iter().copied() {
            if matches!(entry.phase(), DurableStoragePhase::Committed | DurableStoragePhase::Aborted) {
                continue;
            }
            let mut original = EntryOriginalV1::new(selected);
            let result = original.run(coordinator, helper, entry, receiving.as_deref_mut());
            if selected {
                let index = self.entry_outcomes.len();
                self.entry_outcomes.push(original);
                self.first = Some(Failure::Entry(index));
            }
            pending += result?;
        }
        if !selected {
            // The original first loop consumed its Vec before the next query.
            drop(self.entries.take());
        }

        self.first = Some(Failure::AtomicInventory);
        self.atomic_inventory = Some(coordinator.atomic_dataset_snapshot_inventory());
        if !matches!(self.atomic_inventory, Some(Ok(_))) {
            return Err(StorageRuntimeError::Recovery);
        }
        if !selected {
            let Some(Ok(inventory)) = self.atomic_inventory.take() else {
                std::process::abort();
            };
            self.ordinary_atomic_inventory = Some(inventory.into_iter());
        }
        let atomic_count = if selected {
            self.atomic_inventory.as_ref().and_then(|result| result.as_ref().ok())
                .map_or(0, Vec::len)
        } else {
            self.ordinary_atomic_inventory.as_ref().map_or(0, ExactSizeIterator::len)
        };
        for index in 0..atomic_count {
            let ordinary_record = if selected {
                None
            } else {
                self.ordinary_atomic_inventory.as_mut().and_then(Iterator::next)
            };
            let record = if selected {
                self.atomic_inventory.as_ref().and_then(|result| result.as_ref().ok())
                    .and_then(|records| records.get(index))
            } else {
                ordinary_record.as_ref()
            };
            let Some(record) = record else {
                std::process::abort();
            };
            match record.phase() {
                crate::state::AtomicDatasetSnapshotPhaseV1::Prepared => pending += 1,
                crate::state::AtomicDatasetSnapshotPhaseV1::Committed => {}
                crate::state::AtomicDatasetSnapshotPhaseV1::Ambiguous => {
                    let mut original = AtomicOriginalV1::new(selected);
                    let result = original.run(coordinator, helper, record, receiving.as_deref_mut());
                    if selected {
                        let index = self.atomic_outcomes.len();
                        self.atomic_outcomes.push(original);
                        self.first = Some(Failure::Atomic(index));
                    }
                    pending += result?;
                }
            }
            // The ordinary current item ended at this same loop boundary.
            drop(ordinary_record);
        }
        if !selected {
            drop(self.ordinary_atomic_inventory.take());
        }
        self.first = None;
        Ok(pending)
    }

    pub(super) fn failure<'a, B: ZfsProcessBackend>(
        &'a self,
        coordinator: &'a StorageAdmissionCoordinator,
        helper: &'a StorageMutationHelper<B>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Payment => self.payment.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::EntryAllocation => self.entry_allocation.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::AtomicAllocation => self.atomic_allocation.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Entries => self.entries.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Entry(index) => self.entry_outcomes.get(index)?.failure(coordinator, helper),
            Failure::AtomicInventory => self.atomic_inventory.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Atomic(index) => self.atomic_outcomes.get(index)?.failure(coordinator, helper),
        }
    }

    #[cfg(test)]
    pub(super) const fn entered_for_test_v1(&self) -> bool { self.entered }

    pub(super) fn prepare_positive_disposal_v1(
        &mut self,
    ) -> Result<TransactionRecoveryDispositionV1<'_>, StorageRuntimeError> {
        self.require_positive()?;
        Ok(TransactionRecoveryDispositionV1 { original: self })
    }

    pub(super) fn prepare_positive_or_unused_disposal_v1(
        &mut self,
    ) -> Result<TransactionRecoveryDispositionV1<'_>, StorageRuntimeError> {
        if !self.entered && !self.armed && self.first.is_none()
            && self.entries.is_none() && self.atomic_inventory.is_none()
            && self.ordinary_atomic_inventory.is_none()
            && self.entry_outcomes.is_empty() && self.atomic_outcomes.is_empty()
            && self.shape.is_none() && self.payment.is_none()
            && self.entry_allocation.is_none() && self.atomic_allocation.is_none()
        {
            return Ok(TransactionRecoveryDispositionV1 { original: self });
        }
        self.prepare_positive_disposal_v1()
    }

    fn require_positive(&self) -> Result<(), StorageRuntimeError> {
        if !self.entered
            || !matches!(self.payment, Some(Ok(())))
            || self.first.is_some()
            || self.entry_outcomes.iter().any(|row| !row.is_positive())
            || self.atomic_outcomes.iter().any(|row| !row.is_positive())
        {
            return Err(StorageRuntimeError::Receiving);
        }
        Ok(())
    }

    pub(super) fn complete_positive_disposal(&mut self) {
        for row in &mut self.entry_outcomes {
            row.armed = false;
        }
        for row in &mut self.atomic_outcomes {
            row.armed = false;
        }
        self.armed = false;
        self.entries = None;
        self.atomic_inventory = None;
        self.entry_outcomes = Vec::new();
        self.atomic_outcomes = Vec::new();
    }
}

/// Disposes only the actual positive row carriers after all fallible posts.
#[must_use]
pub(super) struct TransactionRecoveryDispositionV1<'owner> {
    original: &'owner mut TransactionRecoveryOriginalV1,
}

impl TransactionRecoveryDispositionV1<'_> {
    pub(super) fn complete_after_disposal_v1(self) {
        self.original.complete_positive_disposal();
    }
}

impl Drop for TransactionRecoveryOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

fn shape(entries: usize, atomic: usize) -> Result<(usize, usize), aos_sandbox_core::AccountingError> {
    use aos_sandbox_core::{AccountingError, ResourceDimension};
    let memory_overflow = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MemoryBytes,
    };
    let bytes = entries.max(4).checked_mul(std::mem::size_of::<crate::StorageRecoveryEntry>())
        .zip(entries.checked_mul(std::mem::size_of::<EntryOriginalV1>()))
        .and_then(|(entries, outcomes)| entries.checked_add(outcomes))
        .zip(atomic.max(4).checked_mul(std::mem::size_of::<crate::state::AtomicDatasetSnapshotInventoryV1>()))
        .and_then(|(entries, atomic)| entries.checked_add(atomic))
        .zip(atomic.checked_mul(std::mem::size_of::<AtomicOriginalV1>()))
        .and_then(|(bytes, outcomes)| bytes.checked_add(outcomes))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<TransactionRecoveryOriginalV1>()))
        .ok_or_else(memory_overflow)?;
    // Owner12; actual entry7 + entry outcome3; inventory9 + atomic outcome4
    // + returned evidence2. Three carriers include caller/old/new backing;
    // Method operands14, pass locals19, entry projections3, atomic projections5,
    // shape parameters/results6, disposition/projection controls7 and wrapper
    // locals2 are distinct from the owned fields and row backing above.
    const CALL_AND_DISPOSITION_CELLS: usize = 14 + 19 + 3 + 5 + 6 + 7 + 2;
    let cells = entries.checked_mul(7 + 3)
        .zip(atomic.checked_mul(9 + 4 + 2))
        .and_then(|(entries, atomic)| entries.checked_add(atomic))
        .and_then(|rows| rows.checked_add(12))
        .and_then(|cells| cells.checked_mul(3))
        .and_then(|cells| cells.checked_add(CALL_AND_DISPOSITION_CELLS))
        .ok_or(AccountingError::ArithmeticOverflow {
            dimension: ResourceDimension::MetadataEntries,
        })?;
    Ok((bytes, cells))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal_files(directory: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(directory).unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_file())
            .map(|path| {
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        files.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        files
    }

    #[test]
    fn repeated_ordinary_terminal_recovery_does_not_probe_or_append() {
        let transactions = tempfile::tempdir().unwrap();
        let workspaces = tempfile::tempdir().unwrap();
        // This existing real signed State fixture has only committed mutation
        // history and a backend that rejects any unexpected ZFS invocation.
        let mut runtime = crate::broker::native_runtime_fixture_for_test(
            &transactions, &workspaces,
        );
        let before = journal_files(transactions.path());
        let entries = runtime.coordinator.recovery_entries().unwrap();

        assert_eq!(super::super::reconcile_transaction_recovery(
            &mut runtime.coordinator, &mut runtime.helper,
        ).unwrap(), 0);
        assert_eq!(super::super::reconcile_transaction_recovery(
            &mut runtime.coordinator, &mut runtime.helper,
        ).unwrap(), 0);

        assert_eq!(runtime.coordinator.recovery_entries().unwrap(), entries);
        assert_eq!(journal_files(transactions.path()), before);
    }
}


#[cfg(test)]
mod unused_inventory_disposition_tests {
    use super::*;

    #[test]
    fn unused_inventory_disposition_does_not_enter_or_price_transaction_recovery() {
        let mut original = TransactionRecoveryOriginalV1::new();

        let disposition = original.prepare_positive_or_unused_disposal_v1().unwrap();
        disposition.complete_after_disposal_v1();

        assert!(!original.entered);
        assert!(!original.armed);
        assert!(original.payment.is_none());
        assert!(original.entries.is_none());
    }

    #[test]
    fn a_reached_collection_is_not_an_unused_transaction_interval() {
        let mut original = TransactionRecoveryOriginalV1::new();
        original.entries = Some(Ok(Vec::new()));

        assert!(original.prepare_positive_or_unused_disposal_v1().is_err());

        assert!(matches!(original.entries, Some(Ok(_))));
        assert!(!original.entered);
    }

    #[test]
    fn an_entered_unpaid_interval_cannot_take_the_inventory_disposition() {
        let mut original = TransactionRecoveryOriginalV1::new();
        original.entered = true;

        assert!(original.prepare_positive_or_unused_disposal_v1().is_err());

        assert!(original.entered);
        assert!(original.payment.is_none());
    }
}
