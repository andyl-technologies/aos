//! Real directory-write, restart and source-fence mechanism controls.
//!
//! The sealed release inputs below are test-only state-machine witnesses.
//! They do not qualify destination readiness or a native execution handoff.

// crucible-lint: allow panic-shortcut -- exact ledger transition controls stop on failed assertions.
#![allow(clippy::expect_used)]

use std::cell::Cell;
use std::time::Duration;

use super::super::tests::{checkpoint, daemon_epoch, lineage, request, resources};
use super::*;
use crate::{AssignmentLedgerError, DirectoryAssignmentLedger, SourceTransferPhase};
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
};

fn fixture() -> (
    SubmitAttemptRequest,
    AttemptExecutionKey,
    AttemptRuntimeState,
) {
    let assignment = request(0x31, 0x32, daemon_epoch(0x33), resources(1, 2048, 4096));
    let key = AttemptExecutionKey::for_request(&assignment);
    let paused = AttemptRuntimeState::Paused {
        execution_basis: assignment.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: assignment.daemon_epoch(),
        execution: ExecutionId::from_bytes([0x34; 16]).expect("execution identity"),
        checkpoint: checkpoint(0x35),
        promotion_basis: None,
        source_transfer: None,
    };
    (assignment, key, paused)
}

fn intent() -> SourceTransferIntent {
    SourceTransferIntent {
        operation: crucible_campaign::CampaignHash::from_bytes([0x36; 32]),
        destination: daemon_epoch(0x37),
        namespace: crucible_campaign::CampaignHash::from_bytes([0x38; 32]),
        offer_generation: 1,
        durable_placements: 1,
    }
}

fn original_supervisor() -> HostOperationSupervisor {
    // This is the existing finite component-operation profile, not a native
    // resource grant. No operation starts again between prepare and release.
    HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )
    .expect("finite original operation owner")
}

fn executor<L: AssignmentLedger>(
    ledger: L,
) -> LocalExecutorSupervisor<L, AllowAllAttemptAdmission> {
    LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        daemon_epoch(0x33),
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("existing component capacity"),
    )
}

fn directory(root: &std::path::Path) -> DirectoryAssignmentLedger {
    let (_, key, paused) = fixture();
    let mut ledger = DirectoryAssignmentLedger::open(root).expect("actual directory writer");
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(paused))
            .expect("durable pause"),
        AttemptStateCas::Advanced,
    );
    ledger
}

fn authorization<'original>(
    preparation: &SourceTransferPreparation<'original>,
) -> SourceTransferReleaseAuthorization<'original> {
    SourceTransferReleaseAuthorization {
        key: preparation.key,
        prepared: preparation.prepared,
        original: preparation.original,
        readiness: crucible_campaign::CampaignHash::from_bytes([0x39; 32]),
        ownership_generation: 1,
    }
}

fn assert_source_is_fenced<L: AssignmentLedger>(
    supervisor: &mut LocalExecutorSupervisor<L, AllowAllAttemptAdmission>,
) where
    L::Error: std::fmt::Debug,
{
    let (assignment, key, paused) = fixture();
    let before = supervisor
        .ledger()
        .load_attempt(key)
        .expect("durable source state");
    let resume =
        ResumeAttemptExecutionRequest::new(&assignment, paused.execution(), checkpoint(0x35))
            .expect("ordinary resume request");
    assert!(matches!(
        supervisor
            .resume_attempt_execution(&resume)
            .expect("ordinary resume refusal")
            .disposition(),
        ResumeAttemptExecutionDisposition::NotCurrent,
    ));
    assert!(matches!(
        supervisor
            .submit_attempt(&assignment)
            .expect("ordinary submit refusal")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Incompatible
        },
    ));
    assert!(matches!(
        supervisor
            .cancel_execution(key, paused.execution())
            .expect("ordinary cancel refusal"),
        CancellationOutcome::NotCurrent,
    ));
    assert!(matches!(
        supervisor
            .request_checkpoint(key, paused.execution())
            .expect("ordinary checkpoint refusal"),
        CheckpointRequestOutcome::NotCurrent,
    ));
    assert!(supervisor.next_queued().is_none());
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(
        supervisor
            .ledger()
            .load_attempt(key)
            .expect("unchanged fence"),
        before
    );
}

#[test]
fn preparation_survives_actual_writer_reopen_and_refuses_source_execution() {
    let root = tempfile::tempdir().expect("ledger directory");
    let mut supervisor = executor(directory(root.path()));
    let original = original_supervisor();
    let operation = original
        .begin(HostOperationClass::Transfer)
        .expect("original transfer");
    let (_, key, paused) = fixture();
    {
        let preparation = supervisor
            .prepare_source_transfer(key, paused, intent(), &operation)
            .expect("durable preparation");
        assert_eq!(preparation.checkpoint(), Some(checkpoint(0x35)));
        assert_source_is_fenced(&mut supervisor);
    }
    drop(supervisor);

    let mut reopened =
        executor(DirectoryAssignmentLedger::open(root.path()).expect("reopen writer"));
    assert_source_is_fenced(&mut reopened);
    assert!(matches!(
        reopened.prepare_source_transfer(key, paused, intent(), &operation),
        Err(SourceTransferFailure::NotCurrent),
    ));
    let mut roots = Vec::new();
    reopened
        .ledger()
        .visit_checkpoint_roots(&mut |root| roots.push(root))
        .expect("retention scan");
    assert_eq!(roots, vec![checkpoint(0x35)]);
}

#[test]
fn canceled_preparation_keeps_root_and_fence_after_actual_reopen() {
    let root = tempfile::tempdir().expect("ledger directory");
    let mut supervisor = executor(directory(root.path()));
    let original = original_supervisor();
    let operation = original
        .begin(HostOperationClass::Transfer)
        .expect("original transfer");
    let (_, key, paused) = fixture();
    {
        let preparation = supervisor
            .prepare_source_transfer(key, paused, intent(), &operation)
            .expect("preparation");
        supervisor
            .cancel_source_transfer(&preparation)
            .expect("durable canceled fence");
        supervisor
            .cancel_source_transfer(&preparation)
            .expect("same canceled disposition");
        assert!(
            supervisor
                .release_source_transfer(&preparation, authorization(&preparation))
                .is_err()
        );
    }
    drop(supervisor);

    let mut reopened =
        executor(DirectoryAssignmentLedger::open(root.path()).expect("reopen canceled source"));
    assert_source_is_fenced(&mut reopened);
    let state = reopened
        .ledger()
        .load_attempt(key)
        .expect("canceled state")
        .expect("record");
    assert_eq!(
        state.source_transfer().expect("fence").phase(),
        SourceTransferPhase::Canceled
    );
    assert_eq!(
        state.materialized_checkpoint_roots()[0],
        Some(checkpoint(0x35))
    );
}

#[test]
fn release_tombstone_survives_reopen_without_granting_destination_execution() {
    let root = tempfile::tempdir().expect("ledger directory");
    let mut supervisor = executor(directory(root.path()));
    let original = original_supervisor();
    let operation = original
        .begin(HostOperationClass::Transfer)
        .expect("original transfer");
    let (_, key, paused) = fixture();
    {
        let preparation = supervisor
            .prepare_source_transfer(key, paused, intent(), &operation)
            .expect("preparation");
        supervisor
            .release_source_transfer(&preparation, authorization(&preparation))
            .expect("source-only release");
        supervisor
            .release_source_transfer(&preparation, authorization(&preparation))
            .expect("identical released record");
        assert!(supervisor.cancel_source_transfer(&preparation).is_err());
    }
    drop(supervisor);

    let mut reopened =
        executor(DirectoryAssignmentLedger::open(root.path()).expect("reopen released source"));
    assert_source_is_fenced(&mut reopened);
    let state = reopened
        .ledger()
        .load_attempt(key)
        .expect("released state")
        .expect("record");
    assert!(matches!(
        state.source_transfer().expect("fence").phase(),
        SourceTransferPhase::Released {
            ownership_generation: 1,
            ..
        }
    ));
    assert!(matches!(
        reopened
            .ledger
            .compare_exchange_attempt(key, Some(state), None)
            .expect("attempt to discard tombstone"),
        AttemptStateCas::Conflict { .. }
    ));
    assert!(matches!(
        reopened
            .ledger
            .compare_exchange_attempt(key, Some(state), Some(paused))
            .expect("attempt to restore ordinary pause"),
        AttemptStateCas::Conflict { .. }
    ));
}

#[test]
fn foreign_release_and_canceled_original_cannot_change_prepared_state() {
    let root = tempfile::tempdir().expect("ledger directory");
    let mut supervisor = executor(directory(root.path()));
    let original = original_supervisor();
    let operation = original
        .begin(HostOperationClass::Transfer)
        .expect("original transfer");
    let (_, key, paused) = fixture();
    let preparation = supervisor
        .prepare_source_transfer(key, paused, intent(), &operation)
        .expect("preparation");
    let before = supervisor
        .ledger()
        .load_attempt(key)
        .expect("prepared state");
    let mut foreign = authorization(&preparation);
    foreign.key = AttemptExecutionKey::new(lineage(0x55), fixture().0.attempt());
    assert!(matches!(
        supervisor.release_source_transfer(&preparation, foreign),
        Err(SourceTransferFailure::InvalidBinding)
    ));
    let other_original = original_supervisor();
    let other_operation = other_original
        .begin(HostOperationClass::Transfer)
        .expect("different original transfer");
    let mut foreign = authorization(&preparation);
    foreign.original = &other_operation;
    assert!(matches!(
        supervisor.release_source_transfer(&preparation, foreign),
        Err(SourceTransferFailure::InvalidBinding)
    ));
    original.cancel().expect("cancel same original");
    assert!(matches!(
        supervisor.cancel_source_transfer(&preparation),
        Err(SourceTransferFailure::Original(
            HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            }
        ))
    ));
    assert_eq!(
        supervisor
            .ledger()
            .load_attempt(key)
            .expect("retained first fence"),
        before
    );
}

#[test]
fn wrong_operation_class_refuses_before_any_source_ledger_write() {
    let root = tempfile::tempdir().expect("ledger directory");
    let mut supervisor = executor(directory(root.path()));
    let (_, key, paused) = fixture();
    let original = original_supervisor();

    for class in [
        HostOperationClass::Setup,
        HostOperationClass::Cleanup,
        HostOperationClass::PageIn,
    ] {
        let operation = original.begin(class).expect("actual different class");
        assert!(matches!(
            supervisor.prepare_source_transfer(key, paused, intent(), &operation),
            Err(SourceTransferFailure::Original(
                HostSupervisionError::InvalidBudget
            ))
        ));
        assert_eq!(
            supervisor
                .ledger()
                .load_attempt(key)
                .expect("unchanged source"),
            Some(paused)
        );
    }

    let canceled = original
        .begin(HostOperationClass::Setup)
        .expect("actual Setup");
    original.cancel().expect("cancel same original");
    assert!(matches!(
        supervisor.prepare_source_transfer(key, paused, intent(), &canceled),
        Err(SourceTransferFailure::Original(
            HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            }
        ))
    ));
    drop(supervisor);
    let reopened = DirectoryAssignmentLedger::open(root.path()).expect("actual reopen");
    assert_eq!(
        reopened
            .load_attempt(key)
            .expect("durable unchanged source"),
        Some(paused)
    );
}

#[test]
fn exact_source_and_nonzero_intent_are_required_before_the_fence_write() {
    let root = tempfile::tempdir().expect("ledger directory");
    let mut supervisor = executor(directory(root.path()));
    let original = original_supervisor();
    let operation = original
        .begin(HostOperationClass::Transfer)
        .expect("original transfer");
    let (_, key, paused) = fixture();

    let mut stale = paused;
    if let AttemptRuntimeState::Paused { checkpoint, .. } = &mut stale {
        *checkpoint = super::super::tests::checkpoint(0x60);
    }
    assert!(matches!(
        supervisor.prepare_source_transfer(key, stale, intent(), &operation),
        Err(SourceTransferFailure::NotCurrent)
    ));
    for invalid in [
        SourceTransferIntent {
            operation: crucible_campaign::CampaignHash::from_bytes([0; 32]),
            ..intent()
        },
        SourceTransferIntent {
            namespace: crucible_campaign::CampaignHash::from_bytes([0; 32]),
            ..intent()
        },
        SourceTransferIntent {
            offer_generation: 0,
            ..intent()
        },
        SourceTransferIntent {
            durable_placements: 0,
            ..intent()
        },
    ] {
        assert!(matches!(
            supervisor.prepare_source_transfer(key, paused, invalid, &operation),
            Err(SourceTransferFailure::InvalidBinding)
        ));
    }
    assert_eq!(
        supervisor
            .ledger()
            .load_attempt(key)
            .expect("unchanged pause"),
        Some(paused)
    );
}

#[test]
fn durable_cas_refuses_changed_source_and_every_transfer_binding() {
    let root = tempfile::tempdir().expect("ledger directory");
    let mut supervisor = executor(directory(root.path()));
    let original = original_supervisor();
    let operation = original
        .begin(HostOperationClass::Transfer)
        .expect("original transfer");
    let (_, key, paused) = fixture();
    let preparation = supervisor
        .prepare_source_transfer(key, paused, intent(), &operation)
        .expect("preparation");
    let prepared = preparation.prepared;
    let mut changed_source = prepared;
    if let AttemptRuntimeState::Paused { checkpoint, .. } = &mut changed_source {
        *checkpoint = super::super::tests::checkpoint(0x61);
    }
    assert!(matches!(
        supervisor
            .ledger
            .compare_exchange_attempt(key, Some(prepared), Some(changed_source))
            .expect("source CAS"),
        AttemptStateCas::Conflict { .. }
    ));
    for changed in [
        SourceTransferIntent {
            operation: crucible_campaign::CampaignHash::from_bytes([0x62; 32]),
            ..intent()
        },
        SourceTransferIntent {
            destination: daemon_epoch(0x63),
            ..intent()
        },
        SourceTransferIntent {
            namespace: crucible_campaign::CampaignHash::from_bytes([0x64; 32]),
            ..intent()
        },
        SourceTransferIntent {
            offer_generation: 2,
            ..intent()
        },
        SourceTransferIntent {
            durable_placements: 2,
            ..intent()
        },
    ] {
        let next = prepared
            .with_source_transfer(
                SourceTransferState::prepared(changed).expect("valid changed declaration"),
            )
            .expect("paused source");
        assert!(matches!(
            supervisor
                .ledger
                .compare_exchange_attempt(key, Some(prepared), Some(next))
                .expect("binding CAS"),
            AttemptStateCas::Conflict { .. }
        ));
    }
    assert_source_is_fenced(&mut supervisor);
}

#[derive(Clone, Copy)]
enum Fault {
    BeforeWrite,
    AfterWrite,
    AfterWriteLostRead,
    CancelAfterWrite,
    WriteAndCancel,
}

#[derive(Debug, thiserror::Error)]
enum FaultError {
    #[error("actual directory failure")]
    Directory(#[source] AssignmentLedgerError),
    #[error("injected persistence failure")]
    Write,
    #[error("injected reconciliation failure")]
    Read,
}

struct FaultLedger<'original> {
    inner: DirectoryAssignmentLedger,
    fault: Fault,
    written: Cell<bool>,
    original: &'original HostOperationSupervisor,
}

impl AssignmentLedger for FaultLedger<'_> {
    type Error = FaultError;

    fn load_assignment(
        &self,
        id: crucible_campaign::AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        self.inner
            .load_assignment(id)
            .map_err(FaultError::Directory)
    }

    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        self.inner
            .publish_assignment(record)
            .map_err(FaultError::Directory)
    }

    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        if self.written.get() && matches!(self.fault, Fault::AfterWriteLostRead) {
            return Err(FaultError::Read);
        }
        self.inner.load_attempt(key).map_err(FaultError::Directory)
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        if matches!(self.fault, Fault::BeforeWrite) {
            return Err(FaultError::Write);
        }
        let outcome = self
            .inner
            .compare_exchange_attempt(key, expected, next)
            .map_err(FaultError::Directory)?;
        self.written.set(true);
        if matches!(self.fault, Fault::CancelAfterWrite | Fault::WriteAndCancel) {
            self.original
                .cancel()
                .expect("cancel at post-write original cut");
            if matches!(self.fault, Fault::CancelAfterWrite) {
                return Ok(outcome);
            }
        }
        Err(FaultError::Write)
    }

    fn visit_attempt_states(
        &self,
        visitor: &mut dyn FnMut(AttemptExecutionKey, AttemptRuntimeState),
    ) -> Result<(), Self::Error> {
        self.inner
            .visit_attempt_states(visitor)
            .map_err(FaultError::Directory)
    }

    fn visit_observation_roots(
        &self,
        visitor: &mut dyn FnMut(ObservationId),
    ) -> Result<(), Self::Error> {
        self.inner
            .visit_observation_roots(visitor)
            .map_err(FaultError::Directory)
    }

    fn visit_checkpoint_roots(
        &self,
        visitor: &mut dyn FnMut(ExactCheckpointId),
    ) -> Result<(), Self::Error> {
        self.inner
            .visit_checkpoint_roots(visitor)
            .map_err(FaultError::Directory)
    }
}

#[test]
fn actual_write_failures_preserve_first_cause_and_reopened_durable_outcome() {
    for fault in [
        Fault::BeforeWrite,
        Fault::AfterWrite,
        Fault::AfterWriteLostRead,
        Fault::CancelAfterWrite,
        Fault::WriteAndCancel,
    ] {
        let root = tempfile::tempdir().expect("ledger directory");
        let original = original_supervisor();
        let operation = original
            .begin(HostOperationClass::Transfer)
            .expect("original transfer");
        let ledger = FaultLedger {
            inner: directory(root.path()),
            fault,
            written: Cell::new(false),
            original: &original,
        };
        let mut supervisor = executor(ledger);
        let (_, key, paused) = fixture();
        let result = supervisor.prepare_source_transfer(key, paused, intent(), &operation);
        let error = result.as_ref().err().expect("refused preparation");
        if !matches!(fault, Fault::CancelAfterWrite) {
            assert!(matches!(
                std::error::Error::source(error)
                    .and_then(|source| source.downcast_ref::<FaultError>()),
                Some(FaultError::Write)
            ));
        }
        match (fault, result) {
            (
                Fault::BeforeWrite,
                Err(SourceTransferFailure::Persistence {
                    source: FaultError::Write,
                    observed,
                    original: None,
                }),
            ) => assert_eq!(observed, SourceTransferPersistenceOutcome::SourceUnchanged),
            (
                Fault::AfterWrite,
                Err(SourceTransferFailure::Persistence {
                    source: FaultError::Write,
                    observed,
                    original: None,
                }),
            ) => assert_eq!(
                observed,
                SourceTransferPersistenceOutcome::RequestedFenceObserved
            ),
            (
                Fault::AfterWriteLostRead,
                Err(SourceTransferFailure::Uncertain {
                    source: FaultError::Write,
                    reconciliation: FaultError::Read,
                    original: None,
                }),
            ) => {}
            (
                Fault::CancelAfterWrite,
                Err(SourceTransferFailure::Original(HostSupervisionError::Terminal {
                    state: HostOperationState::Canceled,
                })),
            ) => {}
            (
                Fault::WriteAndCancel,
                Err(SourceTransferFailure::PersistenceOriginal {
                    source: FaultError::Write,
                    original:
                        HostSupervisionError::Terminal {
                            state: HostOperationState::Canceled,
                        },
                }),
            ) => {}
            _ => panic!("actual persistence cut must refuse without a preparation claim"),
        }
        drop(supervisor);
        let mut reopened = executor(
            DirectoryAssignmentLedger::open(root.path()).expect("reconcile after actual reopen"),
        );
        let state = reopened
            .ledger()
            .load_attempt(key)
            .expect("durable outcome")
            .expect("source record");
        if matches!(fault, Fault::BeforeWrite) {
            assert_eq!(state, paused);
        } else {
            assert_source_is_fenced(&mut reopened);
        }
    }
}
