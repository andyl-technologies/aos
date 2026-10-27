//! Scoped completion transitions preserve exact predecessor identity.

use std::fmt::Debug;

use super::*;

#[test]
fn memory_completion_requires_the_exact_staged_predecessor() {
    exercise_completion_transitions(MemoryAssignmentLedger::default(), |result, current| {
        assert_eq!(result, Ok(AttemptStateCas::Conflict { current }))
    });
}

#[test]
fn directory_completion_requires_the_exact_staged_predecessor() {
    let directory = tempfile::tempdir().expect("ledger directory");
    exercise_completion_transitions(
        DirectoryAssignmentLedger::open(directory.path()).expect("durable ledger"),
        |result, _| {
            assert!(matches!(
                result,
                Err(AssignmentLedgerError::Corrupt {
                    reason: "scoped-promotion-completion-transition"
                        | "attempt-state-does-not-match-execution-scope"
                })
            ));
        },
    );
}

fn exercise_completion_transitions<L>(
    mut ledger: L,
    refuse: impl Fn(
        Result<AttemptStateCas, <L as AssignmentLedger>::Error>,
        Option<AttemptRuntimeState>,
    ),
) where
    L: AssignmentLedger + AssignmentRetentionAdmin<Error = <L as AssignmentLedger>::Error>,
    <L as AssignmentLedger>::Error: Debug,
{
    let request =
        savepoint_capture_request(0x74, 0x75, 1, campaign_fact(0x76), configuration(0x77));
    let key = AttemptExecutionKey::for_request(&request);
    let execution_basis = request.execution_basis_digest();
    let origin = AttemptExecutionOrigin::Initial;
    let daemon_epoch = request.daemon_epoch();
    let execution = execution(0x78);
    let source = checkpoint(0x79);
    let promoted = checkpoint(0x7a);
    let basis = CheckpointPromotionExecutionBasis::new_for_start_mode(
        request.resources(),
        request.retention(),
        request.start_mode(),
        request.retention_policy(),
    );
    let raw = AttemptRuntimeState::Paused {
        execution_basis,
        origin,
        daemon_epoch,
        execution,
        checkpoint: source,
        promotion_basis: Some(basis),
    };
    let staged = AttemptRuntimeState::CheckpointPromoting {
        execution_basis,
        origin,
        daemon_epoch,
        execution,
        source_checkpoint: source,
        promoted_checkpoint: promoted,
        promotion_basis: Some(basis),
    };
    let completed = AttemptRuntimeState::Paused {
        execution_basis,
        origin,
        daemon_epoch,
        execution,
        checkpoint: promoted,
        promotion_basis: None,
    };

    let initial_generation = generation(&mut ledger);
    refuse(
        ledger.compare_exchange_attempt(key, None, Some(completed)),
        None,
    );
    assert_eq!(
        ledger.load_attempt(key).expect("direct creation refused"),
        None
    );
    assert_eq!(generation(&mut ledger), initial_generation);
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(raw))
            .expect("raw pause"),
        AttemptStateCas::Advanced
    );
    let raw_generation = generation(&mut ledger);
    refuse(
        ledger.compare_exchange_attempt(key, Some(raw), Some(completed)),
        Some(raw),
    );
    assert_eq!(
        ledger.load_attempt(key).expect("raw pause preserved"),
        Some(raw)
    );
    assert_eq!(generation(&mut ledger), raw_generation);
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, Some(raw), Some(staged))
            .expect("stage promotion"),
        AttemptStateCas::Advanced
    );
    let staged_generation = generation(&mut ledger);

    // These are actual CAS attempts, not assertions about the private predicate.
    for field in ["checkpoint", "execution", "epoch", "digest", "origin"] {
        let mut changed = completed;
        let AttemptRuntimeState::Paused {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            checkpoint,
            ..
        } = &mut changed
        else {
            panic!("completed fixture is not paused");
        };
        match field {
            "checkpoint" => *checkpoint = source,
            "execution" => *execution = super::execution(0x7b),
            "epoch" => *daemon_epoch = DaemonEpoch::from_bytes([0x7c; 16]).expect("other epoch"),
            "digest" => {
                *execution_basis = CampaignHash::derive("crucible.test.changed-basis", b"changed")
            }
            "origin" => {
                *origin = AttemptExecutionOrigin::ExactCheckpoint {
                    assignment: request.assignment(),
                    request_digest: request.execution_basis_digest(),
                    prior_execution: super::execution(0x7b),
                    checkpoint: source,
                }
            }
            _ => panic!("unknown identity mutation"),
        }
        refuse(
            ledger.compare_exchange_attempt(key, Some(staged), Some(changed)),
            Some(staged),
        );
        assert_eq!(
            ledger.load_attempt(key).expect("staged identity preserved"),
            Some(staged),
            "{field}"
        );
        assert_eq!(generation(&mut ledger), staged_generation, "{field}");
    }

    for replacement in [
        None,
        Some(CheckpointPromotionExecutionBasis::new(
            request.resources(),
            request.retention(),
            request.retention_policy(),
        )),
    ] {
        let mut changed = staged;
        let AttemptRuntimeState::CheckpointPromoting {
            promotion_basis, ..
        } = &mut changed
        else {
            panic!("staged fixture has wrong phase");
        };
        *promotion_basis = replacement;
        refuse(
            ledger.compare_exchange_attempt(key, Some(staged), Some(changed)),
            Some(staged),
        );
        assert_eq!(
            ledger.load_attempt(key).expect("staged scope preserved"),
            Some(staged)
        );
        assert_eq!(generation(&mut ledger), staged_generation);
    }

    for changed in [
        AttemptRuntimeState::Running {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        AttemptRuntimeState::Publishing {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            observation: observation(0x7d),
            finding_candidate: None,
        },
        AttemptRuntimeState::Completed {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            observation: observation(0x7d),
            finding_candidate: CompletedFindingCandidate::None,
        },
    ] {
        refuse(
            ledger.compare_exchange_attempt(key, Some(staged), Some(changed)),
            Some(staged),
        );
        assert_eq!(
            ledger
                .load_attempt(key)
                .expect("capture remains in checkpoint phase"),
            Some(staged)
        );
        assert_eq!(generation(&mut ledger), staged_generation);
    }

    assert_eq!(
        ledger
            .compare_exchange_attempt(key, Some(staged), Some(completed))
            .expect("complete exact staged root"),
        AttemptStateCas::Advanced
    );
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, Some(completed), Some(completed))
            .expect("idempotent completed rewrite"),
        AttemptStateCas::Advanced
    );
    assert_eq!(
        ledger.load_attempt(key).expect("completed root retained"),
        Some(completed)
    );
}

fn generation<L>(ledger: &mut L) -> AssignmentRetentionGeneration
where
    L: AssignmentLedger + AssignmentRetentionAdmin<Error = <L as AssignmentLedger>::Error>,
    <L as AssignmentLedger>::Error: Debug,
{
    ledger
        .acquire_retention_fence()
        .expect("retention owner")
        .visit_roots(&mut |_| Ok(()))
        .expect("coherent root inventory")
        .generation()
}
