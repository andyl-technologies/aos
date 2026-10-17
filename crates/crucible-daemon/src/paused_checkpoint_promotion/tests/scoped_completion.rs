//! Durable completion of authenticated savepoint-capture promotion.

use crucible_campaign::{
    AssignmentId, CampaignFactId, ConfigurationArtifactId, SubmitAttemptRequest,
};

use super::*;
use crate::{AssignmentLedgerError, DirectoryAssignmentLedger};

#[test]
fn authenticated_scoped_promotion_completes_and_stays_complete_after_restart() {
    let repository = tempfile::tempdir().expect("checkpoint repository");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "scoped-promotion-test",
        repository.path(),
    ));
    let checkpoints =
        ExactCheckpointStore::new(backend, 64 * 1024 * 1024).expect("checkpoint store");
    let mut fixture = prepare_repository_promotion_fixture(&checkpoints);
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x71; 16]).expect("assignment"),
        fixture.daemon_epoch,
        fixture.key.lineage(),
        fixture.key.attempt(),
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|request| {
        SubmitAttemptRequest::new_savepoint_capture(
            request,
            CampaignFactId::parse(&format!(
                "crucible.campaign.fact@campaign-fact.15.{}",
                "72".repeat(32)
            ))
            .expect("capture request"),
            ConfigurationArtifactId::parse(&format!(
                "crucible.campaign.configuration-artifact@configuration.1.{}",
                "73".repeat(32)
            ))
            .expect("configuration"),
        )
    })
    .expect("scoped request");
    let key = AttemptExecutionKey::for_request(&request);
    fixture.prepared.key = key;
    let execution = fixture.state.execution();
    let source = fixture.prepared.source();
    let promoted = fixture.prepared.promoted();
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: fixture.daemon_epoch,
        execution,
        checkpoint: source,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
            request.resources(),
            request.retention(),
            request.start_mode(),
            request.retention_policy(),
        )),
    };
    let directory = tempfile::tempdir().expect("durable ledger");
    let mut ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger owner");
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("seed raw scoped pause"),
        AttemptStateCas::Advanced
    );
    let mut supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        fixture.daemon_epoch,
        fixture.capacity,
    );

    let PausedCheckpointPromotionStageOutcome::Publish(staged) =
        stage_prepared_paused_checkpoint_promotion(&mut supervisor, fixture.prepared)
            .expect("stage authenticated promotion")
    else {
        panic!("promotion did not stage");
    };
    let published = publish_staged_paused_checkpoint_promotion(&checkpoints, *staged)
        .expect("publish authenticated promoted root");
    let outcome = match reconcile_published_paused_checkpoint_promotion(
        &checkpoints,
        &mut supervisor,
        published,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            assert!(matches!(
                error.source,
                LocalExecutorError::Ledger(AssignmentLedgerError::Corrupt {
                    reason: "attempt-state-does-not-match-execution-scope"
                })
            ));
            assert_eq!(error.published.source(), source);
            assert_eq!(error.published.promoted(), promoted);
            let mut work = Vec::new();
            supervisor
                .visit_checkpoint_promotion_restart_work(&mut |item| work.push(item))
                .expect("staged durable work after refusal");
            assert_eq!(work.len(), 1);
            assert!(matches!(work[0], CheckpointPromotionRestartWork::Staged(_)));
            panic!(
                "authenticated final promotion CAS refused the completed scoped pause: {}",
                error.source
            );
        }
    };
    assert_eq!(outcome, CheckpointPromotionCompletionOutcome::Promoted);

    let ledger = supervisor.into_ledger();
    let completed = ledger
        .load_attempt(key)
        .expect("completed scoped state")
        .expect("retained pause");
    assert!(
        matches!(completed, AttemptRuntimeState::Paused { checkpoint, promotion_basis: None, .. } if checkpoint == promoted)
    );
    drop(ledger);
    let reopened =
        DirectoryAssignmentLedger::open(directory.path()).expect("reopen completed ledger");
    assert_eq!(
        reopened
            .load_attempt(key)
            .expect("read completed pause after restart"),
        Some(completed)
    );
    let restarted = LocalExecutorSupervisor::new(
        reopened,
        AllowAllAttemptAdmission,
        fixture.daemon_epoch,
        fixture.capacity,
    );
    let mut work = Vec::new();
    restarted
        .visit_checkpoint_promotion_restart_work(&mut |item| work.push(item))
        .expect("restart inventory");
    assert!(work.is_empty(), "completed comparison must not run again");
    assert!(
        restarted
            .replay_promotion_execution_is_inactive(key, execution)
            .expect("completed promotion is inactive")
    );
    crate::exact_checkpoint_restore::install_attempt_production_resume_checkpoint(
        &checkpoints,
        promoted,
        &fixture.source,
        &fixture.initial,
        None,
        &ExecutionCancellation::default(),
    )
    .expect("completed root still authenticates for resume");
}
