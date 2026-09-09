//! Fixed-pool checkpoint promotion and handoff regressions.

use super::*;

#[test]
fn fixed_promotion_worker_promotes_raw_restart_work_without_semantic_execution() {
    let checkpoints = checkpoint_store();
    let raw = checkpoints
        .prepare(
            &checkpoint_snapshot("promotion-worker-restart"),
            BlobHandle::from_bytes(vec![0x41; 512]),
        )
        .and_then(|prepared| checkpoints.publish(&prepared))
        .expect("publish raw restart checkpoint")
        .root();
    let source = checkpoints.load(raw).expect("load raw restart checkpoint");
    let runtime_hash = source.snapshot().checkpoint().configuration;
    let expected = checkpoints
        .prepare_replay_oracle_promotion(
            raw,
            QemuReplayOracleCheck::from_unvalidated_test_result(
                source.snapshot().id(),
                QemuReplayOracleValidation::Match { runtime_hash },
            ),
        )
        .expect("prepare expected promotion")
        .promoted();

    let epoch = DaemonEpoch::from_bytes([0xb1; 16]).expect("daemon epoch");
    let request = request(epoch, 0xb2);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xb3; 16]).expect("execution");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint: raw,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            request.resources(),
            request.retention(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(paused))
            .expect("seed paused restart"),
        AttemptStateCas::Advanced
    );
    let supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, epoch, capacity());
    let executor = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("promotion executor capability");
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_promotions(
        executor,
        store(),
        Arc::clone(&checkpoints),
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
        vec![ExactStorePromotionWorker {
            checkpoints,
            calls: Arc::clone(&calls),
        }],
    )
    .expect("start promotion-enabled pool");
    let service = pool.service();

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let report = service.report().expect("promotion report");
        if report.promotions_reconciled() == 1 {
            assert_eq!(report.promotion_workers(), 1);
            assert_eq!(report.promotions_active(), 0);
            assert_eq!(report.promotions_queued(), 0);
            assert_eq!(report.executions(), 0);
            break;
        }
        assert!(Instant::now() < deadline, "promotion worker timed out");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(calls.load(Ordering::Acquire), 1);
    let executor = service
        .shared
        .executor
        .lock()
        .expect("promotion supervisor");
    assert_eq!(
        executor
            .supervisor()
            .ledger()
            .load_attempt(key)
            .expect("load promoted attempt"),
        Some(AttemptRuntimeState::Paused {
            execution_basis: request.execution_basis_digest(),
            origin: crate::AttemptExecutionOrigin::Initial,
            daemon_epoch: epoch,
            execution,
            checkpoint: expected,
            promotion_basis: None,
        })
    );
    drop(executor);
    pool.shutdown_and_join().expect("promotion pool shutdown");
}

#[test]
fn shutdown_cancels_in_flight_promotion_and_retains_raw_restart_root() {
    let checkpoints = checkpoint_store();
    let raw = checkpoints
        .prepare(
            &checkpoint_snapshot("promotion-worker-cancel"),
            BlobHandle::from_bytes(vec![0x61; 512]),
        )
        .and_then(|prepared| checkpoints.publish(&prepared))
        .expect("publish cancelable promotion source")
        .root();
    let epoch = DaemonEpoch::from_bytes([0xd1; 16]).expect("daemon epoch");
    let request = request(epoch, 0xd2);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xd3; 16]).expect("execution");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint: raw,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            request.resources(),
            request.retention(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    ledger
        .compare_exchange_attempt(key, None, Some(paused))
        .expect("seed cancelable promotion");
    let supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, epoch, capacity());
    let executor = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("cancelable promotion executor");
    let entered = Arc::new(AtomicUsize::new(0));
    let canceled = Arc::new(AtomicUsize::new(0));
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_promotions(
        executor,
        store(),
        checkpoints,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
        vec![BlockingCheckpointPromotionWorker {
            entered: Arc::clone(&entered),
            canceled: Arc::clone(&canceled),
        }],
    )
    .expect("start cancelable promotion pool");
    let service = pool.service();
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });

    pool.request_shutdown();
    let report = pool.shutdown_and_join().expect("join canceled promotion");
    assert_eq!(canceled.load(Ordering::Acquire), 1);
    assert_eq!(report.promotions_active(), 0);
    assert_eq!(report.promotions_reconciled(), 0);
    let executor = service
        .shared
        .executor
        .lock()
        .expect("canceled promotion supervisor");
    assert_eq!(
        executor
            .supervisor()
            .ledger()
            .load_attempt(key)
            .expect("load retained raw pause"),
        Some(paused)
    );
}

#[test]
fn incomplete_staged_restart_reverts_and_regenerates_without_attempt_execution() {
    let checkpoints = checkpoint_store();
    let raw = checkpoints
        .prepare(
            &checkpoint_snapshot("promotion-worker-incomplete"),
            BlobHandle::from_bytes(vec![0x51; 512]),
        )
        .and_then(|prepared| checkpoints.publish(&prepared))
        .expect("publish incomplete-promotion source")
        .root();
    let source = checkpoints
        .load(raw)
        .expect("load incomplete-promotion source");
    let runtime_hash = source.snapshot().checkpoint().configuration;
    let promotion = checkpoints
        .prepare_replay_oracle_promotion(
            raw,
            QemuReplayOracleCheck::from_unvalidated_test_result(
                source.snapshot().id(),
                QemuReplayOracleValidation::Match { runtime_hash },
            ),
        )
        .expect("prepare incomplete replacement");
    let expected = promotion.promoted();

    let epoch = DaemonEpoch::from_bytes([0xc1; 16]).expect("daemon epoch");
    let request = request(epoch, 0xc2);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution = ExecutionId::from_bytes([0xc3; 16]).expect("execution");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint: raw,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            request.resources(),
            request.retention(),
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    ledger
        .compare_exchange_attempt(key, None, Some(paused))
        .expect("seed incomplete promotion");
    let mut supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, epoch, capacity());
    let staged = match stage_prepared_paused_checkpoint_promotion(
        &mut supervisor,
        PreparedPausedCheckpointPromotion::new(key, execution, promotion),
    )
    .expect("stage incomplete replacement")
    {
        PausedCheckpointPromotionStageOutcome::Publish(staged) => staged,
        other => panic!("expected staged incomplete replacement, got {other:?}"),
    };
    drop(staged);

    let executor = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("incomplete promotion executor");
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = LocalExecutorWorkerPool::start_with_checkpoint_promotions(
        executor,
        store(),
        Arc::clone(&checkpoints),
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
        vec![ExactStorePromotionWorker {
            checkpoints,
            calls: Arc::clone(&calls),
        }],
    )
    .expect("restart incomplete promotion pool");
    let service = pool.service();
    wait_until(Duration::from_secs(2), || {
        service
            .report()
            .is_ok_and(|report| report.promotions_reconciled() == 1)
    });

    assert_eq!(calls.load(Ordering::Acquire), 2);
    let report = service.report().expect("regenerated promotion report");
    assert_eq!(report.promotions_discarded(), 1);
    assert_eq!(report.promotions_reconciled(), 1);
    assert_eq!(report.executions(), 0);
    let executor = service
        .shared
        .executor
        .lock()
        .expect("regenerated promotion supervisor");
    assert!(matches!(
        executor
            .supervisor()
            .ledger()
            .load_attempt(key)
            .expect("load regenerated promotion"),
        Some(AttemptRuntimeState::Paused { checkpoint, .. }) if checkpoint == expected
    ));
    drop(executor);
    pool.shutdown_and_join()
        .expect("regenerated promotion shutdown");
}

#[test]
fn pool_stages_the_exact_root_before_the_modeled_worker_returns() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "checkpoint-handoff",
            64 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let (lineage, _policy, _branch, admitted, _candidate) =
        campaign_attempt_fixture(&repository, "checkpoint-handoff");
    let epoch = DaemonEpoch::from_bytes([0xa1; 16]).expect("daemon epoch");
    let assignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xa2; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage id"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("submit request");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity(),
    );
    let capability = LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("capability service");
    let state = Arc::new((Mutex::new(StagedCheckpointState::default()), Condvar::new()));
    let pool = LocalExecutorWorkerPool::start(
        capability,
        CampaignExecutorStore::new(Arc::clone(&repository)),
        checkpoint_store(),
        vec![RepositoryAttemptWorker::new(
            CampaignExecutorStore::new(repository),
            StagingCheckpointModel {
                state: Arc::clone(&state),
            },
        )],
    )
    .expect("checkpoint handoff pool");
    let mut service = pool.service();
    let accepted = service
        .submit_attempt(&assignment)
        .expect("accept checkpointable execution");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("checkpointable execution should be accepted")
    };
    let checkpoint_request =
        CheckpointAttemptExecutionRequest::new(&assignment, execution).expect("checkpoint request");
    assert!(matches!(
        service
            .checkpoint_attempt_execution(&checkpoint_request)
            .expect("request checkpoint")
            .disposition(),
        crucible_campaign::CheckpointAttemptExecutionDisposition::Requested
            | crucible_campaign::CheckpointAttemptExecutionDisposition::AlreadyRequested
    ));

    let (stage_state, changed) = state.as_ref();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut stage_state = stage_state.lock().expect("checkpoint stage state");
    while !stage_state.staged {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "checkpoint handoff timed out");
        let (next, timeout) = changed
            .wait_timeout(stage_state, remaining)
            .expect("checkpoint stage wake");
        stage_state = next;
        assert!(
            !timeout.timed_out() || stage_state.staged,
            "checkpoint handoff timed out"
        );
    }
    let status_request =
        GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
    let status = service
        .get_attempt_execution(&status_request)
        .expect("publishing status");
    let GetAttemptExecutionDisposition::CheckpointPublishing { checkpoint } = status.disposition()
    else {
        panic!("exact root must be staged before the worker returns")
    };
    let publishing_report = service.report().expect("publishing pool report");
    assert_eq!(publishing_report.active(), 1);
    assert_eq!(publishing_report.checkpoints_paused(), 0);
    stage_state.release = true;
    changed.notify_all();
    drop(stage_state);

    wait_until(Duration::from_secs(2), || {
        service
            .get_attempt_execution(&status_request)
            .is_ok_and(|response| {
                response.disposition() == GetAttemptExecutionDisposition::Paused { checkpoint }
            })
    });
    assert_eq!(
        pool.service
            .shared
            .checkpoints
            .load(checkpoint)
            .expect("published checkpoint")
            .vmstate_bytes(),
        512
    );
    let report = service.report().expect("checkpoint pool report");
    assert_eq!(report.checkpoints_paused(), 1);
    assert_eq!(report.active(), 0);
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
}
