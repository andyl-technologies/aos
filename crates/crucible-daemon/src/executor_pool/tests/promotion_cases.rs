//! Promotion worker refusal, stale claims, publication, and reclamation.

use super::*;

#[test]
fn promotion_report_records_terminal_preparation_from_real_process_path() {
    let checkpoints = checkpoint_store(standalone_ram_retention());
    let (shared, mut work, prepared, _) = promotion_process_fixture(Arc::clone(&checkpoints));
    let mut worker = TerminalPromotionWorker;

    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );
    drop(prepared);

    let executor = shared.executor.lock().expect("executor report lock");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotion_failures(), 1);
    assert_eq!(report.promotion_failure_phases().preparation_terminal(), 1);
    assert_eq!(
        report
            .promotion_failure_phases()
            .publication_terminal_reverted(),
        0
    );
    let failure = report
        .last_promotion_failure()
        .expect("terminal preparation retains its typed failure");
    assert_eq!(failure.phase(), LocalExecutorPromotionPhase::Preparation);
    assert_eq!(failure.detail(), "\"terminal preparation\"");
    assert!(!failure.detail_truncated());
    assert_eq!(
        report.last_promotion_activity().map(|(_, phase)| phase),
        Some(LocalExecutorPromotionPhase::Preparation)
    );
}

#[test]
fn stale_raw_promotion_is_discarded_before_worker_preparation() {
    let checkpoints = checkpoint_store(standalone_ram_retention());
    let fixture = crate::prepare_repository_promotion_fixture(&checkpoints);
    let crate::RepositoryPromotionFixture {
        prepared,
        key,
        state,
        daemon_epoch,
        capacity,
        ..
    } = fixture;
    // Keep the original 64 MiB modeled request while reserving the separately
    // authored one MiB watcher and 128-byte backing envelope inside its
    // physical launch peak; the modeled disk request remains zero.
    let capacity = ExecutorCapacity::new(
        capacity.maximum_concurrent_executions(),
        capacity.maximum_vcpus(),
        65 * 1024 * 1024,
        128,
        capacity.maximum_execution_quanta(),
    )
    .expect("promotion physical peak includes its watcher");
    let mut recovery_ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        recovery_ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("seed raw promotion recovery"),
        AttemptStateCas::Advanced
    );
    let recovery_supervisor = LocalExecutorSupervisor::new(
        recovery_ledger,
        AllowAllAttemptAdmission,
        daemon_epoch,
        capacity,
    );
    let recovery = recovery_supervisor
        .paused_checkpoint_promotion_recovery(key)
        .expect("load raw promotion recovery")
        .expect("raw promotion recovery");

    let stale_state = AttemptRuntimeState::Canceled {
        execution_basis: state.execution_basis(),
        origin: state.origin(),
        daemon_epoch: state.daemon_epoch(),
        execution: state.execution(),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(stale_state))
            .expect("seed superseding terminal state"),
        AttemptStateCas::Advanced
    );
    let supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, daemon_epoch, capacity);
    let resources = AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000)
        .expect("promotion fixture resource ceiling");
    let executor = crate::executor_capability::test_support::capability_service(
        supervisor,
        description_with_limits(
            daemon_epoch,
            1,
            crucible_campaign::ExecutorResourceBounds::new(
                crucible_campaign::ExecutorHostResources {
                    resident_peak_bytes: 68157440,
                    backing_peak_bytes: 128,
                    metadata_bytes: 128,
                    staging_bytes: 128,
                    paging_io_slots: 1,
                    cpu_slots: 1,
                    task_slots: 65,
                    file_descriptors: 128,
                },
                crucible_campaign::ExecutorHostResources {
                    resident_peak_bytes: 68157440,
                    backing_peak_bytes: 128,
                    metadata_bytes: 128,
                    staging_bytes: 128,
                    paging_io_slots: 1,
                    cpu_slots: 1,
                    task_slots: 65,
                    file_descriptors: 128,
                },
                resources,
            )
            .expect("authored complete fixture resource bounds"),
        ),
        1024 * 1024,
    )
    .expect("promotion fixture capability");
    let shared = SharedExecutor::new(executor, checkpoints, 1, 1, Vec::new(), None, None);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut worker = CountingTerminalPromotionWorker {
        calls: Arc::clone(&calls),
    };
    let mut work = CheckpointPromotionRestartWork::Paused(recovery);

    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );
    drop(prepared);

    assert_eq!(calls.load(Ordering::Acquire), 0);
    let executor = shared.executor.lock().expect("executor report lock");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotions_discarded(), 1);
    assert_eq!(report.promotion_failures(), 0);
    assert_eq!(report.promotion_failure_phases().preparation_terminal(), 0);
    assert!(report.last_promotion_failure().is_none());
    assert_eq!(
        report.last_promotion_activity().map(|(_, phase)| phase),
        Some(LocalExecutorPromotionPhase::Preflight)
    );
}

#[test]
fn promotion_report_records_terminal_publication_and_raw_reversion() {
    let backend = Arc::new(RejectingPromotionBackend::new());
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(
            backend.clone(),
            64 * 1024 * 1024,
            standalone_ram_retention(),
        )
        .expect("promotion checkpoint store")
        .with_ram_root_resources(
            crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
                .expect("finite component RAM-root credit"),
        ),
    );
    let (shared, mut work, prepared, raw) = promotion_process_fixture(Arc::clone(&checkpoints));
    backend.reject_publication();
    let mut worker = PreparedPromotionWorker {
        prepared: Some(prepared),
    };

    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );

    let executor = shared.executor.lock().expect("executor report lock");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotion_failures(), 1);
    assert_eq!(report.promotions_discarded(), 1);
    assert_eq!(report.promotion_failure_phases().preparation_terminal(), 0);
    assert_eq!(
        report
            .promotion_failure_phases()
            .publication_terminal_reverted(),
        1
    );
    let key = match work {
        CheckpointPromotionRestartWork::Paused(recovery) => recovery.key(),
        CheckpointPromotionRestartWork::Staged(_) => panic!("fixture began as a raw pause"),
    };
    let failure = report
        .last_promotion_failure()
        .expect("terminal publication retains its typed failure");
    assert_eq!(failure.key(), key);
    assert_eq!(failure.phase(), LocalExecutorPromotionPhase::Publication);
    assert!(!failure.detail().is_empty());
    assert_eq!(
        report.last_promotion_activity(),
        Some((key, LocalExecutorPromotionPhase::Publication))
    );
    assert_eq!(
        executor
            .supervisor()
            .paused_checkpoint_promotion_recovery(key)
            .expect("load reverted promotion")
            .expect("raw promotion remains eligible")
            .source(),
        raw
    );
}

#[test]
fn completed_promotion_worker_reclaims_its_live_claim() {
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(
            Arc::new(TestDurableBackend::new()),
            64 * 1024 * 1024,
            standalone_ram_retention(),
        )
        .expect("promotion checkpoint store")
        .with_ram_root_resources(
            crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
                .expect("finite component RAM-root credit"),
        ),
    );
    let (shared, mut work, prepared, _) = promotion_process_fixture(checkpoints);
    assert_eq!(
        promotion::reclaim_inactive_promotion_claims(&shared, &work),
        None,
        "a raw paused execution can still stage its promotion"
    );

    let mut worker = PreparedPromotionWorker {
        prepared: Some(prepared),
    };
    promotion::process_promotion_work(
        &shared,
        &mut worker,
        &mut work,
        ExecutionCancellation::default(),
    );
    let executor = shared.executor.lock().expect("completed promotion ledger");
    let report = shared.report(executor.supervisor());
    assert_eq!(report.promotions_reconciled(), 1);
    drop(executor);

    assert_eq!(
        promotion::reclaim_inactive_promotion_claims(&shared, &work),
        Some(1),
        "completed promotion releases its process-local claim"
    );
    assert_eq!(
        promotion::reclaim_inactive_promotion_claims(&shared, &work),
        Some(0),
        "reclamation is idempotent"
    );
}
