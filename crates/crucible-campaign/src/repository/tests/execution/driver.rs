//! Executor driver lifecycle and response validation tests.

use super::*;

#[test]
fn claimable_attempt_pages_are_bounded_snapshot_bound_and_restart_rebuildable() {
    fn collect(
        repository: &CampaignRepository,
        name: &str,
        scan_limit: usize,
    ) -> (CampaignSnapshotId, Vec<AttemptId>) {
        let mut cursor = None;
        let mut snapshot = None;
        let mut attempts = Vec::new();
        loop {
            let page = repository
                .project_claimable_attempts(name, cursor, scan_limit)
                .expect("project claimable attempts");
            assert!(page.scanned_entries() <= scan_limit);
            if let Some(expected) = snapshot {
                assert_eq!(page.snapshot(), expected);
            } else {
                snapshot = Some(page.snapshot());
            }
            attempts.extend_from_slice(page.attempts());
            cursor = page.next();
            if cursor.is_none() {
                break;
            }
        }
        (snapshot.expect("at least one page"), attempts)
    }

    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "claimable-attempts");

    assert_eq!(
        DaemonEpoch::from_bytes([0; 16]),
        Err(CampaignCodecError::InvalidValue {
            reason: "daemon epoch is all zero"
        })
    );
    let first_epoch = DaemonEpoch::from_bytes([1; 16]).expect("first daemon epoch");
    assert!(matches!(
        AttemptQueue::new(first_epoch, 0),
        Err(AttemptQueueError::ZeroCapacity)
    ));
    let claimable_page = repository
        .project_claimable_attempts("claimable-attempts", None, 10_000)
        .expect("claimable page before completion");
    let mut queue = AttemptQueue::new(first_epoch, 1).expect("bounded attempt queue");
    let first_slot = WorkerSlotId::new(0);
    let first_reservation = queue
        .reserve_from_page(&claimable_page, first_slot)
        .expect("reserve first attempt")
        .expect("claimable attempt");
    assert_eq!(first_reservation.attempt(), admitted.attempt);
    assert_eq!(first_reservation.daemon_epoch(), first_epoch);
    assert_eq!(first_reservation.worker_slot(), first_slot);
    assert_eq!(first_reservation.generation(), 1);
    assert_eq!(
        queue
            .reserve_from_page(&claimable_page, first_slot)
            .expect("repeat exact slot reservation"),
        Some(first_reservation)
    );
    assert_eq!(queue.reservation_count(), 1);

    queue
        .release(first_reservation)
        .expect("release exact reservation");
    let second_reservation = queue
        .reserve_from_page(&claimable_page, WorkerSlotId::new(1))
        .expect("reserve after release")
        .expect("claimable attempt after release");
    assert_eq!(second_reservation.generation(), 2);

    let second_epoch = DaemonEpoch::from_bytes([2; 16]).expect("second daemon epoch");
    let mut restarted_queue = AttemptQueue::new(second_epoch, 1).expect("restarted attempt queue");
    assert_eq!(
        restarted_queue.release(second_reservation),
        Err(AttemptQueueError::ReservationMismatch)
    );
    let restarted_reservation = restarted_queue
        .reserve_from_page(&claimable_page, WorkerSlotId::new(0))
        .expect("reserve in new daemon epoch")
        .expect("claimable attempt in new daemon epoch");
    assert_eq!(restarted_reservation.daemon_epoch(), second_epoch);
    assert_eq!(restarted_reservation.generation(), 1);

    let (small_snapshot, small) = collect(&repository, "claimable-attempts", 1);
    let (large_snapshot, large) = collect(&repository, "claimable-attempts", 10_000);
    assert_eq!(small_snapshot, admitted.new_snapshot);
    assert_eq!(large_snapshot, admitted.new_snapshot);
    assert_eq!(small, vec![admitted.attempt]);
    assert_eq!(large, small);

    let stale_cursor = repository
        .project_claimable_attempts("claimable-attempts", None, 1)
        .expect("first bounded queue page")
        .next()
        .expect("accounting root spans multiple one-entry pages");
    let observed = repository
        .publish_observation("claimable-attempts", admitted.new_snapshot, &observation)
        .expect("publish canonical observation");
    assert!(matches!(
        repository.project_claimable_attempts(
            "claimable-attempts",
            Some(stale_cursor),
            1,
        ),
        Err(CampaignRepositoryError::Stale { expected, current })
            if expected == admitted.new_snapshot && current == observed.new_snapshot
    ));

    let (rebuilt_snapshot, rebuilt) = collect(&repository, "claimable-attempts", 3);
    assert_eq!(rebuilt_snapshot, observed.new_snapshot);
    assert!(rebuilt.is_empty());
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let (restart_snapshot, restart_claimable) = collect(&restarted, "claimable-attempts", 2);
    assert_eq!(restart_snapshot, observed.new_snapshot);
    assert_eq!(restart_claimable, rebuilt);
    let completed_page = restarted
        .project_claimable_attempts("claimable-attempts", None, 10_000)
        .expect("post-completion page");
    let third_epoch = DaemonEpoch::from_bytes([3; 16]).expect("third daemon epoch");
    let mut completed_queue = AttemptQueue::new(third_epoch, 1).expect("post-completion queue");
    assert_eq!(
        completed_queue
            .reserve_from_page(&completed_page, WorkerSlotId::new(0))
            .expect("post-completion reservation attempt"),
        None
    );
}

#[test]
fn campaign_executor_driver_incorporates_completion_and_rebuilds_after_restart() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "executor-driver-completion");
    let observation_id = observation.id().expect("observation id");
    assert_eq!(
        repository
            .put_observation(&observation)
            .expect("publish executor observation body"),
        observation_id.content_id()
    );
    let resume = command(
        "executor-driver-resume",
        admitted.new_snapshot,
        CampaignControlAction::Resume,
    );
    let running = repository
        .apply_control("executor-driver-completion", &resume)
        .expect("start campaign");
    let repository = Arc::new(repository);
    let resources =
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("executor limits");
    let service = CompletingExecutor {
        requests: Vec::new(),
        status_requests: Vec::new(),
        execution: ExecutionId::from_bytes([0x91; 16]).expect("execution"),
        observation: observation_id,
    };
    let mut driver = CampaignExecutorDriver::new(
        repository.clone(),
        ExecutorClient::new(service),
        DaemonEpoch::from_bytes([0x92; 16]).expect("daemon epoch"),
        1,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        10_000,
    )
    .expect("executor driver");

    assert!(matches!(
        driver
            .step("executor-driver-completion", WorkerSlotId::new(0))
            .expect("accept assignment"),
        CampaignExecutorStepOutcome::Running {
            attempt,
            newly_accepted: true,
            ..
        } if attempt == admitted.attempt
    ));
    assert_eq!(driver.reservation_count(), 1);
    let incorporated = driver
        .step("executor-driver-completion", WorkerSlotId::new(0))
        .expect("incorporate completion");
    let CampaignExecutorStepOutcome::Incorporated(incorporated) = incorporated else {
        panic!("expected incorporated completion");
    };
    assert_eq!(incorporated.prior_snapshot, running.new_snapshot);
    assert_eq!(incorporated.observation, observation_id);
    assert_eq!(driver.reservation_count(), 0);
    let service = driver.into_executor().into_inner();
    assert_eq!(service.requests.len(), 1);
    assert_eq!(service.status_requests.len(), 1);
    assert_eq!(
        service.status_requests[0].execution_basis(),
        service.requests[0].execution_basis_digest()
    );
    assert_eq!(service.status_requests[0].execution(), service.execution);

    let restarted_repository = Arc::new(CampaignRepository::new(
        repository.blobs.clone(),
        repository.refs.clone(),
    ));
    let mut restarted = CampaignExecutorDriver::new(
        restarted_repository,
        ExecutorClient::new(RejectingExecutor {
            reason: ExecutorRejection::Incompatible,
        }),
        DaemonEpoch::from_bytes([0x93; 16]).expect("restart epoch"),
        1,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        1,
    )
    .expect("restarted executor driver");
    loop {
        match restarted
            .step("executor-driver-completion", WorkerSlotId::new(0))
            .expect("restart projection")
        {
            CampaignExecutorStepOutcome::ScanPending { .. }
            | CampaignExecutorStepOutcome::CaptureScanPending { .. } => {}
            CampaignExecutorStepOutcome::Idle { snapshot } => {
                assert_eq!(snapshot, incorporated.new_snapshot);
                break;
            }
            outcome => panic!("unexpected restarted driver outcome: {outcome:?}"),
        }
    }
    assert_eq!(restarted.reservation_count(), 0);
}

#[test]
fn campaign_executor_driver_resumes_the_exact_paused_root() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, _) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-driver-exact-resume",
    );
    let resume = command(
        "executor-driver-exact-resume-start",
        admitted.new_snapshot,
        CampaignControlAction::Resume,
    );
    repository
        .apply_control("executor-driver-exact-resume", &resume)
        .expect("start campaign");
    let prior_execution = ExecutionId::from_bytes([0x94; 16]).expect("prior execution");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"executor-driver-resume-root",
    ))
    .expect("checkpoint");
    let resumed_execution = ExecutionId::from_bytes([0x95; 16]).expect("resumed execution");
    let repository = Arc::new(repository);
    let resources =
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("executor limits");
    let service = PausedResumeExecutor {
        prior_execution,
        checkpoint,
        resumed_execution,
        submit_requests: Vec::new(),
        resume_requests: Vec::new(),
    };
    let mut driver = CampaignExecutorDriver::new(
        repository,
        ExecutorClient::new(service),
        DaemonEpoch::from_bytes([0x96; 16]).expect("daemon epoch"),
        1,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        10_000,
    )
    .expect("executor driver");

    assert_eq!(
        driver
            .step("executor-driver-exact-resume", WorkerSlotId::new(0))
            .expect("resume paused assignment"),
        CampaignExecutorStepOutcome::Running {
            attempt: admitted.attempt,
            execution: resumed_execution,
            newly_accepted: true,
        }
    );
    let service = driver.into_executor().into_inner();
    assert_eq!(service.submit_requests.len(), 1);
    assert_eq!(service.resume_requests.len(), 1);
    let resumed = &service.resume_requests[0];
    assert_eq!(resumed.prior_execution(), prior_execution);
    assert_eq!(resumed.checkpoint(), checkpoint);
    assert_eq!(
        resumed.execution_basis_digest(),
        service.submit_requests[0].execution_basis_digest()
    );
    assert_ne!(
        resumed.assignment(),
        service.submit_requests[0].assignment()
    );
}

#[test]
fn campaign_executor_driver_closes_terminal_failure_without_reassignment() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, _) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-driver-terminal-failure",
    );
    repository
        .apply_control(
            "executor-driver-terminal-failure",
            &command(
                "executor-driver-terminal-failure-resume",
                admitted.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("start campaign");
    let repository = Arc::new(repository);
    let resources =
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("executor limits");
    let service = TerminalExecutor {
        requests: Vec::new(),
        status_requests: Vec::new(),
        execution: ExecutionId::from_bytes([0x93; 16]).expect("execution"),
    };
    let mut driver = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        ExecutorClient::new(service),
        DaemonEpoch::from_bytes([0x94; 16]).expect("daemon epoch"),
        1,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        10_000,
    )
    .expect("executor driver");

    assert!(matches!(
        driver
            .step("executor-driver-terminal-failure", WorkerSlotId::new(0))
            .expect("accept assignment"),
        CampaignExecutorStepOutcome::Running {
            attempt,
            newly_accepted: true,
            ..
        } if attempt == admitted.attempt
    ));
    let closed = driver
        .step("executor-driver-terminal-failure", WorkerSlotId::new(0))
        .expect("close terminal attempt");
    let CampaignExecutorStepOutcome::Closed(closed) = closed else {
        panic!("terminal failure should close the attempt");
    };
    assert_eq!(closed.attempt, admitted.attempt);
    assert_eq!(
        closed.disposition,
        NonModeledAttemptDisposition::TerminalWorkerFailure
    );
    assert_eq!(driver.reservation_count(), 0);

    loop {
        match driver
            .step("executor-driver-terminal-failure", WorkerSlotId::new(0))
            .expect("settle closed campaign")
        {
            CampaignExecutorStepOutcome::ScanPending { .. }
            | CampaignExecutorStepOutcome::CaptureScanPending { .. } => {}
            CampaignExecutorStepOutcome::Idle { snapshot } => {
                assert_eq!(snapshot, closed.new_snapshot);
                break;
            }
            outcome => panic!("closed attempt must not be assigned again: {outcome:?}"),
        }
    }

    let service = driver.into_executor().into_inner();
    assert_eq!(service.requests.len(), 1);
    assert_eq!(service.status_requests.len(), 1);
    assert_eq!(
        repository
            .head("executor-driver-terminal-failure")
            .expect("closed campaign head")
            .snapshot_id(),
        closed.new_snapshot
    );

    let mut restarted = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        ExecutorClient::new(TerminalExecutor {
            requests: Vec::new(),
            status_requests: Vec::new(),
            execution: ExecutionId::from_bytes([0x95; 16]).expect("restart execution"),
        }),
        DaemonEpoch::from_bytes([0x96; 16]).expect("restart epoch"),
        1,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        1,
    )
    .expect("restart executor driver");
    loop {
        match restarted
            .step("executor-driver-terminal-failure", WorkerSlotId::new(0))
            .expect("rebuild closed campaign")
        {
            CampaignExecutorStepOutcome::ScanPending { .. }
            | CampaignExecutorStepOutcome::CaptureScanPending { .. } => {}
            CampaignExecutorStepOutcome::Idle { snapshot } => {
                assert_eq!(snapshot, closed.new_snapshot);
                break;
            }
            outcome => panic!("restart must preserve terminal closure: {outcome:?}"),
        }
    }
    let restarted_service = restarted.into_executor().into_inner();
    assert!(restarted_service.requests.is_empty());
    assert!(restarted_service.status_requests.is_empty());
    let replay = repository
        .close_attempt_non_modeled(
            "executor-driver-terminal-failure",
            closed.new_snapshot,
            admitted.attempt,
            NonModeledAttemptDisposition::TerminalWorkerFailure,
        )
        .expect("restart preserves the exact terminal closure reason");
    assert!(replay.replayed);
    assert_eq!(replay.disposition, closed.disposition);
}

#[test]
fn campaign_executor_driver_cancels_exact_execution_and_releases_retryable_attempt() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, _) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-driver-cancellation",
    );
    let running = repository
        .apply_control(
            "executor-driver-cancellation",
            &command(
                "executor-driver-cancellation-resume",
                admitted.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume campaign");
    let repository = Arc::new(repository);
    let execution = ExecutionId::from_bytes([0x95; 16]).expect("execution");
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 0, 10_000).expect("resources");
    let mut driver = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        ExecutorClient::new(CancellableExecutor {
            execution,
            cancel_requests: Vec::new(),
        }),
        DaemonEpoch::from_bytes([0x96; 16]).expect("daemon epoch"),
        1,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("executor driver");
    assert!(matches!(
        driver
            .step("executor-driver-cancellation", WorkerSlotId::new(0))
            .expect("accept execution"),
        CampaignExecutorStepOutcome::Running {
            attempt,
            execution: accepted,
            newly_accepted: true,
        } if attempt == admitted.attempt && accepted == execution
    ));

    let paused = repository
        .apply_control(
            "executor-driver-cancellation",
            &command(
                "executor-driver-cancellation-pause",
                running.new_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::CancelAndRetry),
            ),
        )
        .expect("pause campaign");
    let (_, lifecycle) = repository
        .head_with_lifecycle("executor-driver-cancellation")
        .expect("paused lifecycle");
    assert_eq!(lifecycle.state(), CampaignState::Paused);
    assert_eq!(
        lifecycle.active_attempt_policy(),
        Some(crate::ActiveAttemptPolicy::CancelAndRetry)
    );

    assert_eq!(
        driver
            .cancel_one("executor-driver-cancellation")
            .expect("cancel exact execution"),
        CampaignExecutorCancelOutcome::Canceled {
            attempt: admitted.attempt,
            execution,
            already_canceled: false,
        }
    );
    assert_eq!(driver.reservation_count(), 0);
    let service = driver.into_executor().into_inner();
    assert_eq!(service.cancel_requests.len(), 1);
    assert_eq!(service.cancel_requests[0].execution(), execution);
    assert_eq!(service.cancel_requests[0].attempt(), admitted.attempt);
    assert_eq!(
        repository
            .project_claimable_attempts("executor-driver-cancellation", None, 10_000)
            .expect("canceled attempt remains claimable")
            .attempts(),
        &[admitted.attempt]
    );
    assert_eq!(
        repository
            .head("executor-driver-cancellation")
            .expect("unchanged paused head")
            .snapshot_id(),
        paused.new_snapshot
    );
}

#[test]
fn campaign_executor_driver_closes_stable_rejection_and_retries_transient_basis() {
    let (repository, lineage, policy) = fixture();
    let (genesis, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "executor-driver-rejection");
    let resume = command(
        "executor-driver-rejection-resume",
        admitted.new_snapshot,
        CampaignControlAction::Resume,
    );
    repository
        .apply_control("executor-driver-rejection", &resume)
        .expect("start campaign");
    let repository = Arc::new(repository);
    let resources =
        AttemptResourceLimits::new(1, 256 * 1024 * 1024, 0, 10_000).expect("executor limits");

    let mut deferred = CampaignExecutorDriver::new(
        repository.clone(),
        ExecutorClient::new(DeferringExecutor {
            requests: Vec::new(),
        }),
        DaemonEpoch::from_bytes([0xa1; 16]).expect("deferred epoch"),
        1,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("deferred driver");
    for _ in 0..2 {
        assert_eq!(
            deferred
                .step("executor-driver-rejection", WorkerSlotId::new(0))
                .expect("deferred assignment"),
            CampaignExecutorStepOutcome::RetryScheduled {
                attempt: admitted.attempt,
                reason: ExecutorRejection::Backpressure,
            }
        );
    }
    assert_eq!(deferred.reservation_count(), 0);
    let requests = deferred.into_executor().into_inner().requests;
    assert_eq!(requests.len(), 2);
    assert_ne!(requests[0].assignment(), requests[1].assignment());
    assert_eq!(
        requests[0].execution_basis_digest(),
        requests[1].execution_basis_digest()
    );

    let mut unauthorized = CampaignExecutorDriver::new(
        repository.clone(),
        ExecutorClient::new(RejectingExecutor {
            reason: ExecutorRejection::Unauthorized,
        }),
        DaemonEpoch::from_bytes([0xa3; 16]).expect("unauthorized epoch"),
        1,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("unauthorized driver");
    assert_eq!(
        unauthorized
            .step("executor-driver-rejection", WorkerSlotId::new(0))
            .expect("authorization stop"),
        CampaignExecutorStepOutcome::Blocked {
            attempt: admitted.attempt,
            reason: ExecutorRejection::Unauthorized,
        }
    );
    assert_eq!(unauthorized.reservation_count(), 1);
    assert!(
        repository
            .project_claimable_attempts("executor-driver-rejection", None, 10_000)
            .expect("authorization remains non-semantic")
            .attempts()
            .contains(&admitted.attempt)
    );
    drop(unauthorized);

    let mut rejected = CampaignExecutorDriver::new(
        repository.clone(),
        ExecutorClient::new(RejectingExecutor {
            reason: ExecutorRejection::Incompatible,
        }),
        DaemonEpoch::from_bytes([0xa2; 16]).expect("rejection epoch"),
        1,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("rejecting driver");
    let closed = rejected
        .step("executor-driver-rejection", WorkerSlotId::new(0))
        .expect("close incompatible attempt");
    let CampaignExecutorStepOutcome::Closed(closed) = closed else {
        panic!("expected non-modeled closure");
    };
    assert_eq!(closed.attempt, admitted.attempt);
    assert_eq!(closed.ordinal, AdmissionOrdinal::new(1));
    assert_eq!(
        closed.disposition,
        NonModeledAttemptDisposition::PermanentlyIncompatible
    );
    assert!(!closed.replayed);
    assert_eq!(rejected.reservation_count(), 0);

    let pause = command(
        "executor-driver-rejection-pause",
        closed.new_snapshot,
        CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
    );
    let paused = repository
        .apply_control("executor-driver-rejection", &pause)
        .expect("advance after attempt closure");

    let replay = repository
        .close_attempt_non_modeled(
            "executor-driver-rejection",
            genesis,
            admitted.attempt,
            NonModeledAttemptDisposition::PermanentlyIncompatible,
        )
        .expect("closure replay before stale check");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, closed.new_snapshot);
    assert!(matches!(
        repository.close_attempt_non_modeled(
            "executor-driver-rejection",
            paused.new_snapshot,
            admitted.attempt,
            NonModeledAttemptDisposition::Unauthorized,
        ),
        Err(CampaignRepositoryError::AlreadyExists)
    ));
    assert!(matches!(
        repository.publish_observation(
            "executor-driver-rejection",
            paused.new_snapshot,
            &observation,
        ),
        Err(CampaignRepositoryError::AlreadyExists)
    ));
    let page = repository
        .project_claimable_attempts("executor-driver-rejection", None, 10_000)
        .expect("post-closure projection");
    assert!(page.attempts().is_empty());

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("executor-driver-rejection")
            .expect("restart validates attempt closure")
            .snapshot_id(),
        paused.new_snapshot
    );
    assert!(
        restarted
            .project_claimable_attempts("executor-driver-rejection", None, 10_000)
            .expect("restart claim projection")
            .attempts()
            .is_empty()
    );
}

#[test]
fn executor_responses_authenticate_request_attempt_and_lineage() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-response-validation",
    );
    let observed = repository
        .publish_observation(
            "executor-response-validation",
            admitted.new_snapshot,
            &observation,
        )
        .expect("publish executor observation");
    let resources =
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("executor limits");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x81; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x82; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage id"),
        admitted.attempt,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("executor request");
    repository
        .validate_executor_request(&request)
        .expect("valid executor request");
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    repository
        .validate_executor_request_with_profile(&request, &profile)
        .expect("exact executor profile");
    let mismatched_profile = ExecutorCompatibilityProfile::new(
        lineage.crucible_version(),
        "different-qemu-build",
        lineage.protocol_versions().clone(),
        lineage.scenario_schema(),
        lineage.exact_closure_schema(),
    )
    .expect("mismatched executor profile");
    assert!(matches!(
        repository.validate_executor_request_with_profile(&request, &mismatched_profile),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-compatibility-profile-mismatch"
        })
    ));
    let completed = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observed.observation,
        },
    )
    .expect("completed response");
    repository
        .validate_executor_response(&request, &completed)
        .expect("valid completed response");

    let (_, other_admitted, other_observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-response-other-attempt",
    );
    let other_observed = repository
        .publish_observation(
            "executor-response-other-attempt",
            other_admitted.new_snapshot,
            &other_observation,
        )
        .expect("publish other observation");
    let wrong_attempt = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: other_observed.observation,
        },
    )
    .expect("wrong-attempt response");
    assert!(matches!(
        repository.validate_executor_response(&request, &wrong_attempt),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-completion-attempt-mismatch"
        })
    ));

    let wrong_scenario = lineage.scenario();
    let wrong_genesis =
        ConfigurationId::from_hash(CampaignHash::derive("test", b"wrong-executor-genesis"));
    let wrong_scenario_content = repository
        .publish_scenario_artifact(wrong_scenario, 1, b"different scenario content".to_vec())
        .expect("wrong scenario artifact");
    let wrong_genesis_content = repository
        .publish_configuration_artifact(
            wrong_scenario,
            wrong_scenario_content,
            wrong_genesis,
            1,
            b"wrong genesis".to_vec(),
        )
        .expect("wrong genesis artifact");
    let wrong_lineage = CampaignLineage::new(
        wrong_scenario,
        wrong_scenario_content,
        wrong_genesis,
        wrong_genesis_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("wrong lineage");
    repository
        .put_lineage(&wrong_lineage)
        .expect("publish wrong lineage");
    let wrong_lineage_request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x83; 16]).expect("wrong-lineage assignment"),
        request.daemon_epoch(),
        wrong_lineage.id().expect("wrong lineage id"),
        request.attempt(),
        resources,
        request.retention(),
    )
    .expect("wrong-lineage request");
    let wrong_lineage_response = SubmitAttemptResponse::new(
        &wrong_lineage_request,
        SubmitAttemptDisposition::Accepted {
            execution: ExecutionId::from_bytes([0x84; 16]).expect("execution"),
        },
    )
    .expect("wrong-lineage response");
    assert!(matches!(
        repository.validate_executor_request(&wrong_lineage_request),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-attempt-lineage-mismatch"
        })
    ));
    assert!(matches!(
        repository.validate_executor_response(&wrong_lineage_request, &wrong_lineage_response),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-attempt-lineage-mismatch"
        })
    ));
    let wrong_lineage_completed = SubmitAttemptResponse::new(
        &wrong_lineage_request,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observed.observation,
        },
    )
    .expect("wrong-lineage completed response");
    assert!(matches!(
        repository.validate_executor_response(&wrong_lineage_request, &wrong_lineage_completed),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-attempt-lineage-mismatch"
        })
    ));
}

#[test]
fn executor_validation_errors_preserve_retry_and_authorization_meaning() {
    let missing = ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"missing-input");
    assert_eq!(
        CampaignRepositoryError::Store(StoreError::NotFound { id: missing }).executor_rejection(),
        ExecutorRejection::UnavailableInput
    );
    assert_eq!(
        CampaignRepositoryError::Store(StoreError::Unauthorized).executor_rejection(),
        ExecutorRejection::Unauthorized
    );
    assert_eq!(
        integrity("invalid-executor-closure").executor_rejection(),
        ExecutorRejection::Incompatible
    );
    assert_eq!(
        CampaignRepositoryError::Poisoned.executor_rejection(),
        ExecutorRejection::UnavailableInput
    );
}
