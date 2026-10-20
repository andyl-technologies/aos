//! Executor response and rejection validation regressions.

use super::*;

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
        crate::AttemptRetentionPolicyDisposition::Disabled,
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
        crate::AttemptRetentionPolicyDisposition::Disabled,
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
