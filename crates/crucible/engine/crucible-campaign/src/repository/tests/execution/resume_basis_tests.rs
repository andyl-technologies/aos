//! Stable execution-basis identity across paused campaign resume.

use super::*;

#[test]
fn campaign_executor_driver_resumes_the_exact_paused_root() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, _) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-driver-exact-resume",
    );
    let resources =
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("executor limits");
    let initial_policy_basis = repository
        .attempt_retention_policy_basis_at(admitted.new_snapshot, admitted.attempt)
        .expect("policy basis at initial admission");
    let prior_execution_basis = crate::attempt_execution_basis_digest_for_start_mode(
        repository
            .head("executor-driver-exact-resume")
            .expect("admitted head")
            .snapshot()
            .lineage(),
        admitted.attempt,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        AttemptStartMode::Execute,
        crate::AttemptRetentionPolicyDisposition::Required(initial_policy_basis),
    );
    let resume = command(
        "executor-driver-exact-resume-start",
        admitted.new_snapshot,
        CampaignControlAction::Resume,
    );
    repository
        .apply_control("executor-driver-exact-resume", &resume)
        .expect("start campaign");
    let running_head = repository
        .head("executor-driver-exact-resume")
        .expect("running campaign head");
    repository
        .apply_control(
            "executor-driver-exact-resume",
            &command(
                "executor-driver-exact-resume-pause",
                running_head.snapshot_id(),
                CampaignControlAction::Pause(ActiveAttemptPolicy::ExactCheckpoint),
            ),
        )
        .expect("pause campaign");
    let paused_head = repository
        .head("executor-driver-exact-resume")
        .expect("paused campaign head");
    repository
        .apply_control(
            "executor-driver-exact-resume",
            &command(
                "executor-driver-exact-resume-again",
                paused_head.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume campaign");
    let resumed_head = repository
        .head("executor-driver-exact-resume")
        .expect("resumed campaign head");
    let resumed_policy_basis = repository
        .attempt_retention_policy_basis_at(resumed_head.snapshot_id(), admitted.attempt)
        .expect("policy basis after campaign head advanced");
    assert_ne!(
        initial_policy_basis.snapshot(),
        resumed_policy_basis.snapshot()
    );
    assert_eq!(
        initial_policy_basis.admission(),
        resumed_policy_basis.admission()
    );
    assert_eq!(initial_policy_basis.policy(), resumed_policy_basis.policy());
    let prior_execution = ExecutionId::from_bytes([0x94; 16]).expect("prior execution");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"executor-driver-resume-root",
    ))
    .expect("checkpoint");
    let resumed_execution = ExecutionId::from_bytes([0x95; 16]).expect("resumed execution");
    let repository = Arc::new(repository);
    let service = PausedResumeExecutor {
        prior_execution,
        prior_execution_basis,
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
    assert_eq!(
        service.submit_requests[0].retention_policy(),
        crate::AttemptRetentionPolicyDisposition::Required(resumed_policy_basis)
    );
    assert_eq!(
        service.submit_requests[0].execution_basis_digest(),
        prior_execution_basis
    );
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
