//! Conformance tests for bounded worker-to-supervisor reconciliation.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::sync::atomic::AtomicBool;

use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, AttemptStartMode, CampaignHash,
    CampaignLineageId, ConfigurationArtifact, ConfigurationId, DaemonEpoch,
    ExecutionRetentionIntent, ExecutorRejection, ExecutorService, ExecutorStatusService,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, ScenarioArtifact, ScenarioDefId,
    SubmitAttemptDisposition, SubmitAttemptRequest,
};

use super::*;
use crate::executor_supervisor::{AllowAllAttemptAdmission, ExecutionCancellationHook};
use crate::supervision::ProcessDeadline;
use crate::{
    AssignmentLedger, AttemptExecutionKey, AttemptExecutionOrigin, AttemptRuntimeState,
    ExecutorCapacity, LocalExecutorSupervisor, MemoryAssignmentLedger,
};

#[test]
fn assignment_host_watchdog_interrupts_the_same_execution_incarnation() {
    let cancellation = ExecutionCancellation::default();
    let mut watchdog = AssignmentHostWatchdogGuard::start(10, cancellation.clone())
        .expect("start assignment watchdog");
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1024, 2048, 2).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        cancellation.clone(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_host_watchdog(watchdog.state.clone());
    let replay = context.for_origin_replay();

    std::thread::sleep(Duration::from_millis(30));

    assert!(watchdog.stop());
    assert!(cancellation.is_canceled());
    assert!(
        context
            .remaining_host_watchdog()
            .is_some_and(|remaining| remaining.is_zero())
    );
    assert!(
        replay
            .remaining_host_watchdog()
            .is_some_and(|remaining| remaining.is_zero())
    );
}

#[test]
fn completed_assignment_disarms_host_watchdog_before_deadline() {
    let cancellation = ExecutionCancellation::default();
    let mut watchdog = AssignmentHostWatchdogGuard::start(500, cancellation.clone())
        .expect("start assignment watchdog");

    assert!(!watchdog.stop());
    assert!(!cancellation.is_canceled());
    assert!(!watchdog.state.expired());
}

#[test]
fn maximum_encoded_host_watchdog_does_not_overflow_monotonic_time() {
    let cancellation = ExecutionCancellation::default();
    let mut watchdog = AssignmentHostWatchdogGuard::start(u64::MAX, cancellation.clone())
        .expect("start maximum encoded watchdog");

    assert!(watchdog.state.remaining() > Duration::from_secs(3600));
    assert!(!watchdog.stop());
    assert!(!cancellation.is_canceled());
}

#[test]
fn explicit_assignment_watchdog_supersedes_default_qemu_operation_timeout() {
    let cancellation = ExecutionCancellation::default();
    let mut watchdog = AssignmentHostWatchdogGuard::start(600_000, cancellation.clone())
        .expect("start assignment watchdog");
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1024, 2048, 2).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        cancellation,
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_host_watchdog(watchdog.state.clone());
    let default = crucible_api::ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        "kernel",
        "root",
        "run-state",
    );
    assert_eq!(default.completion_timeout(), Duration::from_secs(240));

    let configured =
        crate::qemu_campaign_lifecycle::config_for_assignment_host_watchdog(default, &context)
            .expect("policy-keyed lifecycle timeout");

    assert!(configured.completion_timeout() > Duration::from_secs(240));
    assert!(configured.completion_timeout() <= Duration::from_secs(600));
    assert!(!watchdog.stop());
}

#[derive(Debug)]
struct TestChildCancellationHook {
    child: Arc<Mutex<std::process::Child>>,
    signaled: Arc<AtomicBool>,
}

impl ExecutionCancellationHook for TestChildCancellationHook {
    fn signal(&self) {
        self.signaled.store(true, Ordering::Release);
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}

#[test]
#[ignore = "subprocess fixture for the assignment watchdog regression"]
fn host_watchdog_child_fixture() {
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
// Host time only bounds this subprocess regression; no modeled value uses it.
// crucible-lint: allow clippy-disallowed-method -- host time bounds only the test process wait.
#[allow(clippy::disallowed_methods)]
fn host_watchdog_kills_live_child_and_reconciles_infrastructure_failure() {
    let epoch = DaemonEpoch::from_bytes([0x61; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let request = request(epoch, 0x62);
    let response = supervisor
        .submit_attempt(&request)
        .expect("accept assignment");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued attempt");
    let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("host_watchdog_child_fixture")
        .arg("--ignored")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("launch supervised child");
    let child = Arc::new(Mutex::new(child));
    let signaled = Arc::new(AtomicBool::new(false));
    let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(TestChildCancellationHook {
        child: Arc::clone(&child),
        signaled: Arc::clone(&signaled),
    });
    let _registration = queued
        .cancellation()
        .register_hook(hook)
        .expect("register process cancellation");
    let mut watchdog = AssignmentHostWatchdogGuard::start(25, queued.cancellation().clone())
        .expect("start assignment watchdog");

    std::thread::sleep(Duration::from_millis(60));

    assert!(watchdog.stop());
    assert!(signaled.load(Ordering::Acquire));
    let reap_deadline =
        ProcessDeadline::after(Duration::from_secs(2)).expect("representable child reap deadline");
    loop {
        if child
            .lock()
            .expect("child lock")
            .try_wait()
            .expect("poll child")
            .is_some()
        {
            break;
        }
        assert!(!reap_deadline.expired(), "watchdog did not reap child");
        std::thread::sleep(Duration::from_millis(5));
    }
    let failure = complete_host_watchdog::<_, std::io::Error>(
        Ok("candidate that must not publish"),
        Some(&mut watchdog),
        Some(25),
    )
    .expect_err("expired host watchdog must suppress candidate publication");
    assert!(matches!(
        &failure,
        AttemptWorkerFailure::Terminal(RepositoryAttemptWorkerError::HostWatchdogExpired {
            milliseconds: 25,
        })
    ));
    let diagnostic =
        crate::packaged_qemu_executor::packaged_attempt_failure_diagnostic(execution, &failure);
    assert!(diagnostic.contains("host watchdog expired after 25 ms"));
    assert!(matches!(
        reconcile_attempt_failure(&mut supervisor, queued, failure),
        Err(AttemptWorkerReconcileError::TerminalStopped {
            terminal_failure: TerminalFailureOutcome::Failed,
            ..
        })
    ));
    let status = GetAttemptExecutionRequest::new(&request, execution).expect("status query");
    assert_eq!(
        supervisor
            .get_attempt_execution(&status)
            .expect("terminal status")
            .disposition(),
        GetAttemptExecutionDisposition::TerminalFailure
    );
}

#[test]
fn execution_quantum_budget_is_shared_and_refuses_the_exact_exhausted_boundary() {
    let resources = AttemptResourceLimits::new(1, 1024, 2048, 2).expect("resources");
    let context = AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    );
    let replay_context = context.for_origin_replay();

    replay_context
        .charge_execution_quantum()
        .expect("first replay quantum");
    assert_eq!(context.consumed_execution_quanta(), 1);
    assert_eq!(
        context
            .process_resources()
            .expect("one remaining process quantum")
            .maximum_execution_quanta(),
        1
    );

    context
        .charge_execution_quantum()
        .expect("last admitted quantum");
    assert_eq!(context.consumed_execution_quanta(), 2);
    assert_eq!(
        context.charge_execution_quantum(),
        Err(ExecutionQuantumBudgetError)
    );
    assert_eq!(
        context.process_resources(),
        Err(ExecutionQuantumBudgetError)
    );
}

#[test]
fn execution_quantum_budget_refuses_saturated_accounting_without_wrapping() {
    let resources = AttemptResourceLimits::new(1, 1024, 2048, u64::MAX).expect("resources");
    let context = AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    );
    context
        .execution_quanta
        .consumed
        .store(u64::MAX, Ordering::Release);

    assert_eq!(
        context.charge_execution_quantum(),
        Err(ExecutionQuantumBudgetError)
    );
    assert_eq!(context.consumed_execution_quanta(), u64::MAX);
    assert_eq!(
        context.process_resources(),
        Err(ExecutionQuantumBudgetError)
    );
}

#[test]
fn capture_start_validation_requires_the_exact_discovery_artifact() {
    let resolved = configuration_artifact(0x21);
    let resolved_id = resolved.id().expect("resolved configuration artifact ID");
    let requested = configuration_artifact(0x22)
        .id()
        .expect("requested configuration artifact ID");
    let start = ResolvedAttemptStart::Discover {
        configuration: resolved,
    };

    assert_eq!(
        capture_start_validation_reason(
            &start,
            AttemptStartMode::CaptureMaterializedStart {
                configuration: resolved_id,
            },
        )
        .expect("matching capture validation"),
        None
    );
    assert_eq!(
        capture_start_validation_reason(
            &start,
            AttemptStartMode::CaptureMaterializedStart {
                configuration: requested,
            },
        )
        .expect("capture validation"),
        Some("materialized-start capture configuration differs from resolved discovery start")
    );
    assert_eq!(
        capture_start_validation_reason(&start, AttemptStartMode::Execute)
            .expect("ordinary execution validation"),
        None
    );
}

#[test]
fn operational_worker_failure_requeues_without_growing_the_bounded_queue() {
    let epoch = DaemonEpoch::from_bytes([0x32; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    supervisor
        .submit_attempt(&request(epoch, 0x42))
        .expect("accept assignment");
    assert!(matches!(
        {
            let queued = supervisor.next_queued().expect("queued attempt");
            reconcile_attempt_failure(
                &mut supervisor,
                queued,
                AttemptWorkerFailure::Retryable("temporary materialization failure"),
            )
        },
        Err(AttemptWorkerReconcileError::Worker(
            AttemptWorkerFailure::Retryable("temporary materialization failure")
        ))
    ));
    assert_eq!(supervisor.active_count(), 1);
    assert_eq!(supervisor.queued_count(), 1);
}

#[test]
fn cancellation_keeps_capacity_until_the_worker_acknowledges_exit() {
    let epoch = DaemonEpoch::from_bytes([0x33; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let first_request = request(epoch, 0x43);
    let response = supervisor
        .submit_attempt(&first_request)
        .expect("accept assignment");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued attempt");
    supervisor
        .cancel_execution(
            AttemptExecutionKey::new(first_request.lineage(), first_request.attempt()),
            execution,
        )
        .expect("cancel running worker");
    assert!(queued.cancellation().is_canceled());
    assert_eq!(supervisor.active_count(), 1);
    let replacement = request(epoch, 0x44);
    assert!(matches!(
        supervisor
            .submit_attempt(&replacement)
            .expect("bounded replacement response")
            .disposition(),
        SubmitAttemptDisposition::Rejected { .. }
    ));

    assert!(matches!(
        reconcile_attempt_failure(
            &mut supervisor,
            queued,
            AttemptWorkerFailure::Canceled::<&'static str>("worker observed cancellation"),
        ),
        Err(AttemptWorkerReconcileError::Stopped {
            cancellation: CancellationOutcome::AlreadyCanceled,
            ..
        })
    ));
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);
}

#[test]
fn cancellation_wins_over_a_retryable_worker_failure() {
    let epoch = DaemonEpoch::from_bytes([0x34; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let request = request(epoch, 0x45);
    let response = supervisor
        .submit_attempt(&request)
        .expect("accept assignment");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued attempt");
    supervisor
        .cancel_execution(
            AttemptExecutionKey::new(request.lineage(), request.attempt()),
            execution,
        )
        .expect("cancel running worker");

    assert!(matches!(
        reconcile_attempt_failure(
            &mut supervisor,
            queued,
            AttemptWorkerFailure::Retryable("temporary failure after cancellation"),
        ),
        Err(AttemptWorkerReconcileError::Stopped {
            failure: AttemptWorkerFailure::Retryable("temporary failure after cancellation"),
            cancellation: CancellationOutcome::AlreadyCanceled,
        })
    ));
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);
}

#[test]
fn terminal_worker_failure_is_durable_without_requeue() {
    let epoch = DaemonEpoch::from_bytes([0x34; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let request = request(epoch, 0x45);
    let response = supervisor
        .submit_attempt(&request)
        .expect("accept assignment");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued attempt");

    assert!(matches!(
        reconcile_attempt_failure(
            &mut supervisor,
            queued,
            AttemptWorkerFailure::Terminal("incompatible modeled result"),
        ),
        Err(AttemptWorkerReconcileError::TerminalStopped {
            terminal_failure: TerminalFailureOutcome::Failed,
            failure: AttemptWorkerFailure::Terminal("incompatible modeled result"),
        })
    ));
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);

    let status = GetAttemptExecutionRequest::new(&request, execution).expect("status query");
    assert_eq!(
        supervisor
            .get_attempt_execution(&status)
            .expect("terminal status")
            .disposition(),
        GetAttemptExecutionDisposition::TerminalFailure
    );

    let restart_epoch = DaemonEpoch::from_bytes([0x35; 16]).expect("restart epoch");
    let mut restarted = LocalExecutorSupervisor::new(
        supervisor.into_ledger(),
        AllowAllAttemptAdmission,
        restart_epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity"),
    );
    assert_eq!(
        restarted
            .ledger()
            .load_attempt(AttemptExecutionKey::new(
                request.lineage(),
                request.attempt()
            ))
            .expect("load terminal state"),
        Some(AttemptRuntimeState::TerminalFailure {
            execution_basis: request.execution_basis_digest(),
            origin: AttemptExecutionOrigin::Initial,
            daemon_epoch: epoch,
            execution,
        })
    );

    let reassignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x46; 16]).expect("reassignment"),
        restart_epoch,
        request.lineage(),
        request.attempt(),
        request.resources(),
        request.retention(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("restart assignment");
    assert_eq!(
        restarted
            .submit_attempt(&reassignment)
            .expect("terminal replay response")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::TerminalFailure,
        }
    );
    assert_eq!(restarted.active_count(), 0);
    assert_eq!(restarted.queued_count(), 0);
}

fn supervisor(
    epoch: DaemonEpoch,
) -> LocalExecutorSupervisor<MemoryAssignmentLedger, AllowAllAttemptAdmission> {
    LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity"),
    )
}

fn request(epoch: DaemonEpoch, byte: u8) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([byte; 16]).expect("assignment"),
        epoch,
        CampaignLineageId::parse(&typed_content_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            1,
            byte,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_content_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            9,
            byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("request")
}

fn configuration_artifact(byte: u8) -> ConfigurationArtifact {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "crucible.test.executor-worker.capture-scenario.v1",
        &[byte],
    ));
    let scenario_artifact = ScenarioArtifact::new(scenario, 1, vec![byte])
        .expect("scenario artifact")
        .id()
        .expect("scenario artifact ID");
    let configuration = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.executor-worker.capture-configuration.v1",
        &[byte],
    ));
    ConfigurationArtifact::new(scenario, scenario_artifact, configuration, 1, vec![byte])
        .expect("configuration artifact")
}

fn typed_content_id(tag: &str, kind: &str, schema_version: u32, byte: u8) -> String {
    format!(
        "{tag}@{kind}.{schema_version}.{}",
        format!("{byte:02x}").repeat(32)
    )
}
