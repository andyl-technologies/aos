// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    AppRandomDecision, Checkpoint, CheckpointKind, Configuration, Decision, NodeId, RngDecision,
    RngStreamId, ScenarioDef, SchedulerEventLogEntry, VirtualTime, step,
};
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig,
    ProductionVmNodeLauncher,
};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
    ConfigurationArtifact, ConfigurationId, ExecutionRetentionIntent, ScenarioArtifact,
    ScenarioDefId, StopCondition,
};
use crucible_cas::content_store::{BlobHandle, ContentId, ObjectKind};
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory, QemuReplayOracleValidation, QemuVmRealizationError, QemuVmSnapshot,
};

use super::*;
use crate::{
    AttemptExecutionProduct, CrucibleAttemptExecution, CrucibleMaterializationTier,
    CrucibleResolvedAttemptStart, ExecutionCancellation, ExecutionCheckpointRequest,
    QemuAttemptOperationalBoundary, QemuAttemptResourceGuard,
};

#[derive(Default)]
struct GuardCounters {
    begins: AtomicUsize,
    checks: AtomicUsize,
    charges: AtomicUsize,
    finishes: AtomicUsize,
    quarantines: AtomicUsize,
}

struct FakeResourceFactory {
    installed_resources: AttemptResourceLimits,
    replace_cancellation: bool,
    counters: Arc<GuardCounters>,
}

impl QemuAttemptResourceGuardFactory for FakeResourceFactory {
    type Guard = FakeResourceGuard;

    fn begin(
        &mut self,
        _resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        self.counters.begins.fetch_add(1, Ordering::SeqCst);
        Ok(FakeResourceGuard {
            resources: self.installed_resources,
            cancellation: if self.replace_cancellation {
                ExecutionCancellation::default()
            } else {
                cancellation
            },
            counters: Arc::clone(&self.counters),
            terminal: false,
        })
    }
}

struct FakeResourceGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    counters: Arc<GuardCounters>,
    terminal: bool,
}

impl QemuAttemptOperationalBoundary for FakeResourceGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.counters.checks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.counters.charges.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl QemuAttemptResourceGuard for FakeResourceGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if !self.terminal {
            self.counters.finishes.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.counters.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }
}

impl QemuAttemptProcessResourceGuard for FakeResourceGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Err(fake_guard_error(
            "fake guard does not launch child processes",
        ))
    }

    fn prepare_generation_run_directory(
        &mut self,
        _requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        Err(fake_guard_error(
            "fake guard does not provision generation directories",
        ))
    }

    fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}
}

fn fake_guard_error(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "test production lifecycle guard",
        message: message.into(),
    }
}

fn resources(quanta: u64) -> AttemptResourceLimits {
    AttemptResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024, quanta)
        .expect("attempt resource fixture")
}

fn context(
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::Discard,
        cancellation,
        ExecutionCheckpointRequest::default(),
    )
}

fn factory(
    installed_resources: AttemptResourceLimits,
    replace_cancellation: bool,
    counters: Arc<GuardCounters>,
) -> QemuAttemptProductionVmLifecycleFactory<FakeResourceFactory> {
    QemuAttemptProductionVmLifecycleFactory::new(
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        FakeResourceFactory {
            installed_resources,
            replace_cancellation,
            counters,
        },
    )
}

#[test]
fn exact_guard_is_transferred_to_lifecycle_launcher_hooks() {
    let limits = resources(2);
    let counters = Arc::new(GuardCounters::default());
    let cancellation = ExecutionCancellation::default();
    let context = context(limits, cancellation);
    let mut factory = factory(limits, false, Arc::clone(&counters));

    factory
        .with_attempt_launcher(&context, 1, |mut launcher| {
            launcher.begin_execution_quantum()?;
            launcher.check_operational_boundary()?;
            launcher.finish()
        })
        .expect("exact guard should back lifecycle launcher hooks");

    assert_eq!(counters.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counters.charges.load(Ordering::SeqCst), 1);
    assert_eq!(counters.checks.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_resume_is_rejected_before_resource_installation() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"fresh-lifecycle-resume-rejection",
    ))
    .expect("exact checkpoint fixture");
    let context =
        context(limits, ExecutionCancellation::default()).with_resume_checkpoint(Some(checkpoint));
    let mut factory = factory(limits, false, Arc::clone(&counters));
    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario fixture")
        .scenario;

    let error = factory
        .begin_fresh(&source.scenario_def(), &source, &context)
        .err()
        .expect("resume root must fail closed on the fresh path");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(actual)
            if actual == checkpoint
    ));
    assert_eq!(counters.begins.load(Ordering::SeqCst), 0);
}

#[test]
fn drifted_scenario_identity_fields_are_rejected_before_resource_installation() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let context = context(limits, ExecutionCancellation::default());
    let mut factory = factory(limits, false, Arc::clone(&counters));
    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario fixture")
        .scenario;
    let reconstructed = source.scenario_def();
    let drifted = crucible::ScenarioDef::from_trusted_identity(
        reconstructed.id(),
        crucible::Seed::from_u64(0xabad_1dea),
        reconstructed.app_random_draw_cap(),
    );

    let error = factory
        .begin_fresh(&drifted, &source, &context)
        .err()
        .expect("drifted scenario fields must fail closed");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch
    ));
    assert_eq!(counters.begins.load(Ordering::SeqCst), 0);
}

#[test]
fn mismatched_guard_contract_is_released_before_rejection() {
    let requested = resources(1);
    let installed = AttemptResourceLimits::new(
        requested.maximum_vcpus() + 1,
        requested.maximum_resident_bytes(),
        requested.maximum_disk_bytes(),
        requested.maximum_execution_quanta(),
    )
    .expect("mismatched limits fixture");
    let counters = Arc::new(GuardCounters::default());
    let context = context(requested, ExecutionCancellation::default());
    let mut factory = factory(installed, false, Arc::clone(&counters));

    let error = factory
        .with_attempt_launcher(&context, 1, |_launcher| Ok(()))
        .expect_err("mismatched limits must fail closed");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn mismatched_cancellation_incarnation_is_released_before_rejection() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let context = context(limits, ExecutionCancellation::default());
    let mut factory = factory(limits, true, Arc::clone(&counters));

    let error = factory
        .with_attempt_launcher(&context, 1, |_launcher| Ok(()))
        .expect_err("mismatched cancellation must fail closed");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn lifecycle_construction_failure_quarantines_installed_guard() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let context = context(limits, ExecutionCancellation::default());
    let mut factory = factory(limits, false, Arc::clone(&counters));

    let error = factory
        .with_attempt_launcher(&context, 1, |_launcher| {
            Err::<(), _>(LifecycleApiError::LoopFactory {
                message: String::from("injected lifecycle construction failure"),
            })
        })
        .expect_err("construction failure must remain observable");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::Lifecycle(_)
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

struct FakeFreshLifecycle {
    order: Arc<Mutex<Vec<&'static str>>>,
    cleanup_error: bool,
}

impl QemuFreshAttemptLifecycleOwner for FakeFreshLifecycle {
    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("replay");
        let configuration = step(
            &request.configuration,
            Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            }),
        );
        Ok(crucible::QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: 1 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        Ok(true)
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("fake lifecycle has no production fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("shutdown");
        if self.cleanup_error {
            Err(crucible::SchedulerError::BoundaryViolation {
                message: String::from("injected fresh lifecycle cleanup failure"),
            })
        } else {
            Ok(vec![SchedulerEventLogEntry::execution_budget_exhausted(
                7,
                VirtualTime { ticks: 11 },
                "final-drain-test",
            )])
        }
    }
}

struct FakeFreshLifecycleFactory {
    order: Arc<Mutex<Vec<&'static str>>>,
    cleanup_error: bool,
}

impl QemuFreshAttemptLifecycleFactory for FakeFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &crucible::ScenarioDefForm,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("begin");
        Ok(FakeFreshLifecycle {
            order: Arc::clone(&self.order),
            cleanup_error: self.cleanup_error,
        })
    }
}

#[derive(Clone, Copy)]
enum FakeFreshDriverFailure {
    Retryable,
}

struct FakeFreshDriver {
    order: Arc<Mutex<Vec<&'static str>>>,
    failure: Option<FakeFreshDriverFailure>,
}

impl QemuFreshAttemptDriver for FakeFreshDriver {
    type Pending = &'static str;
    type Error = &'static str;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _materialization: QemuFreshStartMaterialization,
    ) -> Result<Self::Pending, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("drive");
        assert_eq!(lifecycle.pending_network_output_count(), 0);
        assert!(
            lifecycle
                .exact_checkpoint_ready()
                .expect("checkpoint ready")
        );
        match self.failure {
            None => Ok("pending modeled result"),
            Some(FakeFreshDriverFailure::Retryable) => {
                Err(AttemptWorkerFailure::Retryable("driver retry"))
            }
        }
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert_eq!(pending, "pending modeled result");
        assert_eq!(final_events.len(), 1);
        assert_eq!(final_events[0].sequence(), 7);
        let mut order = self.order.lock().expect("fresh lifecycle order");
        assert_eq!(order.last(), Some(&"shutdown"));
        order.push("seal");
        Ok(test_checkpoint_product())
    }
}

#[test]
fn fresh_runner_seals_only_after_runner_owned_shutdown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let outcome = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect("fresh execution should seal after cleanup");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown", "seal"]
    );
    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn fresh_runner_rejects_resume_origin_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        3,
        b"fresh-runner-resume-origin",
    ))
    .expect("exact checkpoint fixture");
    let resumed = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let error = runner
        .execute(&fresh_runner_input(), &resumed)
        .expect_err("fresh runner must reject a resume origin");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::ResumeCheckpointUnsupported(actual)
        ) if actual == checkpoint
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_replays_supported_non_genesis_start_before_driver() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input();
    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("fresh runner must replay a supported non-genesis start");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn fresh_runner_replay_divergence_cleans_up_without_calling_driver() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("drifted replay prefix must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Diverged
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn fresh_runner_replay_honors_cancellation_before_first_quantum() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();

    let error = runner
        .execute(
            &non_genesis_fresh_runner_input(),
            &context(resources(4), cancellation),
        )
        .expect_err("canceled replay must fail before a scheduler quantum");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Canceled
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "shutdown"]
    );
}

#[test]
fn fresh_runner_replay_is_bounded_by_admitted_quanta() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let input = non_genesis_fresh_runner_input_with_decisions(vec![decision.clone(), decision]);

    let error = runner
        .execute(
            &input,
            &context(resources(1), ExecutionCancellation::default()),
        )
        .expect_err("replay must not exceed the attempt quantum ceiling");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::QuantumLimit
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn fresh_runner_rejects_producer_override_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input =
        non_genesis_fresh_runner_input_with_decision(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::from_name("fresh-runner-override"),
            request_id: 1,
            width: 8,
            value: 7,
        }));
    let expected = match input.start() {
        CrucibleResolvedAttemptStart::Discover { configuration } => configuration.id(),
        CrucibleResolvedAttemptStart::Branch { .. } => panic!("expected discovery fixture"),
    };

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("producer override must fail before fresh lifecycle construction");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                configuration,
                decision: 0,
            }
        ) if configuration == expected
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_cleans_up_and_preserves_driver_failure_classification() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: Some(FakeFreshDriverFailure::Retryable),
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("driver retry should remain classified");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver("driver retry"))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
}

#[test]
fn fresh_cleanup_failure_overrides_driver_retry_and_retains_diagnostics() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: Some(FakeFreshDriverFailure::Retryable),
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("cleanup failure must take precedence");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterDriver {
            driver: "driver retry",
            ..
        })
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
}

#[test]
fn production_lifecycle_resource_admission_keeps_retry_and_cancel_classes() {
    let unavailable = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "install test resources",
                message: String::from("temporarily unavailable"),
            },
        ),
    );
    assert!(matches!(unavailable, AttemptWorkerFailure::Retryable(_)));

    let canceled = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::Canceled {
                operation: "install test resources",
            },
        ),
    );
    assert!(matches!(canceled, AttemptWorkerFailure::Canceled(_)));

    let terminal = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch,
    );
    assert!(matches!(terminal, AttemptWorkerFailure::Terminal(_)));
}

fn fresh_runner_input() -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let definition = scenario.scenario_def();
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(definition.id().bytes));
    let scenario_artifact =
        ScenarioArtifact::new(scenario_id, 1, b"scenario".to_vec()).expect("scenario artifact");
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(definition);
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario_id,
        scenario_content,
        configuration_id,
        1,
        b"configuration".to_vec(),
    )
    .expect("configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_id,
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("campaign lineage");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path id"),
        StopCondition::Terminal,
    )
    .expect("discovery attempt");

    CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn non_genesis_fresh_runner_input() -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    }))
}

fn non_genesis_fresh_runner_input_with_decision(decision: Decision) -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decisions(vec![decision])
}

fn non_genesis_fresh_runner_input_with_decisions(
    decisions: Vec<Decision>,
) -> CrucibleAttemptExecution {
    let input = fresh_runner_input();
    let scenario = input.scenario().clone();
    let definition = scenario.scenario_def();
    let configuration = decisions.into_iter().fold(
        Configuration::genesis(definition.clone()),
        |parent, decision| step(&parent, decision),
    );
    let scenario_id = input.lineage().scenario();
    let scenario_content = input.lineage().scenario_content();
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario_id,
        scenario_content,
        configuration_id,
        1,
        b"non-genesis-configuration".to_vec(),
    )
    .expect("non-genesis configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("non-genesis configuration artifact id");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path id"),
        StopCondition::Terminal,
    )
    .expect("non-genesis discovery attempt");

    CrucibleAttemptExecution::from_test_parts(
        input.lineage().clone(),
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn fresh_runner_context() -> AttemptExecutionContext {
    context(resources(4), ExecutionCancellation::default())
}

fn test_checkpoint_product() -> AttemptExecutionProduct {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.fresh-campaign-runner",
        "sealed-product",
    ));
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("fresh runner checkpoint boundary");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("fresh runner QEMU snapshot");
    AttemptExecutionProduct::ExactCheckpoint(Box::new(crate::CapturedExactCheckpoint::new(
        snapshot,
        BlobHandle::from_bytes(vec![0x5a; 512]),
    )))
}
