//! QEMU campaign lifecycle restart, promotion, and recovery tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible::model::{BindingSearchChoice, SearchChoiceId};
use crucible::test_support::{
    condition_observation_entry_for_test, condition_open_payload_entry_for_test,
};
use crucible::{
    AppRandomDecision, AppRandomSelectable, AssertionDef, AssertionId, AssertionPhase, Checkpoint,
    CheckpointKind, Configuration, Decision, EventAttributeValue, EventDiagnosticPayload,
    EventLevel, EventLog, EventPayload, FindingDiscoveryPath, FindingReproductionArtifact, Icount,
    MarkerId, NodeId, NodeTemplate, ObservableEvent, Plan, Predicate, Properties, Property,
    ReadyPoint, RngDecision, RngStreamId, ScenarioDef, ScenarioDefForm, ScenarioSelectableLimits,
    ScenarioSelectables, SchedulerEvaluationBoundaryKind, SchedulerEventLogClass,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SearchFrontierChoices, SearchRuntimeFrontier,
    SearchScheduleNamedPredicateKey, SearchScheduleNamedPredicateTruths, Seed, SelectionDecision,
    SignalFaultSelectable, VirtualTime, WhiteBoxPolicy, World, WorldNode, step,
};
use crucible_api::vm_lifecycle::production_permanently_failed_loop_for_test;
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig,
    ProductionVmNodeLauncher, build_authenticated_production_checkpoint_codec_fixture,
};
use crucible_campaign::{
    AssignmentId, Attempt, AttemptContinuationInput, AttemptResourceLimits, AttemptStart,
    AttemptStartMode, BooleanDomain, BranchPath, BranchPathSegment, BudgetGrant, CampaignCommandId,
    CampaignControlAction, CampaignExecutorStore, CampaignFactId, CampaignHash, CampaignLineage,
    CampaignMode, CampaignPolicy, CampaignRepository, CampaignSeed, ChoiceClassContext,
    ChoiceDiscovery, ChoiceDomain, ChoiceSource, ChoiceValue, ConfigurationArtifact,
    ConfigurationId, ControlRequest, CoverageProjection, DaemonEpoch, DiscoveryRequest,
    ExecutionId, ExecutionRetentionIntent, ExecutorRejection, ExecutorService, ExplorerPolicy,
    FairnessPolicy, FindingCandidateBundleId, FindingExactPins, MeasurementSet, Observation,
    ObservationCandidate, ObservationCondition, ObservationEventLogProof, ObservationId,
    ObservationQuantumBoundary, ObservationStopProof, ObservationStopSatisfaction,
    PropertyEvidence, PropertyVerdict, PropertyVerdictSet, RetentionPolicy, ScenarioArtifact,
    ScenarioDefId, SelectableDeclaration, Selection, SelectionOrigin, SelectionReplayMismatchKind,
    StopCondition, StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
};
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MemoryBlobBackend, MemoryRefBackend, ObjectKind, StoreGraph, StoreGraphConfig, StoreNodeId,
    StoreNodeSpec,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuLiveNodeStepGateConfig,
    QemuNodeChild, QemuPreparedRunDirectory, QemuReplayOracleValidation, QemuVmRealizationError,
    QemuVmSnapshot,
};

use super::*;
use crate::crucible_execution::{CrucibleAttemptOrigin, CrucibleAttemptOrigins};
use crate::exact_checkpoint_store::AttemptCheckpointResultState;
use crate::executor_supervisor::{AttemptCheckpointHandoff, ExecutionCheckpointHandoff};
use crate::qemu_campaign_driver::QemuFreshSupplementalModeledDriver;
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionDisposition,
    AttemptExecutionOrigin, AttemptExecutionProduct, AttemptExecutionReconciliationStep,
    AttemptResultRecoveryFailure, AttemptResultStageOutcome, AttemptRuntimeState, AttemptStateCas,
    AutomaticFindingReplayOutcome, CapturedAttemptCheckpoint, CheckpointHandoffFailure,
    CompletionValidationFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, CrucibleFindingReplayTranscript, CrucibleMaterializationTier,
    CrucibleResolvedAttemptStart, DirectoryAssignmentLedger, DirectoryCampaignGcJournal,
    DirectoryPreparedResultJournal, ExactCheckpointStore, ExecutionCancellation,
    ExecutionCheckpointRequest, ExecutorCapacity, FindingReplayCaptureStore,
    LocalExecutorSupervisor, MAX_PREPARED_SEMANTIC_RESULT_BYTES, ObservationPublicationOutcome,
    PreparedAttemptCheckpoint, PreparedAttemptRecoveryOutcome, PreparedSemanticAttemptResult,
    QemuAttemptExecutionRouter, QemuAttemptExecutionRouterError, QemuAttemptOperationalBoundary,
    QemuAttemptResourceGuard, QemuFreshModeledDriver, QemuSavepointReplayProof,
    QemuSelectedOriginResumeRunner, apply_single_host_campaign_gc, plan_single_host_campaign_gc,
};

#[derive(Debug)]
struct OversizedFailure<E> {
    source: E,
}

impl<E: fmt::Display> fmt::Display for OversizedFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} trailing=", self.source)?;
        for _ in 0..10_000 {
            formatter.write_str("x")?;
        }
        Ok(())
    }
}

impl<E: Error + 'static> Error for OversizedFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[test]
fn genesis_start_error_retains_worker_class_and_underlying_cause() {
    let error = QemuFreshGenesisCheckpointError::Start(AttemptWorkerFailure::Terminal(
        std::io::Error::other("guarded launch rejected"),
    ));
    assert!(
        error
            .to_string()
            .contains("terminal execution failure: guarded launch rejected")
    );
    let worker = std::error::Error::source(&error).expect("worker classification source");
    assert_eq!(
        worker.source().expect("original cause").to_string(),
        "guarded launch rejected"
    );
}

#[test]
fn selected_start_derives_matching_scheduler_and_plugin_branch_plans() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.campaign.branch-plan",
        "scenario=branch-plan",
        Seed::from_u64(0x51ec_7100),
    );
    let genesis = Configuration::genesis(scenario.clone());
    let stream = RngStreamId::from_name("app-random/node:6:node-a/stream:6:branch");
    let mut seeded = scenario
        .seed()
        .decision_rng()
        .fork_in_domain(&stream.domain, &stream.name);
    let raw = seeded.next_u64();
    let selected = raw ^ 1;
    let live = AppRandomDecision {
        node: NodeId {
            name: String::from("node-a"),
        },
        stream: stream.clone(),
        request_id: 11,
        width: 64,
        value: selected,
    };
    let parent = step(
        &genesis,
        Decision::RngDraw(RngDecision { stream, value: raw }),
    );
    let selection = AppRandomSelectable::from_decision(&scenario, &live)
        .expect("app-random request should reconstruct")
        .branch_selection(&parent, selected)
        .expect("exact parent should admit branch selection");
    let target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );

    let (scheduler, plugins) =
        app_random_branch_replay(&target).expect("selected target should derive plans");

    assert_eq!(
        scheduler.get(&parent.id()),
        Some(&SelectionDecision::new(&selection))
    );
    let plugin = plugins
        .get(&NodeId {
            name: String::from("node-a"),
        })
        .expect("node plan should exist");
    assert!(matches!(
        plugin.entries(),
        [entry]
            if entry.draw_index() == 0
                && entry.expected_raw_value() == raw
                && entry.selected_value() == selected
                && entry.selection_id()
                    == selection.id().expect("selection id").content_id().digest()
    ));
}

#[test]
fn promoted_signal_fault_branch_is_admitted_only_by_its_typed_plan() {
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.campaign.signal-fault-branch",
        "signal fault branch",
    );
    let parent = Configuration::genesis(scenario);
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(b"choice")),
        candidates_digest: crucible::ContentHash::from_bytes(b"candidates"),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    let frontier = SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime { ticks: 91 },
        choices: SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(Decision::Override),
        ),
    };
    let selectable = SignalFaultSelectable::from_frontier(&frontier)
        .expect("signal-fault frontier should normalize");
    let selection = selectable
        .branch_selection(&parent, 1)
        .expect("candidate should select");
    let branch = selectable
        .resolve_branch(&selection)
        .expect("candidate should reconstruct");

    let empty = crucible::SignalFaultCampaignReplayPlan::empty(branch.selected().clone());
    assert_eq!(
        unsupported_fresh_replay_decision(branch.selected(), &empty),
        Some(1)
    );
    let plan = crucible::SignalFaultCampaignReplayPlan::new(
        branch.selected().clone(),
        vec![branch.clone()],
    )
    .expect("typed replay plan");
    assert_eq!(
        unsupported_fresh_replay_decision(branch.selected(), &plan),
        None
    );
}

#[test]
fn app_random_projection_ignores_a_campaign_selection_outside_its_owned_stream() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.campaign.branch-plan",
        "scenario=foreign-stream-domain",
        Seed::from_u64(0x51ec_7101),
    );
    let genesis = Configuration::genesis(scenario.clone());
    let stream = RngStreamId::for_node("app-random/node:6:node-a/stream:6:branch");
    let raw = 17;
    let selected = 23;
    let live = AppRandomDecision {
        node: NodeId {
            name: String::from("node-a"),
        },
        stream: stream.clone(),
        request_id: 11,
        width: 64,
        value: selected,
    };
    let parent = step(
        &genesis,
        Decision::RngDraw(RngDecision { stream, value: raw }),
    );
    let selection = AppRandomSelectable::from_decision(&scenario, &live)
        .expect("foreign-domain selectable should remain structurally valid")
        .branch_selection(&parent, selected)
        .expect("exact parent should admit a structural branch selection");
    let target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );

    let (selections, plans) =
        app_random_branch_replay(&target).expect("foreign producer stays outside this adapter");
    assert!(selections.is_empty());
    assert!(plans.is_empty());
}

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
    completed_quanta: u64,
    promotion_observations: Option<Arc<Mutex<Vec<bool>>>>,
    cleanup_error: bool,
    pending: Vec<crucible_qemu::QemuNodeSelectablePendingRequest>,
    replies: Arc<Mutex<Vec<crucible_protocol::SelectionReply>>>,
    signal_fault_branches: VecDeque<crucible::SignalFaultCampaignBranch>,
    terminal_after_replay: bool,
    checkpoint_ready: bool,
    fingerprint_error: bool,
    fingerprint_node_override: Arc<Mutex<Option<crucible::NodeId>>>,
}

impl FakeFreshLifecycle {
    fn complete_quantum(
        &mut self,
        outcome: crucible::QuantumOutcome,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.completed_quanta = self.completed_quanta.checked_add(1).ok_or_else(|| {
            crucible::SchedulerError::BoundaryViolation {
                message: String::from("fake lifecycle quantum coordinate overflowed"),
            }
        })?;
        Ok(outcome)
    }
}

impl QemuFreshAttemptLifecycleOwner for FakeFreshLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("promotion");
        if let Some(observations) = &self.promotion_observations {
            observations
                .lock()
                .expect("promotion observations")
                .push(true);
        }
    }

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("replay");
        if let Some(branch) = self.signal_fault_branches.front().cloned()
            && branch.parent() == &request.configuration
        {
            self.signal_fault_branches.pop_front();
            return self.complete_quantum(crucible::QuantumOutcome {
                configuration: branch.selected().clone(),
                frontier: branch.frontier(),
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: branch.decisions().to_vec(),
                discovered_choices: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible::EventLogOffset::default(),
                scheduler_quiescence: None,
            });
        }
        let configuration = step(
            &request.configuration,
            Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            }),
        );
        let next_frontier = self.completed_quanta.saturating_add(1);
        self.complete_quantum(crucible::QuantumOutcome {
            configuration,
            frontier: VirtualTime {
                ticks: next_frontier,
            },
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

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        (self.terminal_after_replay && self.completed_quanta > 0).then(|| {
            crucible::QuantumTerminalVerdict::Failed(vec![String::from(
                "selected property was violated",
            )])
        })
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), crucible::SchedulerError> {
        assert_eq!(
            cause,
            crucible::CheckpointTerminalCause::Failed(vec![String::from(
                "selected property was violated",
            )])
        );
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("terminal-cause");
        Ok(())
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        Ok(self.checkpoint_ready)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, crucible::SchedulerError>
    {
        Ok(std::mem::take(&mut self.pending))
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.replies
            .lock()
            .expect("fresh lifecycle replies")
            .push(reply.clone());
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("capture");
        Ok(test_checkpoint_capture().into())
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

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        if self.fingerprint_error {
            return Err(crucible::SchedulerError::BoundaryViolation {
                message: format!("injected missing fingerprint node `{}`", node.name),
            });
        }
        Ok(crucible::FingerprintSample {
            node: self
                .fingerprint_node_override
                .lock()
                .expect("fingerprint node override")
                .clone()
                .unwrap_or(node),
            at: VirtualTime {
                ticks: self.completed_quanta,
            },
            fingerprint: crucible::ExecutionFingerprint {
                hash: crucible::ContentHash::from_bytes(&self.completed_quanta.to_le_bytes()),
            },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, crucible::SchedulerError> {
        Ok(Some(b"resolved-effect-test".to_vec()))
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

#[test]
fn observed_lifecycle_retains_only_successful_execution_evidence() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.standalone-campaign-lifecycle",
        "scenario=standalone-campaign-lifecycle",
        Seed::from_u64(0x5a11_da10),
    );
    let genesis = Configuration::genesis(scenario);
    let order = Arc::new(Mutex::new(Vec::new()));
    let lifecycle = FakeFreshLifecycle {
        order: Arc::clone(&order),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed = QemuObservedFreshAttemptLifecycle::new(
        lifecycle,
        vec![crucible::NodeId {
            name: String::from("node"),
        }],
        evidence.clone(),
    );

    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis.clone(),
            control: Vec::new(),
        })
        .expect("first admitted quantum");
    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis,
            control: Vec::new(),
        })
        .expect("second admitted quantum");
    observed
        .prepare_terminal_fingerprints()
        .expect("terminal fingerprints");
    observed.shutdown().expect("cleanup remains available");
    let snapshot = evidence.snapshot().expect("observed execution evidence");
    assert_eq!(snapshot.quanta(), 2);
    assert_eq!(snapshot.frontier(), VirtualTime { ticks: 2 });
    assert_eq!(snapshot.event_log_entries().len(), 1);
    assert_eq!(snapshot.execution_fingerprints().len(), 2);
    assert_eq!(snapshot.execution_fingerprints()[0].at.ticks, 0);
    assert_eq!(snapshot.execution_fingerprints()[1].at.ticks, 1);
    let terminal = snapshot
        .terminal_fingerprints()
        .expect("published terminal fingerprints");
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].at.ticks, 2);
    assert_ne!(
        terminal[0].fingerprint,
        snapshot.execution_fingerprints()[1].fingerprint
    );
    assert_eq!(
        snapshot.resolved_effect_trace(),
        Some(b"resolved-effect-test".as_slice())
    );
    assert_eq!(
        *order.lock().expect("standalone lifecycle order"),
        ["replay", "replay", "shutdown"]
    );
}

#[test]
fn observed_production_lifecycle_projects_retained_failed_node_terminal_fingerprints()
-> Result<(), Box<dyn Error>> {
    let (source, mut lifecycle) = production_permanently_failed_loop_for_test()?;
    let nodes = source
        .world()
        .vm_nodes()
        .iter()
        .map(|vm| vm.id.clone())
        .collect::<Vec<_>>();
    let expected = nodes
        .iter()
        .map(|node| QuantumLoop::sample_fingerprint(&mut lifecycle, node.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed = QemuObservedFreshAttemptLifecycle::new(lifecycle, nodes, evidence.clone());

    observed.prepare_terminal_fingerprints()?;
    observed.shutdown()?;

    let snapshot = evidence.snapshot()?;
    assert_eq!(snapshot.terminal_fingerprints(), Some(expected.as_slice()));
    Ok(())
}

#[test]
fn observed_lifecycle_rejects_a_mismatched_terminal_fingerprint_atomically() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.terminal-fingerprint-mismatch",
        "scenario=terminal-fingerprint-mismatch",
        Seed::from_u64(0x5a11_da11),
    );
    let genesis = Configuration::genesis(scenario);
    let expected = crucible::NodeId {
        name: String::from("expected-node"),
    };
    let fingerprint_node_override = Arc::new(Mutex::new(None));
    let lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::clone(&fingerprint_node_override),
    };
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed =
        QemuObservedFreshAttemptLifecycle::new(lifecycle, vec![expected], evidence.clone());
    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis,
            control: Vec::new(),
        })
        .expect("admitted quantum");
    *fingerprint_node_override
        .lock()
        .expect("fingerprint node override") = Some(crucible::NodeId {
        name: String::from("wrong-node"),
    });

    let error = observed
        .prepare_terminal_fingerprints()
        .expect_err("a mismatched terminal sample must fail closed");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    observed.shutdown().expect("cleanup remains available");
    let snapshot = evidence.snapshot().expect("evidence after refusal");
    assert_eq!(snapshot.execution_fingerprints().len(), 2);
    assert_eq!(snapshot.terminal_fingerprints(), None);
}

#[test]
fn observed_lifecycle_does_not_publish_staged_fingerprints_when_cleanup_fails() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.terminal-fingerprint-cleanup",
        "scenario=terminal-fingerprint-cleanup",
        Seed::from_u64(0x5a11_da12),
    );
    let genesis = Configuration::genesis(scenario);
    let node = crucible::NodeId {
        name: String::from("cleanup-node"),
    };
    let lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: true,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed =
        QemuObservedFreshAttemptLifecycle::new(lifecycle, vec![node], evidence.clone());
    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis,
            control: Vec::new(),
        })
        .expect("admitted quantum");
    observed
        .prepare_terminal_fingerprints()
        .expect("stage terminal fingerprints");

    observed
        .shutdown()
        .expect_err("injected cleanup failure must remain observable");

    let snapshot = evidence.snapshot().expect("evidence after cleanup failure");
    assert_eq!(snapshot.execution_fingerprints().len(), 2);
    assert_eq!(snapshot.terminal_fingerprints(), None);
}

struct FakeFreshLifecycleFactory {
    order: Arc<Mutex<Vec<&'static str>>>,
    cleanup_error: bool,
    terminal_after_replay: bool,
    checkpoint_ready: bool,
}

struct ContinuationAcceptingFreshLifecycleFactory {
    inner: FakeFreshLifecycleFactory,
    continuations: Arc<Mutex<Vec<(u64, crucible::ContentHash)>>>,
}

struct FingerprintFailingFreshLifecycleFactory {
    inner: FakeFreshLifecycleFactory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedBoundary {
    quanta: u64,
    configuration: crucible::ContentHash,
    events: Vec<SchedulerEventLogEntry>,
}

struct BoundaryCaptureLifecycle {
    configuration: Configuration,
    quanta: u64,
    event_log: EventLog,
    events: Vec<SchedulerEventLogEntry>,
    captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    final_events: Vec<SchedulerEventLogEntry>,
    replay_decisions: VecDeque<Decision>,
}

impl QemuFreshAttemptLifecycleOwner for BoundaryCaptureLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        let at = VirtualTime {
            ticks: self.quanta + 1,
        };
        let append = self.event_log.append_observations_at_boundary(
            std::iter::empty(),
            at,
            SchedulerEvaluationBoundaryKind::Quantum,
        )?;
        self.quanta += 1;
        self.events.extend(append.entries.iter().cloned());
        let configuration = self
            .replay_decisions
            .pop_front()
            .map_or(request.configuration.clone(), |decision| {
                step(&request.configuration, decision)
            });
        Ok(crucible::QuantumOutcome {
            configuration,
            frontier: at,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: append.entries,
            event_log_segment_bytes: append.segment_bytes,
            event_log_segment_text: append.segment_text,
            event_log_segment_hash: append.segment_hash,
            event_log_offset: append.offset,
            scheduler_quiescence: None,
        })
    }

    fn completed_quanta(&self) -> u64 {
        self.quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        Ok(true)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, crucible::SchedulerError>
    {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &Configuration,
        _decision: SelectionDecision,
        _selected: &Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("boundary capture fixture has no selectable requests"),
        })
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, crucible::SchedulerError> {
        self.captured
            .lock()
            .expect("captured boundaries")
            .push(CapturedBoundary {
                quanta: self.quanta,
                configuration: self.configuration.id(),
                events: self.events.clone(),
            });
        let checkpoint = Checkpoint::from_recorded_configuration(
            &self.configuration,
            None,
            VirtualTime { ticks: self.quanta },
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(|error| crucible::SchedulerError::BoundaryViolation {
            message: error.to_string(),
        })?;
        let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
            .map_err(|error| crucible::SchedulerError::BoundaryViolation {
                message: error.to_string(),
            })?;
        let byte = u8::try_from(self.quanta).unwrap_or(0xff);
        Ok(
            crate::CapturedExactCheckpoint::new(snapshot, BlobHandle::from_bytes(vec![byte; 512]))
                .into(),
        )
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("boundary capture fixture has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(
        &mut self,
        node: NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        Ok(crucible::FingerprintSample {
            fingerprint: crucible::ExecutionFingerprint {
                hash: crucible::ContentHash::from_bytes(node.name.as_bytes()),
            },
            node,
            at: VirtualTime { ticks: self.quanta },
        })
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        Ok(std::mem::take(&mut self.final_events))
    }
}

struct BoundaryCaptureLifecycleFactory {
    captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    final_events: Vec<SchedulerEventLogEntry>,
    replay_decisions: VecDeque<Decision>,
}

struct SequencedBoundaryCaptureLifecycleFactory {
    captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    final_events: VecDeque<Vec<SchedulerEventLogEntry>>,
    replay_decisions: VecDeque<Decision>,
}

impl QemuFreshAttemptLifecycleFactory for BoundaryCaptureLifecycleFactory {
    type Lifecycle = BoundaryCaptureLifecycle;
    type Error = Infallible;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        Ok(BoundaryCaptureLifecycle {
            configuration: start.clone(),
            quanta: 0,
            event_log: EventLog::new(),
            events: Vec::new(),
            captured: Arc::clone(&self.captured),
            final_events: self.final_events.clone(),
            replay_decisions: self.replay_decisions.clone(),
        })
    }
}

impl QemuFreshAttemptLifecycleFactory for SequencedBoundaryCaptureLifecycleFactory {
    type Lifecycle = BoundaryCaptureLifecycle;
    type Error = Infallible;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let final_events = self
            .final_events
            .pop_front()
            .expect("sequenced boundary fixture has one event log per replay");
        Ok(BoundaryCaptureLifecycle {
            configuration: start.clone(),
            quanta: 0,
            event_log: EventLog::new(),
            events: Vec::new(),
            captured: Arc::clone(&self.captured),
            final_events,
            replay_decisions: self.replay_decisions.clone(),
        })
    }
}

impl QemuFreshAttemptLifecycleFactory for FakeFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &crucible::ScenarioDefForm,
        _start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("begin");
        Ok(FakeFreshLifecycle {
            order: Arc::clone(&self.order),
            completed_quanta: 0,
            promotion_observations: None,
            cleanup_error: self.cleanup_error,
            pending: Vec::new(),
            replies: Arc::new(Mutex::new(Vec::new())),
            signal_fault_branches: signal_fault_replay.branches().iter().cloned().collect(),
            terminal_after_replay: self.terminal_after_replay,
            checkpoint_ready: self.checkpoint_ready,
            fingerprint_error: false,
            fingerprint_node_override: Arc::new(Mutex::new(None)),
        })
    }
}

impl QemuFreshAttemptLifecycleFactory for ContinuationAcceptingFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn configure_attempt_continuations(
        &mut self,
        continuations: &[crate::QemuAttemptContinuation<'_>],
    ) -> bool {
        self.continuations
            .lock()
            .expect("accepted continuation trace")
            .extend(continuations.iter().map(|continuation| {
                (
                    continuation.input().source_frontier_ticks(),
                    continuation.source().id(),
                )
            }));
        true
    }

    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &crucible::ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.inner
            .start_fresh_lifecycle(scenario, source, start, signal_fault_replay, context)
    }
}

impl QemuFreshAttemptLifecycleFactory for FingerprintFailingFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &crucible::ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let mut lifecycle = self.inner.start_fresh_lifecycle(
            scenario,
            source,
            start,
            signal_fault_replay,
            context,
        )?;
        lifecycle.fingerprint_error = true;
        Ok(lifecycle)
    }
}

struct PromotionRecordingFreshLifecycleFactory {
    order: Arc<Mutex<Vec<&'static str>>>,
    observed: Arc<Mutex<Vec<bool>>>,
}

impl QemuFreshAttemptLifecycleFactory for PromotionRecordingFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &crucible::ScenarioDefForm,
        _start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("begin");
        Ok(FakeFreshLifecycle {
            order: Arc::clone(&self.order),
            completed_quanta: 0,
            promotion_observations: Some(Arc::clone(&self.observed)),
            cleanup_error: false,
            pending: Vec::new(),
            replies: Arc::new(Mutex::new(Vec::new())),
            signal_fault_branches: signal_fault_replay.branches().iter().cloned().collect(),
            terminal_after_replay: false,
            checkpoint_ready: true,
            fingerprint_error: false,
            fingerprint_node_override: Arc::new(Mutex::new(None)),
        })
    }
}

struct FakeGenesisCheckpointLifecycle {
    order: Arc<Mutex<Vec<&'static str>>>,
    capture: Option<CapturedAttemptCheckpoint>,
    launch_profiles: Vec<ProductionVmNodeReplayLaunchProfile>,
    checkpoint_ready: bool,
    cleanup_error: bool,
}

impl QemuFreshAttemptLifecycleOwner for FakeGenesisCheckpointLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        panic!("fresh genesis capture must not enable signal-fault promotion");
    }

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        unreachable!("fresh genesis capture performs no modeled quantum")
    }

    fn completed_quanta(&self) -> u64 {
        0
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("ready");
        Ok(self.checkpoint_ready)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, crucible::SchedulerError>
    {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("genesis checkpoint fixture has no selectable transport"),
        })
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("capture");
        self.capture
            .take()
            .ok_or_else(|| crucible::SchedulerError::BoundaryViolation {
                message: String::from("genesis checkpoint fixture was already consumed"),
            })
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("profiles");
        Ok(self.launch_profiles.clone())
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("genesis capture fixture has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("shutdown");
        if self.cleanup_error {
            Err(crucible::SchedulerError::BoundaryViolation {
                message: String::from("injected genesis capture cleanup failure"),
            })
        } else {
            Ok(Vec::new())
        }
    }
}

struct FakeGenesisCheckpointLifecycleFactory {
    order: Arc<Mutex<Vec<&'static str>>>,
    capture: Option<CapturedAttemptCheckpoint>,
    foreign_capture: bool,
    checkpoint_ready: bool,
    cleanup_error: bool,
}

impl QemuFreshAttemptLifecycleFactory for FakeGenesisCheckpointLifecycleFactory {
    type Lifecycle = FakeGenesisCheckpointLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        source: &crucible::ScenarioDefForm,
        start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("begin");
        let configuration = if self.foreign_capture {
            Configuration::genesis(ScenarioDef::from_canonical_material(
                "crucible.test.foreign-genesis-capture",
                "foreign",
            ))
        } else {
            start.clone()
        };
        let launch_profiles = source
            .world()
            .vm_nodes()
            .iter()
            .map(|node| {
                ProductionVmNodeReplayLaunchProfile::new(
                    node.id.clone(),
                    QemuLiveNodeStepGateConfig::new(
                        "qemu",
                        "plugin",
                        "kernel",
                        "firmware",
                        format!("run-{}", node.id.name),
                    ),
                )
            })
            .collect();
        let capture = self
            .capture
            .take()
            .unwrap_or_else(|| test_checkpoint_capture_for_configuration(&configuration).into());
        Ok(FakeGenesisCheckpointLifecycle {
            order: Arc::clone(&self.order),
            capture: Some(capture),
            launch_profiles,
            checkpoint_ready: self.checkpoint_ready,
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

struct UnsolicitedCheckpointDriver;

struct OrderingCheckpointHandoff {
    order: Arc<Mutex<Vec<&'static str>>>,
    checkpoints: ExactCheckpointStore,
}

struct PanickingCheckpointHandoff;

impl std::fmt::Debug for PanickingCheckpointHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PanickingCheckpointHandoff")
    }
}

impl AttemptCheckpointHandoff for PanickingCheckpointHandoff {
    fn prepare_and_stage(
        &self,
        _capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        panic!("injected panic after production capture")
    }
}

impl std::fmt::Debug for OrderingCheckpointHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrderingCheckpointHandoff")
            .finish_non_exhaustive()
    }
}

impl AttemptCheckpointHandoff for OrderingCheckpointHandoff {
    fn prepare_and_stage(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        let prepared = self
            .checkpoints
            .prepare_attempt_checkpoint(capture.reopenable_copy())
            .map_err(|_| CheckpointHandoffFailure::Terminal)?;
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("stage");
        Ok(prepared)
    }
}

impl QemuFreshAttemptDriver for UnsolicitedCheckpointDriver {
    type Pending = ();
    type Error = &'static str;

    fn drive(
        &mut self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        Ok(QemuFreshDriveOutcome::CheckpointRequested)
    }

    fn seal(
        &mut self,
        _pending: Self::Pending,
        _final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        unreachable!("an unsolicited checkpoint never reaches result sealing")
    }
}

impl QemuFreshAttemptDriver for FakeFreshDriver {
    type Pending = &'static str;
    type Error = &'static str;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        _materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
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
        if context.checkpoint_request().is_requested() {
            return Ok(QemuFreshDriveOutcome::CheckpointRequested);
        }
        match self.failure {
            None => Ok(QemuFreshDriveOutcome::Observation("pending modeled result")),
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

struct AbsentSelectedSourceResume {
    authentications: Arc<AtomicUsize>,
    authentication_failure: Option<&'static str>,
}

impl CrucibleExecutionRunner for AbsentSelectedSourceResume {
    type Error = &'static str;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("selected source absence must route to cold execution")
    }
}

impl QemuSelectedOriginResumeRunner for AbsentSelectedSourceResume {
    fn authenticate_selected_resume_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        assert!(matches!(
            input.start(),
            CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ));
        assert!(context.resume_checkpoint().is_some());
        self.authentications.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.authentication_failure {
            return Err(AttemptWorkerFailure::Terminal(error));
        }
        Ok(None)
    }

    fn execute_verified_selected_origin(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _proof: QemuSavepointReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("an absent selected source has no physical execution path")
    }
}

impl crate::QemuOrdinaryResumeRunner for AbsentSelectedSourceResume {
    fn execute_verified_attempt_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _proof: crate::QemuAttemptStartReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("absent selected-source fixture must not resume an ordinary attempt")
    }
}

#[test]
fn router_cold_executes_an_initial_selected_origin_when_its_source_is_absent() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: None,
        },
    );
    let (input, source_attempt, source_checkpoint) = selected_after_genesis_input();
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xa1),
        request: campaign_fact_id(0xa2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xa3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let outcome = router
        .execute(&input, &context)
        .expect("absent initial selected source should cold execute");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Failed)
            .expect("reconcile the initial selected cold route"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert!(matches!(
        router.reconcile_execution(AttemptExecutionDisposition::Failed),
        Err(AttemptWorkerFailure::Terminal(
            QemuAttemptExecutionRouterError::NoPendingReconciliation
        ))
    ));
}

#[test]
fn router_cold_executes_continuation_control_after_authenticating_exact_source() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let continuations = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::clone(&continuations),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: None,
        },
    );
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, source_attempt, source_checkpoint) =
        selected_after_genesis_input_with_continuation(Some(continuation));
    let source = input.start().configuration().id();
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xa1),
        request: campaign_fact_id(0xa2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xa3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let outcome = router
        .execute(&input, &context)
        .expect("controlled continuation should cold execute");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert_eq!(
        continuations
            .lock()
            .expect("accepted continuation trace")
            .as_slice(),
        [(1, source)]
    );
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Failed)
            .expect("reconcile the controlled cold route"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn router_cold_replays_each_control_in_a_two_generation_continuation_chain() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let continuations = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::clone(&continuations),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: None,
        },
    );
    let (input, source_attempt, source_checkpoint, expected_controls) =
        selected_after_two_controlled_generations();
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xb1),
        request: campaign_fact_id(0xb2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xb3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let outcome = router
        .execute(&input, &context)
        .expect("two controlled generations should cold replay in order");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert_eq!(
        continuations
            .lock()
            .expect("accepted continuation trace")
            .as_slice(),
        expected_controls
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn private_fresh_replay_can_preserve_descendant_continuation_controls() {
    let (source, _, _, expected_controls) = selected_after_two_controlled_generations();
    let candidate = source.start().configuration().clone();
    let candidate_artifact =
        test_reached_configuration_artifact(&source, &candidate, b"finding-replay-candidate");
    let replay = source
        .for_finding_replay(
            source.scenario().clone(),
            candidate_artifact,
            candidate.clone(),
            crucible::SignalFaultCampaignReplayPlan::empty(candidate),
        )
        .unwrap_or_else(|error| panic!("private finding candidate should replay: {error}"));

    let controls = validated_attempt_continuations(&replay)
        .unwrap_or_else(|()| panic!("private replay continuation controls should validate"));
    let actual = controls
        .iter()
        .map(|control| {
            (
                control.input().source_frontier_ticks(),
                control.source().id(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(actual, expected_controls);
}

#[test]
fn private_fresh_replay_rejects_a_candidate_shorter_than_its_descendant_controls() {
    let (source, _, _, _) = selected_after_two_controlled_generations();
    let full = source.start().configuration();
    let shortened = Configuration {
        def: full.def.clone(),
        schedule: full
            .schedule
            .prefix(1)
            .unwrap_or_else(|error| panic!("first controlled prefix should exist: {error}")),
    };
    let candidate_artifact =
        test_reached_configuration_artifact(&source, &shortened, b"short-finding-replay-candidate");
    let replay = source.for_finding_replay(
        source.scenario().clone(),
        candidate_artifact,
        shortened.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(shortened),
    );

    assert!(matches!(
        replay,
        Err(crucible_campaign::CampaignCodecError::InvalidValue {
            reason: "finding replay candidate ends before a controlled source boundary"
        })
    ));
}

#[test]
fn router_rejects_invalid_exact_source_before_cold_continuation_allocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::new(Mutex::new(Vec::new())),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: Some("invalid exact continuation source"),
        },
    );
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, source_attempt, source_checkpoint) =
        selected_after_genesis_input_with_continuation(Some(continuation));
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xa1),
        request: campaign_fact_id(0xa2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xa3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let error = router
        .execute(&input, &context)
        .expect_err("invalid exact source must reject cold continuation");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuAttemptExecutionRouterError::Resume(
            "invalid exact continuation source"
        ))
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_captures_a_sticky_checkpoint_before_shutdown_and_seal() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_directory = tempfile::tempdir().expect("checkpoint handoff directory");
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "fresh-runner-checkpoint-handoff",
        checkpoint_directory.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
        .expect("checkpoint handoff store");
    let checkpoint_scenario = test_checkpoint_capture()
        .snapshot()
        .checkpoint()
        .scenario_ref;
    let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
        order: Arc::clone(&order),
        checkpoints,
    }));
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_checkpoint_handoff(checkpoint_scenario, Some(handoff));

    let outcome = runner
        .execute(&fresh_runner_input(), &context)
        .expect("fresh execution should capture the requested checkpoint");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "capture", "stage", "shutdown"]
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn savepoint_captures_same_start_at_q100_and_q200_as_distinct_physical_prefixes() {
    fn capture_at(
        quanta: u64,
        label: &[u8],
        captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    ) -> ExactCheckpointId {
        let input = fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(quanta));
        let AttemptStart::Discover { configuration } = input.attempt().start() else {
            panic!("savepoint fixture must begin with discovery")
        };
        let request = CampaignFactId::parse(&format!(
            "crucible.campaign.fact@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 11, label)
        ))
        .expect("capture request ID");
        let mut runner = QemuFreshExecutionRunner::new(
            BoundaryCaptureLifecycleFactory {
                captured,
                final_events: Vec::new(),
                replay_decisions: VecDeque::new(),
            },
            QemuFreshModeledDriver::new(),
        );
        let checkpoint_directory = tempfile::tempdir().expect("savepoint checkpoint directory");
        let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(
            DirectoryBlobBackend::new("savepoint-checkpoint-handoff", checkpoint_directory.path()),
        );
        let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
            .expect("savepoint checkpoint store");
        let order = Arc::new(Mutex::new(Vec::new()));
        let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
            order,
            checkpoints,
        }));
        let checkpoint_request = ExecutionCheckpointRequest::default();
        checkpoint_request.request_for_test();
        let context = AttemptExecutionContext::new(
            resources(250),
            ExecutionRetentionIntent::RetainAlways,
            ExecutionCancellation::default(),
            checkpoint_request,
        )
        .with_start_mode(AttemptStartMode::SavepointCapture {
            request,
            configuration,
        })
        .with_checkpoint_handoff(input.scenario().scenario_def().id(), Some(handoff));

        let outcome = runner
            .execute(&input, &context)
            .expect("savepoint capture reaches exact quanta boundary");
        let (product, _) = outcome.into_parts();
        let AttemptExecutionProduct::ExactCheckpoint(checkpoint) = product else {
            panic!("savepoint capture must return an exact checkpoint")
        };
        let AttemptCheckpointResultState::Prepared(checkpoint) = checkpoint.into_state() else {
            panic!("runner handoff must prepare the exact root before return")
        };
        checkpoint.root()
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let q100 = capture_at(100, b"savepoint-q100", Arc::clone(&captured));
    let q200 = capture_at(200, b"savepoint-q200", Arc::clone(&captured));
    let captured = captured.lock().expect("captured boundary records");

    assert_ne!(q100, q200);
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].quanta, 100);
    assert_eq!(captured[1].quanta, 200);
    assert_eq!(captured[0].configuration, captured[1].configuration);
    assert_eq!(captured[0].events.len(), 100);
    assert_eq!(captured[1].events.len(), 200);
    assert_eq!(captured[0].events, captured[1].events[..100]);
    assert_ne!(captured[0].events, captured[1].events);
}

#[test]
fn fresh_runner_capture_mode_returns_the_materialized_start_without_driving() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_directory = tempfile::tempdir().expect("checkpoint handoff directory");
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "materialized-start-checkpoint-handoff",
        checkpoint_directory.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
        .expect("checkpoint handoff store");
    let checkpoint_scenario = test_checkpoint_capture()
        .snapshot()
        .checkpoint()
        .scenario_ref;
    let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
        order: Arc::clone(&order),
        checkpoints,
    }));
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let input = fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration })
    .with_checkpoint_handoff(checkpoint_scenario, Some(handoff));

    let outcome = runner
        .execute(&input, &context)
        .expect("capture mode should return the exact materialized start");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "capture", "stage", "shutdown"]
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn fresh_runner_capture_mode_preserves_a_terminal_property_boundary() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: true,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_directory = tempfile::tempdir().expect("checkpoint handoff directory");
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "terminal-materialized-start-checkpoint-handoff",
        checkpoint_directory.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
        .expect("checkpoint handoff store");
    let checkpoint_scenario = test_checkpoint_capture()
        .snapshot()
        .checkpoint()
        .scenario_ref;
    let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
        order: Arc::clone(&order),
        checkpoints,
    }));
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let input = non_genesis_fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration })
    .with_checkpoint_handoff(checkpoint_scenario, Some(handoff));

    let outcome = runner
        .execute(&input, &context)
        .expect("checkpoint-ready property boundary must remain capturable");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        [
            "begin",
            "replay",
            "terminal-cause",
            "capture",
            "stage",
            "shutdown"
        ]
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn fresh_runner_capture_mode_rejects_a_terminal_boundary_that_is_not_checkpoint_ready() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: true,
            checkpoint_ready: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let input = non_genesis_fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration });

    let error = runner
        .execute(&input, &context)
        .expect_err("unsafe terminal materialization must not be captured");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::CaptureStartNotCheckpointReady
        )
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn fresh_runner_capture_mode_requires_a_prelatched_checkpoint_request() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = fresh_runner_context()
        .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration });

    let error = runner
        .execute(&input, &context)
        .expect_err("capture mode without a prelatched request must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::CaptureCheckpointNotRequested
        )
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_opts_only_next_choice_attempts_into_live_signal_promotion() {
    for (stop, expected) in [
        (StopCondition::Terminal, false),
        (StopCondition::NextChoice, true),
    ] {
        let order = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut runner = QemuFreshExecutionRunner::new(
            PromotionRecordingFreshLifecycleFactory {
                order: Arc::clone(&order),
                observed: Arc::clone(&observed),
            },
            FakeFreshDriver {
                order,
                failure: None,
            },
        );

        runner
            .execute(&fresh_runner_input_for_stop(stop), &fresh_runner_context())
            .expect("fresh runner promotion admission");

        let observed = observed.lock().expect("promotion observations");
        if expected {
            assert_eq!(observed.as_slice(), [true]);
        } else {
            assert!(observed.is_empty());
        }
    }
}

#[test]
fn fresh_runner_enables_live_signal_promotion_after_start_materialization() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        PromotionRecordingFreshLifecycleFactory {
            order: Arc::clone(&order),
            observed: Arc::clone(&observed),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input_with_decisions_for_stop(
        vec![Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        })],
        StopCondition::NextChoice,
    );

    runner
        .execute(&input, &fresh_runner_context())
        .expect("fresh runner should activate promotion after replay");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "promotion", "drive", "shutdown", "seal"]
    );
    assert_eq!(
        observed.lock().expect("promotion observations").as_slice(),
        [true]
    );
}

#[test]
fn fresh_genesis_checkpoint_capture_uses_no_modeled_quantum_and_tears_down() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: false,
        checkpoint_ready: true,
        cleanup_error: false,
    };

    let capture = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect("fresh genesis capture should succeed");

    assert_eq!(
        capture.configuration(),
        Configuration::genesis(input.scenario().scenario_def()).id()
    );
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "profiles", "shutdown"]
    );
}

#[test]
fn fresh_genesis_checkpoint_capture_rejects_foreign_basis_after_teardown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: true,
        checkpoint_ready: true,
        cleanup_error: false,
    };

    let error = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect_err("foreign genesis capture must fail closed");

    assert!(matches!(
        error,
        QemuFreshGenesisCheckpointError::Capture(
            QemuFreshGenesisCheckpointCaptureFailure::BasisMismatch
        )
    ));
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "shutdown"]
    );
}

#[test]
fn fresh_genesis_checkpoint_capture_preserves_cleanup_precedence() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: true,
        checkpoint_ready: true,
        cleanup_error: true,
    };

    let error = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect_err("cleanup failure must retain precedence");

    assert!(matches!(
        error,
        QemuFreshGenesisCheckpointError::Cleanup {
            prior: Some(prior),
            ..
        } if matches!(
            prior.as_ref(),
            QemuFreshGenesisCheckpointCaptureFailure::BasisMismatch
        )
    ));
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "shutdown"]
    );
}

#[test]
fn production_genesis_capture_quarantines_native_catalog_after_shutdown_error() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let run_state = tempfile::tempdir().expect("production genesis run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production genesis fixture");
    let retirement = fixture.closure().native_retirement();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: Some(CapturedAttemptCheckpoint::from(fixture.closure().clone())),
        foreign_capture: false,
        checkpoint_ready: true,
        cleanup_error: true,
    };

    let error = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        fixture.source(),
        &fresh_runner_context(),
    )
    .expect_err("shutdown failure must quarantine the native catalog");

    assert!(matches!(
        error,
        QemuFreshGenesisCheckpointError::Cleanup {
            retirement: Some(_),
            ..
        }
    ));
    let report = crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
        .expect("catalog remains available to its quarantine owner");
    assert!(report.retired());
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "profiles", "shutdown"]
    );
}

#[test]
fn fresh_runner_quarantines_failed_production_handoff_after_shutdown_error() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let run_state = tempfile::tempdir().expect("production fresh run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production fresh fixture");
    let retirement = fixture.closure().native_retirement();
    let mut runner = QemuFreshExecutionRunner::new(
        FakeGenesisCheckpointLifecycleFactory {
            order: Arc::clone(&order),
            capture: Some(CapturedAttemptCheckpoint::from(fixture.closure().clone())),
            foreign_capture: false,
            checkpoint_ready: true,
            cleanup_error: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = fresh_runner_input();
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_checkpoint_handoff(input.scenario().scenario_def().id(), None);

    let failure = runner
        .execute(&input, &context)
        .expect_err("foreign production capture and failed shutdown must fail closed");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterRunner { .. })
    ));
    let Some(crate::NativeCheckpointCleanup::Quarantine(cleanup)) =
        runner.take_abandoned_native_checkpoint()
    else {
        panic!("failed shutdown must quarantine the captured native catalog")
    };
    let report = crucible_api::retire_production_exact_checkpoint_catalog(&cleanup)
        .expect("test owner releases quarantined production capture");
    assert!(report.retired());
    let repeated = crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
        .expect("repeat shutdown quarantine retirement");
    assert!(!repeated.retired());
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "drive", "ready", "capture", "shutdown"]
    );
}

#[test]
fn fresh_runner_retains_production_quarantine_when_handoff_panics_after_capture() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let run_state = tempfile::tempdir().expect("production panic run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production panic fixture");
    let retirement = fixture.closure().native_retirement();
    let mut runner = QemuFreshExecutionRunner::new(
        FakeGenesisCheckpointLifecycleFactory {
            order: Arc::clone(&order),
            capture: Some(CapturedAttemptCheckpoint::from(fixture.closure().clone())),
            foreign_capture: false,
            checkpoint_ready: true,
            cleanup_error: false,
        },
        FakeFreshDriver {
            order,
            failure: None,
        },
    );
    let input = fresh_runner_input();
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_checkpoint_handoff(
        fixture.closure().scenario(),
        Some(ExecutionCheckpointHandoff::new(Arc::new(
            PanickingCheckpointHandoff,
        ))),
    );

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _outcome = runner.execute(&input, &context);
    }));

    assert!(panicked.is_err());
    let Some(crate::NativeCheckpointCleanup::Quarantine(cleanup)) =
        runner.take_abandoned_native_checkpoint()
    else {
        panic!("unwinding capture must remain in the runner quarantine slot")
    };
    let report = crucible_api::retire_production_exact_checkpoint_catalog(&cleanup)
        .expect("test owner releases panic quarantine");
    assert!(report.retired());
    let repeated = crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
        .expect("repeat panic quarantine retirement");
    assert!(!repeated.retired());
}

#[test]
fn dropping_fresh_runner_moves_in_flight_capture_to_process_quarantine() {
    let run_state = tempfile::tempdir().expect("production drop run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production drop fixture");
    let capture = CapturedAttemptCheckpoint::from(fixture.closure().clone());
    let before = crate::executor_worker::native_checkpoint_process_quarantine_len_for_test();
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeGenesisCheckpointLifecycleFactory {
            order: Arc::clone(&order),
            capture: None,
            foreign_capture: false,
            checkpoint_ready: true,
            cleanup_error: false,
        },
        FakeFreshDriver {
            order,
            failure: None,
        },
    );
    runner.register_native_checkpoint_capture(&capture);

    drop(runner);

    let after = crate::executor_worker::native_checkpoint_process_quarantine_len_for_test();
    assert!(after > before);
}

#[test]
fn production_baked_genesis_rejects_legacy_capture_after_guarded_teardown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: false,
        checkpoint_ready: true,
        cleanup_error: false,
    };

    let error = crate::capture_production_baked_genesis(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect_err("production baked genesis must require a version-four closure");

    assert!(matches!(
        error,
        crate::ProductionBakedGenesisCaptureError::Admission(
            crate::ProductionBakedGenesisCheckpointError::CompatibilityCapture
        )
    ));
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "profiles", "shutdown"]
    );
}

#[test]
fn fresh_runner_rejects_an_unsolicited_checkpoint_before_capture() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        UnsolicitedCheckpointDriver,
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("unsolicited checkpoint capture must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::UnsolicitedCheckpoint)
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "shutdown"]
    );
}

#[test]
fn fresh_runner_seals_only_after_runner_owned_shutdown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
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
fn terminal_evidence_runner_attaches_the_fresh_terminal_world_set_after_shutdown() {
    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(1));
    let factory = BoundaryCaptureLifecycleFactory {
        captured: Arc::new(Mutex::new(Vec::new())),
        final_events: Vec::new(),
        replay_decisions: VecDeque::new(),
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver::new());
    let mut runner = QemuTerminalEvidenceExecutionRunner::new(runner, evidence);

    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("fresh modeled execution with terminal evidence");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("fresh absolute stop must produce a prepared semantic result")
    };
    let terminal = result
        .terminal_fingerprints()
        .expect("prepared fresh terminal fingerprints");
    let expected_nodes = input
        .scenario()
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let retained_nodes = terminal
        .iter()
        .map(|sample| sample.node.clone())
        .collect::<BTreeSet<_>>();

    assert!(!terminal.is_empty());
    assert_eq!(retained_nodes, expected_nodes);
    assert!(terminal.iter().all(|sample| sample.at.ticks == 1));
    result
        .verify_terminal_fingerprints(input.scenario())
        .expect("fresh terminal set must match the authenticated World");
    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
}

fn finding_candidate_artifact(input: &CrucibleAttemptExecution) -> ConfigurationArtifact {
    let scenario = crate::encode_crucible_scenario_artifact(input.scenario())
        .expect("candidate scenario artifact");
    crate::encode_crucible_configuration_artifact(
        &scenario,
        &input.start().configuration().schedule,
    )
    .expect("candidate configuration artifact")
}

fn finding_candidate_input_with_configuration(
    base: &CrucibleAttemptExecution,
    configuration: Configuration,
) -> CrucibleAttemptExecution {
    finding_candidate_input_with_configuration_and_stop(
        base,
        configuration,
        StopCondition::Terminal,
    )
}

fn finding_candidate_input_with_configuration_and_stop(
    base: &CrucibleAttemptExecution,
    configuration: Configuration,
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let scenario = crate::encode_crucible_scenario_artifact(base.scenario())
        .expect("candidate scenario artifact");
    let configuration_artifact =
        crate::encode_crucible_configuration_artifact(&scenario, &configuration.schedule)
            .expect("candidate configuration artifact");
    let lineage = CampaignLineage::new(
        scenario.scenario(),
        scenario.id().expect("candidate scenario content ID"),
        configuration_artifact.configuration(),
        configuration_artifact
            .id()
            .expect("candidate configuration content ID"),
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario.payload_schema(),
        1,
    )
    .expect("candidate campaign lineage");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact
                .id()
                .expect("candidate configuration ID"),
        },
        base.path().id().expect("candidate path ID"),
        stop,
    )
    .expect("candidate attempt");
    CrucibleAttemptExecution::from_test_parts(
        lineage,
        base.scenario().clone(),
        attempt,
        base.path().clone(),
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn owned_finding_candidate(
    input: &CrucibleAttemptExecution,
    discovery: ChoiceDiscovery,
    selection: Selection,
    property: &str,
) -> ObservationCandidate {
    let child = finding_candidate_artifact(input);
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("owned measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        property.to_owned(),
        PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())
            .expect("owned failed property"),
    )]))
    .expect("owned properties");
    let coverage =
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("owned coverage");
    let opportunity = discovery.opportunity().id().expect("opportunity ID");
    let observation = Observation::new(
        input.attempt().id().expect("candidate attempt ID"),
        child.configuration(),
        child.id().expect("candidate child ID"),
        input.path().id().expect("candidate path ID"),
        StopOutcome::AssertionFailure(property.to_owned()),
        measurements.id().expect("owned measurement ID"),
        properties.id().expect("owned property ID"),
        coverage.id().expect("owned coverage ID"),
        BTreeSet::from([opportunity]),
    )
    .expect("owned observation");
    ObservationCandidate::new(
        child,
        measurements,
        properties,
        coverage,
        vec![discovery],
        observation,
    )
    .expect("owned observation candidate")
    .with_produced_selections(vec![selection])
    .expect("owned produced selection")
}

fn assert_composed_candidate_replay_retains_choice_and_measurement(
    input: CrucibleAttemptExecution,
    discovery: ChoiceDiscovery,
    selection: Selection,
    assertion: &AssertionId,
) {
    let (lifecycle_artifacts, lifecycle) = finding_replay_lifecycle_fixture();
    let provisional_candidate = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        crucible::ContentHash::from_bytes(b"composed-exact-candidate"),
        input.scenario(),
        input.start().configuration(),
    )
    .expect("candidate reproduction");
    let owned = owned_finding_candidate(
        &input,
        discovery.clone(),
        selection.clone(),
        assertion.name.as_str(),
    );
    let object_root = lifecycle_artifacts.path().join("objects");
    let graph_root = StoreNodeId::new("composed-exact-candidate").expect("store graph node");
    let (blob_backend, blob_admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: graph_root.clone(),
        admitted_kinds: BTreeSet::from([
            ObjectKind::CampaignFact,
            ObjectKind::CampaignSnapshot,
            ObjectKind::MerkleNode,
            ObjectKind::Scenario,
            ObjectKind::Configuration,
            ObjectKind::Policy,
            ObjectKind::ExactManifest,
            ObjectKind::RamExtent,
            ObjectKind::DiskExtent,
            ObjectKind::DeviceState,
            ObjectKind::Observation,
            ObjectKind::Finding,
            ObjectKind::Projection,
            ObjectKind::Trace,
        ]),
        nodes: BTreeMap::from([(
            graph_root,
            StoreNodeSpec::Directory {
                root: object_root.clone(),
            },
        )]),
    })
    .expect("build composed recovery store graph");
    let blob_backend = Arc::new(blob_backend);
    let ref_backend = Arc::new(DirectoryRefBackend::new(
        lifecycle_artifacts.path().join("refs"),
    ));
    let repository = Arc::new(CampaignRepository::new(
        blob_backend.clone(),
        ref_backend.clone(),
    ));
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let request =
        publish_composed_candidate_input(&repository, &store, &input, &discovery, &selection);
    let final_event = SchedulerEventLogEntry::assertion_state_observation(
        1,
        VirtualTime { ticks: 1 },
        assertion.clone(),
        AssertionPhase::Violated,
    );
    let decisions = input
        .start()
        .configuration()
        .schedule
        .decisions()
        .iter()
        .cloned()
        .collect();
    let production_boundaries = Arc::new(Mutex::new(Vec::new()));
    let mut runner = crate::packaged_qemu_executor::packaged_finding_replay_runner(
        lifecycle.clone(),
        BoundaryCaptureLifecycleFactory {
            captured: Arc::clone(&production_boundaries),
            final_events: vec![final_event],
            replay_decisions: decisions,
        },
    );
    let context = fresh_runner_context();
    let target_signature =
        crate::automatic_finding_runner::automatic_finding_signature(&input, &owned)
            .expect("candidate target signature")
            .expect("failed-property target signature");

    let outcome = crate::automatic_finding_runner::replay_candidate(
        &store,
        &mut runner,
        &input,
        &provisional_candidate,
        &owned,
        &target_signature,
        &context,
    )
    .expect("composed exact candidate replay");
    let AutomaticFindingReplayOutcome::Observed {
        evidence,
        measurement_replay_evidence,
        ..
    } = &outcome
    else {
        panic!("exact candidate must reach its semantic boundary")
    };
    assert!(evidence.signature().is_some());
    assert_eq!(evidence.opportunities(), &[discovery.opportunity().clone()]);
    assert_eq!(evidence.selections(), &[selection]);
    assert_eq!(measurement_replay_evidence.len(), 1);
    assert_eq!(
        measurement_replay_evidence[0].configuration(),
        evidence.configuration().configuration()
    );
    let triage = outcome
        .triage_evidence()
        .expect("exact property replay must retain full triage evidence");
    assert_eq!(triage.finding(), &provisional_candidate);
    assert!(matches!(
        triage.failure(),
        crucible::FailureClusterReportFailure::Property(_)
    ));
    assert!(!triage.causal_entries().is_empty());
    assert!(triage.recorded_event_frames().is_empty());

    let signature = outcome
        .signature()
        .expect("exact property replay signature")
        .clone();
    let candidate = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        crucible::ContentHash {
            bytes: signature.fingerprint().as_bytes(),
        },
        input.scenario(),
        input.start().configuration(),
    )
    .expect("signature-bound candidate reproduction");

    let mut transcript = CrucibleFindingReplayTranscript::new();
    transcript
        .record_minimization_outcome(&provisional_candidate, outcome.clone())
        .expect("journal composed minimization replay");
    transcript
        .record_verification_outcome(&provisional_candidate, outcome)
        .expect("journal composed verification replay");

    let minimization_target = signature.clone();
    let prepared = crate::prepare_automatic_signature_preserving_finding_with_outcomes(
        PreparedSemanticAttemptResult::new(owned.clone(), None)
            .expect("prepared composed observation"),
        signature,
        &candidate,
        FindingExactPins::default(),
        Seed::from_bytes([0x75; 32]),
        |replay_candidate| {
            let decisions = replay_candidate
                .artifact
                .schedule()
                .decisions()
                .iter()
                .cloned()
                .collect::<VecDeque<_>>();
            let boundary = u64::try_from(decisions.len()).expect("candidate event sequence");
            let final_event = SchedulerEventLogEntry::assertion_state_observation(
                boundary,
                VirtualTime { ticks: boundary },
                assertion.clone(),
                AssertionPhase::Violated,
            );
            let mut replay_runner = crate::packaged_qemu_executor::packaged_finding_replay_runner(
                lifecycle.clone(),
                BoundaryCaptureLifecycleFactory {
                    captured: Arc::clone(&production_boundaries),
                    final_events: vec![final_event],
                    replay_decisions: decisions,
                },
            );
            Ok(crate::automatic_finding_runner::replay_candidate(
                &store,
                &mut replay_runner,
                &input,
                replay_candidate,
                &owned,
                &minimization_target,
                &context,
            )
            .expect("production candidate replay during automatic minimization"))
        },
    )
    .expect("prepare production rich finding closure");
    let capture_inputs = prepared
        .production_replay_capture_inputs()
        .expect("encode production replay captures")
        .expect("packaged runner must retain production replay captures");
    assert!(matches!(
        prepared.canonical_bytes(),
        Err(crate::PreparedSemanticResultCodecError::Inconsistent {
            component: "unbound finding production replay captures"
        })
    ));
    assert!(
        capture_inputs
            .iter()
            .all(|capture| matches!(capture, crate::FindingReplayCaptureInput::Complete { .. }))
    );
    let durable_captures = FindingReplayCaptureStore::prepare_set(capture_inputs)
        .expect("prepare production replay capture closure");
    let capture_references = durable_captures.references();
    let guard = store
        .acquire_finding_replay_publication_guard()
        .expect("exclude GC while publishing production replay captures");
    FindingReplayCaptureStore::publish_set(&guard, &durable_captures)
        .expect("publish production replay capture closure");

    let bound_finding = prepared
        .prepare_bound_production_replay_finding(capture_references)
        .expect("bind production replay manifests to finding");
    let mut prepared = prepared;
    prepared.commit_bound_production_replay_finding(bound_finding);

    let durable_bytes = prepared
        .canonical_bytes()
        .expect("encode rich prepared result");
    assert_eq!(
        crate::crucible_artifact::PreparedSemanticResultVersion::from_payload(&durable_bytes),
        Some(crate::crucible_artifact::PreparedSemanticResultVersion::V6)
    );
    let expected_observation = prepared
        .observation()
        .observation()
        .id()
        .expect("prepared observation ID");
    let expected_finding = prepared
        .finding()
        .expect("prepared V6 finding")
        .id()
        .expect("prepared V6 finding ID");
    let key = crate::AttemptExecutionKey::new(
        input.lineage().id().expect("candidate lineage ID"),
        input.attempt().id().expect("candidate attempt ID"),
    );
    let producer_execution = ExecutionId::from_bytes([0x77; 16]).expect("producer execution ID");
    let ledger_root = lifecycle_artifacts.path().join("ledger");
    fs::create_dir(&ledger_root).expect("create assignment ledger directory");
    let mut producer_ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("open producer assignment ledger");
    assert_eq!(
        producer_ledger
            .compare_exchange_attempt(
                key,
                None,
                Some(AttemptRuntimeState::Publishing {
                    execution_basis: request.execution_basis_digest(),
                    origin: AttemptExecutionOrigin::Initial,
                    daemon_epoch: DaemonEpoch::from_bytes([0x78; 16])
                        .expect("producer daemon epoch"),
                    execution: producer_execution,
                    observation: expected_observation,
                    finding_candidate: Some(expected_finding),
                    finding_replay_captures: Some(capture_references),
                    finding_exact_retention_roots: [None; 3],
                    prepared_result_digest: None,
                }),
            )
            .expect("stage production replay capture roots before journaling"),
        AttemptStateCas::Advanced
    );
    drop(guard);
    drop(producer_ledger);

    let journal_namespace = lifecycle_artifacts.path().join("journals");
    fs::create_dir(&journal_namespace).expect("create prepared-result journal namespace");
    let (journal, disposition) = DirectoryPreparedResultJournal::create(
        &journal_namespace,
        key,
        producer_execution,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        prepared,
    )
    .expect("create V6 prepared-result journal");
    assert_eq!(
        disposition,
        crate::PreparedResultJournalCreateDisposition::Created
    );
    drop(journal);
    let production_boundaries_before_restart = production_boundaries
        .lock()
        .expect("production replay boundaries")
        .len();
    let capture_manifest = capture_references
        .minimization_original()
        .evidence()
        .expect("complete minimization-original manifest")
        .content_id();
    let manifest_bytes = blob_backend
        .read(capture_manifest, None)
        .expect("load persisted production replay manifest")
        .read_all(64 * 1024)
        .expect("read persisted production replay manifest");
    let manifest = ContentEnvelope::from_canonical_bytes(&manifest_bytes)
        .expect("decode persisted production replay manifest");
    let capture_roots = capture_references
        .references()
        .into_iter()
        .filter_map(crucible_campaign::FindingReplayCaptureReference::evidence)
        .map(|evidence| evidence.content_id());
    let persisted_capture_closure = repository
        .authenticated_closure_ids(capture_roots)
        .expect("authenticate every persisted production replay capture closure");

    let mut restarted_ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen assignment ledger");
    let gc_plan = plan_single_host_campaign_gc(
        &repository,
        ref_backend.as_ref(),
        &mut restarted_ledger,
        None,
        None,
        &blob_admin,
    )
    .expect("plan GC between V6 journal durability and candidate publication");
    assert!(
        gc_plan
            .candidates()
            .iter()
            .all(|candidate| !persisted_capture_closure.contains(&candidate.id()))
    );
    let (mut gc_journal, _) =
        DirectoryCampaignGcJournal::create(lifecycle_artifacts.path().join("gc-journal"), &gc_plan)
            .expect("journal pre-publication GC plan");
    apply_single_host_campaign_gc(
        &mut gc_journal,
        &repository,
        ref_backend.as_ref(),
        &mut restarted_ledger,
        None,
        None,
        &blob_admin,
    )
    .expect("apply GC between V6 journal durability and candidate publication");
    let retained_capture_closure = repository
        .authenticated_closure_ids(
            capture_references
                .references()
                .into_iter()
                .filter_map(crucible_campaign::FindingReplayCaptureReference::evidence)
                .map(|evidence| evidence.content_id()),
        )
        .expect("reauthenticate every capture closure after pre-publication GC");
    assert_eq!(retained_capture_closure, persisted_capture_closure);

    let mut supervisor = LocalExecutorSupervisor::new(
        restarted_ledger,
        UnavailableCompletionAdmission,
        request.daemon_epoch(),
        ExecutorCapacity::new(1, 2, 64 * 1024 * 1024, 128 * 1024 * 1024, 64)
            .expect("recovery executor capacity"),
    );
    let response = supervisor
        .submit_attempt(&request)
        .expect("admit restarted V6 attempt");
    let SubmitAttemptDisposition::Accepted {
        execution: recovery_execution,
    } = response.disposition()
    else {
        panic!("restarted V6 attempt must be accepted: {response:?}");
    };
    assert_ne!(recovery_execution, producer_execution);
    let queued = supervisor.next_queued().expect("queued V6 recovery");

    let missing_chunk = manifest
        .children()
        .first()
        .expect("production replay manifest has one chunk")
        .id();
    fs::remove_file(directory_blob_object_path(
        &lifecycle_artifacts.path().join("objects"),
        missing_chunk,
    ))
    .expect("remove one persisted production replay chunk");
    let failed_recovery = crate::recover_prepared_attempt_result(
        &store,
        &journal_namespace,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        queued,
    )
    .expect_err("missing capture chunk must fail V6 recovery");
    assert!(matches!(
        failed_recovery.source,
        AttemptResultRecoveryFailure::CaptureStore(_)
    ));
    assert!(
        repository
            .load_finding_candidate_bundle(expected_finding)
            .is_err()
    );

    let guard = store
        .acquire_finding_replay_publication_guard()
        .expect("exclude GC while restoring missing capture chunk");
    FindingReplayCaptureStore::publish_set(&guard, &durable_captures)
        .expect("restore production replay capture closure");
    drop(guard);

    let capture_chunk_path =
        directory_blob_object_path(&lifecycle_artifacts.path().join("objects"), missing_chunk);
    let mut corrupt_chunk_bytes =
        fs::read(&capture_chunk_path).expect("read restored production replay chunk");
    *corrupt_chunk_bytes
        .first_mut()
        .expect("production replay chunk must not be empty") ^= 0xff;
    fs::write(&capture_chunk_path, corrupt_chunk_bytes)
        .expect("corrupt one persisted production replay chunk");
    let failed_recovery = crate::recover_prepared_attempt_result(
        &store,
        &journal_namespace,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        *failed_recovery.queued,
    )
    .expect_err("corrupt capture chunk must fail V6 recovery");
    assert!(matches!(
        failed_recovery.source,
        AttemptResultRecoveryFailure::CaptureStore(_)
    ));
    assert!(
        repository
            .load_finding_candidate_bundle(expected_finding)
            .is_err()
    );
    assert_eq!(
        production_boundaries
            .lock()
            .expect("production replay boundaries after corrupt recovery")
            .len(),
        production_boundaries_before_restart,
        "corrupt journal recovery must not execute another production lifecycle"
    );

    fs::remove_file(&capture_chunk_path).expect("remove corrupt production replay chunk");
    let guard = store
        .acquire_finding_replay_publication_guard()
        .expect("exclude GC while replacing corrupt capture chunk");
    FindingReplayCaptureStore::publish_set(&guard, &durable_captures)
        .expect("replace corrupt production replay capture closure");
    drop(guard);

    let recovered = crate::recover_prepared_attempt_result(
        &store,
        &journal_namespace,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        *failed_recovery.queued,
    )
    .expect("recover authenticated V6 prepared result after restart");
    let PreparedAttemptRecoveryOutcome::Prepared(prepared) = recovered else {
        panic!("complete V6 journal must recover without guest execution");
    };
    assert_eq!(
        production_boundaries
            .lock()
            .expect("production replay boundaries after restart")
            .len(),
        production_boundaries_before_restart,
        "journal recovery must not execute another production lifecycle"
    );
    let finding = prepared.result().finding().expect("recovered rich finding");
    let triage_ids = finding
        .bundle()
        .triage_evidence()
        .expect("candidate bundle v3 triage evidence");
    assert_eq!(finding.bundle().schema_version(), 3);
    assert_eq!(
        triage_ids.minimization_original(),
        triage_ids.verification_original(),
        "independent original replays must retain identical native evidence",
    );
    assert_eq!(
        triage_ids.minimization_selected(),
        triage_ids.verification_selected(),
        "independent selected replays must retain identical native evidence",
    );

    let replay_captures = finding
        .bundle()
        .replay_captures()
        .expect("recovered V6 finding owns production replay manifests");
    assert_eq!(replay_captures, capture_references);
    assert_eq!(
        supervisor
            .stage_observation_finding_and_replay_capture_publication(
                prepared.queued(),
                expected_observation,
                expected_finding,
                capture_references,
            )
            .expect("restage recovered V6 publication roots"),
        ObservationPublicationOutcome::AlreadyStaged
    );

    let staged = crate::stage_prepared_attempt_result(&mut supervisor, *prepared)
        .expect("stage recovered V6 candidate publication");
    let AttemptResultStageOutcome::Publish(staged) = staged else {
        panic!("recovered V6 candidate must require immutable publication");
    };
    assert!(
        repository
            .load_finding_candidate_bundle(expected_finding)
            .is_err()
    );
    let published = crate::publish_prepared_attempt_result(&store, staged)
        .expect("publish recovered V6 candidate");
    assert_eq!(published.finding_candidate(), Some(expected_finding));
    assert!(repository.load_observation(expected_observation).is_ok());
    let durable_bundle = repository
        .load_finding_candidate_bundle(expected_finding)
        .expect("load published V6 finding candidate");
    assert_eq!(durable_bundle.schema_version(), 3);
    assert_eq!(durable_bundle.replay_captures(), Some(capture_references));
}

struct UnavailableCompletionAdmission;

impl AttemptAdmissionValidator for UnavailableCompletionAdmission {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        Ok(())
    }

    fn validate_completion_artifacts(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
        _finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        Err(CompletionValidationFailure::UnavailableInput)
    }
}

fn publish_composed_candidate_input(
    repository: &CampaignRepository,
    store: &CampaignExecutorStore,
    input: &CrucibleAttemptExecution,
    discovery: &ChoiceDiscovery,
    selection: &Selection,
) -> SubmitAttemptRequest {
    const CAMPAIGN: &str = "composed-production-recovery";

    let scenario = crate::encode_crucible_scenario_artifact(input.scenario())
        .expect("encode composed recovery scenario");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .expect("publish composed recovery scenario");
    assert_eq!(
        scenario_content,
        input.lineage().scenario_content(),
        "published scenario must match the execution lineage"
    );

    let configuration = crate::encode_crucible_configuration_artifact(
        &scenario,
        &input.start().configuration().schedule,
    )
    .expect("encode composed recovery configuration");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration.scenario(),
            scenario_content,
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .expect("publish composed recovery configuration");
    assert_eq!(configuration_content, input.lineage().genesis_content());

    store
        .publish_executor_choice_domain(discovery.domain())
        .expect("publish composed recovery choice domain");
    store
        .publish_executor_selectable(discovery.declaration())
        .expect("publish composed recovery selectable");
    store
        .publish_executor_choice_opportunity(discovery.opportunity())
        .expect("publish composed recovery choice opportunity");
    store
        .publish_executor_selection(selection)
        .expect("publish composed recovery selection");

    let policy = CampaignPolicy::new(
        input.lineage().scenario(),
        CampaignSeed::from_bytes([0x74; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 1,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("composed recovery fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("composed recovery campaign policy");
    let created = repository
        .create(CAMPAIGN, input.lineage(), &policy, &BTreeMap::new())
        .expect("create composed recovery campaign");
    let resumed = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"resume-composed-production-recovery",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume composed recovery campaign");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"fund-composed-production-recovery",
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("composed recovery attempt grant"),
                ),
            },
        )
        .expect("fund composed recovery campaign");
    let admitted = repository
        .submit_discovery_request(
            CAMPAIGN,
            &DiscoveryRequest::new(
                CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"discover-composed-production-recovery",
                )),
                funded.new_snapshot,
                configuration_content,
                input.attempt().stop().clone(),
            )
            .expect("composed recovery discovery request"),
        )
        .expect("admit composed recovery attempt");
    let attempt = input.attempt().id().expect("composed recovery attempt ID");
    assert_eq!(admitted.attempt, attempt);

    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x75; 16]).expect("composed recovery assignment"),
        DaemonEpoch::from_bytes([0x76; 16]).expect("composed recovery daemon epoch"),
        input.lineage().id().expect("composed recovery lineage ID"),
        attempt,
        resources(64),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("composed recovery submit request")
}

fn directory_blob_object_path(root: &std::path::Path, id: ContentId) -> std::path::PathBuf {
    let encoded = id.encode();
    let digest = encoded
        .rsplit_once('.')
        .expect("content digest separator")
        .1;
    root.join(id.kind().as_str())
        .join(id.schema_version().to_string())
        .join(&digest[..2])
        .join(digest)
}

fn finding_replay_lifecycle_fixture() -> (tempfile::TempDir, ProductionVmLifecycleConfig) {
    let directory = tempfile::tempdir().expect("finding replay lifecycle fixture");
    let root = directory.path();
    let qemu = root.join("bin/qemu-system-x86_64");
    let plugin = root.join("lib/libcrucible-qemu-plugin.so");
    let kernel = root.join("guest/kernel");
    let root_image = root.join("guest/root.qcow2");
    let qemu_marker = root.join("share/aos/crucible/qemu-build-identity.env");
    let plugin_marker = root.join("nix-support/crucible-qemu-plugin-build-info");

    for path in [
        &qemu,
        &plugin,
        &kernel,
        &root_image,
        &qemu_marker,
        &plugin_marker,
    ] {
        fs::create_dir_all(path.parent().expect("fixture artifact parent"))
            .expect("create finding replay fixture directory");
    }
    fs::write(&qemu, b"authenticated qemu fixture").expect("write QEMU fixture");
    fs::write(&plugin, b"authenticated plugin fixture").expect("write plugin fixture");
    fs::write(&kernel, b"guest kernel fixture").expect("write guest kernel fixture");
    fs::write(&root_image, b"guest root fixture").expect("write guest root fixture");

    let abi_version = crucible::SHMEM_ABI_VERSION;
    let abi = format!("crucible-shmem-abi-v{abi_version}");
    fs::write(
        &qemu_marker,
        format!(
            "qemu_sim_capability=qemu-crucible\n\
             qemu_crucible_patches_applied=true\n\
             qemu_plugins_enabled=true\n\
             qemu_build_id=qemu-build-v1\n\
             qemu_patch_series_hash=sha256:patch\n\
             qemu_shmem_abi_version={abi_version}\n\
             qemu_shmem_abi={abi}\n\
             qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\n\
             qemu_shmem_header_hash=sha256:header\n"
        ),
    )
    .expect("write QEMU identity marker");
    fs::write(
        &plugin_marker,
        format!(
            "plugin_abi={abi}\n\
             qemu_build_id=qemu-build-v1\n\
             shmem_abi_version={abi_version}\n\
             shmem_abi={abi}\n\
             shmem_generated_header_hash=sha256:header\n"
        ),
    )
    .expect("write plugin identity marker");

    let lifecycle =
        ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image, root.join("run-state"));
    (directory, lifecycle)
}

struct NamedSupplementalFindingOracle {
    scenario: ScenarioDefForm,
    source: GuardedCampaignFindingOracleSource,
    truths: SearchScheduleNamedPredicateTruths,
}

impl GuardedCampaignFindingOracle for NamedSupplementalFindingOracle {
    fn source(&self) -> &GuardedCampaignFindingOracleSource {
        &self.source
    }

    fn evaluate(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<GuardedCampaignFindingOracleEvaluation>, GuardedCampaignFindingOracleError>
    {
        crucible::SearchFailureOracle::evaluate_configuration_with_named_predicates(
            &self.scenario,
            configuration,
            &self.truths,
        )
        .map(|finding| finding.map(GuardedCampaignFindingOracleEvaluation::new))
        .map_err(|error| GuardedCampaignFindingOracleError::new(error.to_string()))
    }
}

#[test]
fn automatic_wrapper_retains_supplemental_violation_when_offline_source_also_fails() {
    const PROPERTY: &str = "supplemental-collision";
    const NAMED_PREDICATE: &str = "supplemental-truth";

    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty World");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name(PROPERTY),
            message: String::from("supplemental collision failed"),
            property: Property::Always {
                predicate: Predicate::named(NAMED_PREDICATE),
            },
        }],
    )
    .expect("supplemental collision properties");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &properties,
        Seed::from_u64(0x005a_771e),
    )
    .expect("supplemental collision scenario");
    let input = modeled_fresh_runner_input_for_scenario(
        scenario.clone(),
        StopCondition::ExecutionQuanta(1),
    );
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("supplemental-collision"),
        value: 1,
    });
    let finding_configuration = step(input.start().configuration(), decision.clone());
    let source = GuardedCampaignFindingOracleSource::new(
        ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes)),
        "application/vnd.crucible.test-named-truth+binary",
        b"supplemental-truth=false".to_vec(),
    )
    .expect("supplemental source");
    let source_id = source.content_id();
    let oracle = Arc::new(NamedSupplementalFindingOracle {
        scenario: scenario.clone(),
        source,
        truths: SearchScheduleNamedPredicateTruths::new().with_truth(
            SearchScheduleNamedPredicateKey::new(NAMED_PREDICATE, Vec::new()),
            false,
        ),
    });
    let expected_finding = oracle
        .evaluate(&finding_configuration)
        .expect("evaluate supplemental collision")
        .expect("supplemental collision must fail");
    let oracle: Arc<dyn GuardedCampaignFindingOracle> = oracle;

    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("supplemental-wrapper", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let artifacts = crate::CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    artifacts
        .import_scenario(&scenario)
        .expect("publish supplemental scenario");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    store
        .publish_executor_trace_leaf(source_id, 1, oracle.source().canonical_bytes().as_slice())
        .expect("publish supplemental source");
    let configuration = artifacts
        .import_configuration(&scenario, &input.start().configuration().schedule)
        .expect("publish supplemental start configuration");
    let policy = CampaignPolicy::new(
        input.lineage().scenario(),
        CampaignSeed::from_bytes([0x5a; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 1,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("supplemental fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("supplemental campaign policy");
    let created = repository
        .create(
            "supplemental-wrapper",
            input.lineage(),
            &policy,
            &BTreeMap::new(),
        )
        .expect("create supplemental campaign");
    let resumed = repository
        .apply_control(
            "supplemental-wrapper",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"resume-supplemental-wrapper",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume supplemental campaign");
    let funded = repository
        .apply_control(
            "supplemental-wrapper",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"fund-supplemental-wrapper",
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("supplemental attempt grant"),
                ),
            },
        )
        .expect("fund supplemental campaign");
    let admitted = repository
        .submit_discovery_request(
            "supplemental-wrapper",
            &DiscoveryRequest::new(
                CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"discover-supplemental-wrapper",
                )),
                funded.new_snapshot,
                configuration,
                StopCondition::ExecutionQuanta(1),
            )
            .expect("supplemental discovery request"),
        )
        .expect("admit supplemental discovery");
    assert_eq!(
        admitted.attempt,
        input.attempt().id().expect("supplemental input attempt ID")
    );

    let replay_decisions = VecDeque::from([decision]);
    let main = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: vec![SchedulerEventLogEntry::assertion_state_observation(
                1,
                VirtualTime { ticks: 1 },
                AssertionId::from_name(PROPERTY),
                AssertionPhase::Violated,
            )],
            replay_decisions: replay_decisions.clone(),
        },
        QemuFreshSupplementalModeledDriver::new(Some(Arc::clone(&oracle))),
    );
    // Each pass replays the one-decision original and then the empty selected
    // schedule, so the retained assertion follows prefixes of length one and zero.
    let replay_final_events = [1, 0, 1, 0]
        .into_iter()
        .map(|sequence| {
            vec![SchedulerEventLogEntry::assertion_state_observation(
                sequence,
                VirtualTime { ticks: sequence },
                AssertionId::from_name(PROPERTY),
                AssertionPhase::Violated,
            )]
        })
        .collect::<VecDeque<_>>();
    let replay = QemuFreshExecutionRunner::new(
        SequencedBoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: replay_final_events,
            replay_decisions,
        },
        QemuFreshSupplementalModeledDriver::new(Some(oracle)),
    );
    let mut runner = crate::AutomaticFindingExecutionRunner::new(store.clone(), main, replay);

    let outcome = runner
        .execute(
            &input,
            &context(resources(64), ExecutionCancellation::default()),
        )
        .expect("automatic supplemental finding wrapper");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("supplemental finding must produce a prepared semantic result")
    };
    let property = result
        .observation()
        .properties()
        .properties()
        .get(PROPERTY)
        .expect("supplemental property verdict");
    assert_eq!(property.verdict(), PropertyVerdict::Failed);
    assert_eq!(property.evidence(), &BTreeSet::from([source_id]));

    let finding = result
        .finding()
        .expect("supplemental finding must survive private minimization");
    assert_eq!(finding.bundle().schema_version(), 2);
    crate::executor_worker::publish_prepared_semantic_attempt_result(&store, result)
        .expect("publish supplemental prepared result");
    let triage = finding
        .bundle()
        .triage_evidence()
        .expect("supplemental finding triage set");
    let retained = repository
        .load_finding_triage_replay_evidence(triage.minimization_original())
        .expect("load supplemental triage evidence");
    let reproduction = finding.original();
    let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
        .expect("decode supplemental reproduction");
    let native_finding = FindingReproductionArtifact {
        discovery_path: FindingDiscoveryPath::StateSpaceSearch,
        finding_fingerprint: crucible::ContentHash {
            bytes: reproduction.finding_fingerprint().as_bytes(),
        },
        configuration: crucible::ContentHash {
            bytes: reproduction.configuration().as_hash().as_bytes(),
        },
        replay: artifact.replay().expect("replay supplemental reproduction"),
        artifact,
    };
    let replay = crucible::FailureTriageReplayEvidence::from_compact_binary(
        native_finding,
        retained.payload(),
    )
    .expect("decode supplemental triage payload");
    let crucible::FailureClusterReportFailure::Property(actual) = replay.failure() else {
        panic!("supplemental replay must retain a property violation")
    };
    let mut expected = expected_finding.violation().clone();
    expected.reproduction_artifact = replay.finding().artifact.id();
    assert_eq!(actual.violation, expected);
}

#[test]
fn finding_candidate_replay_evaluates_the_exact_materialized_boundary() {
    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(4));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("candidate boundary replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("genesis candidate must be observable")
    };

    assert_eq!(evidence.replay().configuration(), &candidate);
    assert_eq!(evidence.measurement_replay_evidence().len(), 1);
    assert!(evidence.final_events().is_empty());
    let (replay, measurements, final_events, _) = (*evidence).into_parts();
    assert_eq!(replay.configuration(), &candidate);
    assert_eq!(measurements.len(), 1);
    assert!(final_events.is_empty());
}

#[test]
fn finding_candidate_replay_stops_after_reaching_a_nonempty_schedule() {
    let input = modeled_non_genesis_fresh_runner_input();
    let candidate = finding_candidate_artifact(&input);
    let context = fresh_runner_context();
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::from([Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            })]),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("nonempty candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("matching nonempty candidate must be observable")
    };

    assert_eq!(evidence.replay().configuration(), &candidate);
    assert_eq!(
        context.consumed_execution_quanta(),
        1,
        "candidate evaluation must not run a continuation quantum"
    );
}

#[test]
fn finding_candidate_replay_retains_authenticated_execution_quanta_timeout() {
    let input = modeled_non_genesis_fresh_runner_input_for_stop(StopCondition::Observation(
        ObservationCondition::SchedulerQuiescentOrExecutionQuanta {
            execution_quanta: 1,
        },
    ));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::from([Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            })]),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("execution-bound candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("execution-bound candidate must be observable")
    };
    let (_, _, _, triage) = evidence.into_parts();
    let (failures, causal_entries, _, _, _) = triage.into_parts();
    let [crucible::FailureClusterReportFailure::Timeout(timeout)] = failures.as_slice() else {
        panic!("execution-bound replay must retain exactly one timeout source")
    };

    assert_eq!(
        timeout.budget_kind,
        crucible::FailureTimeoutBudgetKind::ExecutionQuanta
    );
    assert_eq!(timeout.configured_limit, Some(1));
    assert_eq!(timeout.observed_quanta, 1);
    assert!(causal_entries.iter().any(|entry| {
        entry.event_payload().kind() == "execution_budget_exhausted"
            && entry.event_payload().string("budget_kind") == Some("execution-quanta")
    }));
}

#[test]
fn property_failure_precedes_a_coincident_execution_quanta_timeout() {
    let assertion = AssertionId::from_name("coincident-timeout-safety");
    let base = modeled_assertion_candidate_input(assertion.clone(), 1);
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let configuration = step(base.start().configuration(), decision.clone());
    let input = finding_candidate_input_with_configuration_and_stop(
        &base,
        configuration,
        StopCondition::ExecutionQuanta(1),
    );
    let candidate = finding_candidate_artifact(&input);
    let final_event = SchedulerEventLogEntry::assertion_state_observation(
        1,
        VirtualTime { ticks: 1 },
        assertion,
        AssertionPhase::Violated,
    );
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: vec![final_event],
            replay_decisions: VecDeque::from([decision]),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("coincident property and timeout candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("coincident property and timeout candidate must be observable")
    };
    let (_, _, _, triage) = evidence.into_parts();
    let (failures, _, _, _, _) = triage.into_parts();

    assert!(matches!(
        failures.as_slice(),
        [
            crucible::FailureClusterReportFailure::Property(_),
            crucible::FailureClusterReportFailure::Timeout(_)
        ]
    ));
}

#[test]
fn fresh_paired_replay_keeps_selected_evidence_and_both_distinct_coverages_coherent() {
    let fork_entry = |sequence, label: &'static [u8]| {
        let mut attributes = BTreeMap::new();
        attributes.insert(
            String::from("from_checkpoint_id"),
            EventAttributeValue::String(crucible::ContentHash::from_bytes(label).to_hex()),
        );
        attributes.insert(
            String::from("schedule_delta"),
            EventAttributeValue::String(
                crucible::ContentHash::from_bytes(&[label, b"-schedule"].concat()).to_hex(),
            ),
        );
        condition_open_payload_entry_for_test(
            sequence,
            VirtualTime { ticks: 1 },
            SchedulerEventLogClass::Causal,
            EventPayload::new("fork", attributes.clone()),
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "paired-fork",
                EventLevel::Info,
                attributes,
            )),
        )
    };
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty World");
    let properties =
        Properties::from_assertions_for_world(&world, Vec::new()).expect("empty property set");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &properties,
        Seed::from_u64(0xa2b0_c0d0),
    )
    .expect("paired replay scenario");
    let input = modeled_fresh_runner_input_for_scenario(scenario, StopCondition::NextChoice);
    let candidate = finding_candidate_artifact(&input);
    let expected_event = condition_observation_entry_for_test(
        0,
        &ObservableEvent::coverage_marker(
            Icount { retired: 1 },
            NodeId {
                name: String::from("paired-node"),
            },
            MarkerId::from_name("expected-path"),
        ),
    );
    let reproduced_event = condition_observation_entry_for_test(
        0,
        &ObservableEvent::coverage_marker(
            Icount { retired: 1 },
            NodeId {
                name: String::from("paired-node"),
            },
            MarkerId::from_name("reproduced-path"),
        ),
    );
    let expected_boundary = fork_entry(1, b"expected-fork");
    let reproduced_boundary = fork_entry(1, b"reproduced-fork");
    let mut runner = QemuFreshExecutionRunner::new(
        SequencedBoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: VecDeque::from([
                vec![expected_event, expected_boundary],
                vec![reproduced_event, reproduced_boundary],
            ]),
            replay_decisions: VecDeque::new(),
        },
        QemuFreshModeledDriver::new(),
    );
    let context = fresh_runner_context();

    let expected = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("expected candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(expected) = expected else {
        panic!("expected replay must reach the candidate boundary")
    };
    let expected_coverage = expected.replay().coverage().clone();
    let reproduced = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("reproduced candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(reproduced) = reproduced else {
        panic!("reproduced replay must reach the candidate boundary")
    };
    let (_, _, _, expected_triage) = (*expected).clone().into_parts();
    let (_, _, _, reproduced_triage) = (*reproduced).clone().into_parts();
    let (_, expected_causal, _, _, _) = expected_triage.into_parts();
    let (_, reproduced_causal, _, _, _) = reproduced_triage.into_parts();
    assert_ne!(expected_causal, reproduced_causal);
    let reproduced = Box::new((*reproduced).compare_against_expected_replay(&expected));
    let reproduced_coverage = reproduced
        .paired_reproduced_coverage()
        .expect("paired replay retains reproduced coverage")
        .clone();
    let (selected_replay, _, selected_events, triage) = (*reproduced).into_parts();
    let (failures, causal_entries, coverage_fingerprint, _, paired_logs) = triage.into_parts();

    assert_ne!(expected_coverage, reproduced_coverage);
    assert_eq!(selected_replay.coverage(), &expected_coverage);
    assert_eq!(selected_events.len(), 2);
    assert_eq!(causal_entries, selected_events);
    assert_eq!(
        coverage_fingerprint,
        crucible::coverage_fingerprint_from_event_log(&selected_events)
    );
    assert!(matches!(
        failures.as_slice(),
        [crucible::FailureClusterReportFailure::Divergence(_)]
    ));
    assert!(paired_logs.is_some());
}

#[test]
fn replay_divergence_uses_the_actual_first_causal_log_mismatch() {
    let expected = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "execution-quanta",
    )];
    let reproduced = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "virtual-time",
    )];
    let comparison = crucible::compare_event_log_determinism(&expected, &reproduced);
    let mismatch = comparison.mismatch().expect("actual causal mismatch");
    let expected_point = mismatch.first_location().expect("mismatch coordinate");
    let expected_coverage = ContentHash::from_bytes(b"expected-replay-coverage");
    let reproduced_coverage = ContentHash::from_bytes(b"reproduced-replay-coverage");
    let expected_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            expected.clone(),
            expected_coverage,
            vec![b"expected-frame".to_vec()],
        );
    let reproduced_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            reproduced.clone(),
            reproduced_coverage,
            vec![b"reproduced-frame".to_vec()],
        );

    let (triage, selected_expected) = crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::from_replay_determinism_mismatch(
        &expected_inputs,
        &reproduced_inputs,
    )
    .expect("divergence triage inputs");
    let (failures, causal_entries, coverage_fingerprint, frames, paired_logs) = triage.into_parts();
    let [crucible::FailureClusterReportFailure::Divergence(divergence)] = failures.as_slice()
    else {
        panic!("mismatched causal logs must retain one divergence source")
    };

    assert!(selected_expected);
    assert_eq!(divergence.raw_index, expected_point.raw_index);
    assert_eq!(divergence.kind, expected_point.kind);
    assert!(
        divergence.expected_state_summary.contains(
            &mismatch
                .expected_entry
                .as_ref()
                .expect("expected mismatch entry")
                .content_hash()
                .to_hex()
        )
    );
    assert!(
        divergence.reproduced_state_summary.contains(
            &mismatch
                .reproduced_entry
                .as_ref()
                .expect("reproduced mismatch entry")
                .content_hash()
                .to_hex()
        )
    );
    assert_eq!(causal_entries, expected);
    assert_eq!(coverage_fingerprint, expected_coverage);
    assert_eq!(frames, [b"expected-frame".to_vec()]);
    assert_eq!(paired_logs, Some((expected, reproduced)));
}

#[test]
fn replay_divergence_uses_reproduced_evidence_when_expected_entry_is_absent() {
    let expected = Vec::new();
    let reproduced = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "execution-quanta",
    )];
    let expected_coverage = ContentHash::from_bytes(b"empty-expected-replay-coverage");
    let reproduced_coverage = ContentHash::from_bytes(b"present-reproduced-replay-coverage");
    let expected_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            expected.clone(),
            expected_coverage,
            vec![b"empty-expected-frame".to_vec()],
        );
    let reproduced_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            reproduced.clone(),
            reproduced_coverage,
            vec![b"present-reproduced-frame".to_vec()],
        );

    let (triage, selected_expected) = crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::from_replay_determinism_mismatch(
        &expected_inputs,
        &reproduced_inputs,
    )
    .expect("divergence triage inputs");
    let (_, causal_entries, coverage_fingerprint, frames, paired_logs) = triage.into_parts();

    assert!(!selected_expected);
    assert_eq!(causal_entries, reproduced);
    assert_eq!(coverage_fingerprint, reproduced_coverage);
    assert_eq!(frames, [b"present-reproduced-frame".to_vec()]);
    assert_eq!(paired_logs, Some((expected, reproduced)));
}

#[test]
fn composed_candidate_replay_retains_app_random_choice_and_measurement_leaf() {
    let assertion = AssertionId::from_name("app-random-candidate-safety");
    let base = modeled_assertion_candidate_input_with_vm(assertion.clone(), 2);
    let selectable = AppRandomSelectable::new(
        &base.scenario().scenario_def(),
        NodeId {
            name: String::from("node-a"),
        },
        RngStreamId::for_node("finding-replay-app-random"),
        11,
        16,
    )
    .expect("app-random selectable");
    let selection = selectable
        .sampled_selection(0x1234_5678_9abc_def0)
        .expect("app-random sampled selection");
    let discovery = selectable.into_discovery().expect("app-random discovery");
    let configuration = Configuration {
        def: base.scenario().scenario_def(),
        schedule: Schedule::empty()
            .appended(Decision::Selection(SelectionDecision::new(&selection))),
    };
    let input = finding_candidate_input_with_configuration(&base, configuration);

    assert_composed_candidate_replay_retains_choice_and_measurement(
        input, discovery, selection, &assertion,
    );
}

#[test]
fn composed_candidate_replay_retains_signal_fault_choice_and_measurement_leaf() {
    let assertion = AssertionId::from_name("signal-fault-candidate-safety");
    let base = modeled_assertion_candidate_input_with_vm(assertion.clone(), 2);
    let parent = Configuration::genesis(base.scenario().scenario_def());
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(
            b"finding-replay-signal-choice",
        )),
        candidates_digest: crucible::ContentHash::from_bytes(b"finding-replay-signal-candidates"),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    let frontier = SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime { ticks: 17 },
        choices: SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(Decision::Override),
        ),
    };
    let selectable =
        SignalFaultSelectable::from_frontier(&frontier).expect("signal-fault selectable");
    let selection = selectable
        .branch_selection(&parent, 2)
        .expect("signal-fault selection");
    let discovery = selectable.discovery().expect("signal-fault discovery");
    let configuration = selectable
        .resolve_branch(&selection)
        .expect("signal-fault branch")
        .selected()
        .clone();
    let input = finding_candidate_input_with_configuration(&base, configuration);

    assert_composed_candidate_replay_retains_choice_and_measurement(
        input, discovery, selection, &assertion,
    );
}

#[test]
fn finding_candidate_replay_reports_preserving_and_nonpreserving_verdicts() {
    let assertion = AssertionId::from_name("candidate-safety");

    for (predicate_at, expected) in [(1, PropertyVerdict::Passed), (2, PropertyVerdict::Failed)] {
        let input = modeled_assertion_candidate_input(assertion.clone(), predicate_at);
        let candidate = finding_candidate_artifact(&input);
        let final_event = SchedulerEventLogEntry::assertion_state_observation(
            0,
            VirtualTime { ticks: 1 },
            assertion.clone(),
            AssertionPhase::Satisfied,
        );
        let mut runner = QemuFreshExecutionRunner::new(
            BoundaryCaptureLifecycleFactory {
                captured: Arc::new(Mutex::new(Vec::new())),
                final_events: vec![final_event],
                replay_decisions: VecDeque::new(),
            },
            QemuFreshModeledDriver::new(),
        );

        let outcome = runner
            .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
            .expect("candidate assertion replay");
        let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
            panic!("materializable candidate must produce semantic evidence")
        };
        let actual = evidence
            .replay()
            .properties()
            .properties()
            .get(assertion.name.as_str())
            .expect("candidate assertion verdict")
            .verdict();

        assert_eq!(actual, expected);
        assert_eq!(evidence.final_events().len(), 1);
    }
}

#[test]
fn finding_candidate_replay_reports_prefix_divergence_after_cleanup() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("incompatible replay is a modeled outcome");

    assert_eq!(
        outcome,
        QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
            QemuFindingCandidateIncompatibility::PrefixDiverged,
        )
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_reports_terminal_prefix_after_cleanup() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let input = non_genesis_fresh_runner_input_with_decisions(vec![decision.clone(), decision]);
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: true,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("terminal prefix is a modeled incompatibility");

    assert_eq!(
        outcome,
        QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
            QemuFindingCandidateIncompatibility::PrefixTerminated,
        )
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_preserves_cleanup_failure_over_incompatibility() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let error = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect_err("cleanup failure overrides deterministic incompatibility");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterRunner { .. })
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_shares_cancellation_and_still_cleans_up() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input();
    let candidate = finding_candidate_artifact(&input);
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let error = runner
        .replay_finding_candidate_boundary(
            &input,
            &candidate,
            None,
            &context(resources(4), cancellation),
        )
        .expect_err("canceled candidate replay remains operational failure");

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

struct PreparedSemanticResultRunner {
    result: Option<PreparedSemanticAttemptResult>,
}

impl CrucibleExecutionRunner for PreparedSemanticResultRunner {
    type Error = Infallible;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        let result = self
            .result
            .take()
            .expect("prepared semantic fixture executes once");
        Ok(CrucibleExecutionOutcome::new(
            AttemptExecutionProduct::PreparedSemantic(Box::new(result)),
            CrucibleMaterializationTier::ThinReplay,
        ))
    }
}

#[test]
fn terminal_evidence_runner_rejects_previous_attempt_samples_after_a_factory_reset() {
    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(1));
    let captured = Arc::new(Mutex::new(Vec::new()));
    let factory = BoundaryCaptureLifecycleFactory {
        captured: Arc::clone(&captured),
        final_events: Vec::new(),
        replay_decisions: VecDeque::new(),
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver::new());
    let mut first = QemuTerminalEvidenceExecutionRunner::new(runner, evidence.clone());
    let first_outcome = first
        .execute(&input, &fresh_runner_context())
        .expect("first attempt publishes terminal evidence");
    let AttemptExecutionProduct::PreparedSemantic(first_result) = first_outcome.product() else {
        panic!("first attempt must produce a prepared semantic result")
    };
    assert!(first_result.terminal_fingerprints().is_some());

    let next_result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
        first_result.observation().clone(),
        first_result.measurement_replay_evidence().to_vec(),
        first_result.finding().cloned(),
    )
    .expect("next prepared result without terminal evidence");
    let resetting_factory = QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
        BoundaryCaptureLifecycleFactory {
            captured,
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
        },
        evidence.clone(),
    );
    resetting_factory
        .prepare_observation(input.scenario())
        .expect("new fast-tier attempt resets per-worker evidence");
    assert_eq!(
        evidence
            .snapshot()
            .expect("reset evidence snapshot")
            .terminal_fingerprints(),
        None
    );

    let inner = PreparedSemanticResultRunner {
        result: Some(next_result),
    };
    let mut next = QemuTerminalEvidenceExecutionRunner::new(inner, evidence);
    let error = next
        .execute(&input, &fresh_runner_context())
        .expect_err("the next attempt cannot reuse the previous terminal set");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuTerminalEvidenceExecutionRunnerError::MissingTerminalFingerprints
        )
    ));
}

#[test]
fn fresh_runner_rejects_resume_origin_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
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
fn fresh_runner_rejects_unconsumed_continuation_input_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let continuation_input = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation(Some(continuation_input));

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("default factory must reject modeled continuation input");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::ContinuationInputUnsupported)
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_rejects_continuation_without_exact_virtual_time_source() {
    assert_invalid_continuation_source(StopCondition::ExecutionQuanta(1));
}

#[test]
fn fresh_runner_rejects_continuation_at_a_different_virtual_time() {
    assert_invalid_continuation_source(StopCondition::VirtualTimeNanoseconds(2));
}

#[test]
fn continuation_accepts_an_authenticated_observation_source_frontier() {
    let condition = ObservationCondition::SchedulerQuiescent;
    let proof = ObservationStopProof::new(
        condition.clone(),
        ObservationStopSatisfaction::SchedulerQuiescent,
        ConfigurationId::from_hash(CampaignHash::derive(
            "continuation-observation-source",
            b"child",
        )),
        ObservationQuantumBoundary::new(1, 0, 1, 0).expect("observation source boundary"),
        ObservationEventLogProof::new(
            CampaignHash::derive("continuation-observation-source", b"prefix"),
            None,
            0,
            0,
            CampaignHash::derive("continuation-observation-source", b"digest"),
        ),
        None,
    )
    .expect("quiescent source proof");
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation_source_evidence(
        continuation,
        StopCondition::Observation(condition),
        StopOutcome::ObservationReached(Box::new(proof)),
    );

    let controls = validated_attempt_continuations(&input)
        .unwrap_or_else(|()| panic!("authenticated observation source should validate"));

    assert_eq!(controls.len(), 1);
    assert_eq!(controls[0].input().source_frontier_ticks(), 1);
}

#[test]
fn continuation_rejects_a_terminally_preempted_source_stop() {
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation_source_evidence(
        continuation,
        StopCondition::VirtualTimeNanoseconds(1),
        StopOutcome::TerminalSuccess,
    );

    assert!(validated_attempt_continuations(&input).is_err());
}

fn assert_invalid_continuation_source(source_stop: StopCondition) {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::new(Mutex::new(Vec::new())),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) =
        selected_after_genesis_input_with_continuation_source_stop(continuation, source_stop);

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("invalid source must not admit continuation control");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::InvalidContinuationInput)
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
            terminal_after_replay: false,
            checkpoint_ready: true,
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
fn fresh_runner_replays_authenticated_signal_fault_plan_before_driver() {
    let base = fresh_runner_input();
    let CrucibleResolvedAttemptStart::Discover {
        configuration: parent,
    } = base.start()
    else {
        panic!("fresh runner fixture should discover genesis");
    };
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(
            b"fresh-runner-signal-choice",
        )),
        candidates_digest: crucible::ContentHash::from_bytes(b"fresh-runner-signal-candidates"),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    let selectable = SignalFaultSelectable::from_frontier(&SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime::default(),
        choices: SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(Decision::Override),
        ),
    })
    .expect("fresh runner signal selectable");
    let selection = selectable
        .branch_selection(parent, 1)
        .expect("fresh runner signal selection");
    let branch = selectable
        .resolve_branch(&selection)
        .expect("fresh runner signal branch");
    let replay = crucible::SignalFaultCampaignReplayPlan::new(
        branch.selected().clone(),
        vec![branch.clone()],
    )
    .expect("fresh runner signal replay plan");
    let input = non_genesis_fresh_runner_input_with_decisions(branch.decisions().to_vec())
        .with_test_signal_fault_replay(replay);
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("typed signal-fault replay should reach the modeled driver");

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
fn fresh_replay_applies_campaign_selection_at_exact_guest_request() {
    let node = NodeId {
        name: String::from("router-a"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("guest-selectable-replay-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("guest selectable replay World");
    let declaration = SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::from([String::from("recovery")]),
        true,
    )
    .expect("guest selectable declaration");
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32).expect("selectable limits"),
        vec![declaration.clone()],
    )
    .expect("scenario selectables");
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(17),
    )
    .expect("guest selectable replay scenario")
    .with_selectables(selectables)
    .expect("attach guest selectables");
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let parent = Configuration::genesis(source.scenario_def());
    let request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)
        .expect("guest request");
    let pending = SelectablePlanPendingRequest::new(request, 41, 0, 0x1000);
    let discovery =
        crate::guest_selectable::resolve_guest_selectable(scenario, &source, &node, &pending)
            .expect("runtime opportunity");
    let default_selection = Selection::new(
        discovery.opportunity(),
        discovery.domain(),
        discovery.opportunity().default().clone(),
        crucible_campaign::SelectionOrigin::Default,
    )
    .expect("default guest selection");
    let default_target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&default_selection)),
    );
    assert_eq!(
        unsupported_fresh_replay_decision(
            &default_target,
            &crucible::SignalFaultCampaignReplayPlan::empty(default_target.clone()),
        ),
        None,
        "the runner prefilter must admit default guest replay"
    );
    let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
    let selection = Selection::new_campaign_branch(
        discovery.opportunity(),
        discovery.domain(),
        ChoiceValue::Boolean(true),
        discovery.opportunity().branch_point_id(parent_id),
    )
    .expect("campaign selection");
    let target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "guest-selectable-replay-diagnostic",
            1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    repository
        .publish_choice_domain(discovery.domain())
        .expect("publish guest choice domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish guest selectable declaration");
    repository
        .publish_choice_opportunity(discovery.opportunity())
        .expect("publish guest choice opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish guest selection");
    let resolved_selection = repository
        .resolve_selection(selection.id().expect("guest selection ID"))
        .expect("resolve guest selection");
    let replay_start = CrucibleResolvedAttemptStart::Branch {
        parent: parent.clone(),
        selection: Box::new(resolved_selection),
        selected: target.clone(),
    };
    assert!(
        replay_start.replay_selection(1).is_none(),
        "expected context must not attach to an unrelated decision index"
    );
    let base_attempt = fresh_runner_input();
    let AttemptStart::Discover {
        configuration: parent_artifact,
    } = base_attempt.attempt().start()
    else {
        panic!("guest branch fixture must start from discovery")
    };
    let SelectionOrigin::CampaignBranch { branch_point, edge } = selection.origin() else {
        panic!("guest replay selection must be a campaign branch")
    };
    let replay_path = BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)])
        .expect("guest replay branch path");
    let replay_attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: parent_artifact,
            selection: selection.id().expect("guest replay selection ID"),
        },
        replay_path.id().expect("guest replay branch path ID"),
        StopCondition::Terminal,
    )
    .expect("guest replay branch attempt");
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: vec![
            crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(node, pending),
        ],
        replies: Arc::clone(&replies),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let mut current = parent.clone();
    let diagnostic_config = crate::GuestSelectableBoundaryDiagnosticConfig::new(4)
        .expect("guest-selectable diagnostic policy");
    let (diagnostics, diagnostic_lines) =
        crate::guest_selectable::GuestSelectableBoundaryDiagnosticRecorder::capture(
            diagnostic_config,
        );
    let execution_context =
        fresh_runner_context().with_guest_selectable_boundary_diagnostics(diagnostics);
    let mut materialization = QemuFreshStartMaterialization::genesis();
    apply_replayed_guest_selectables::<(), ()>(
        &mut lifecycle,
        &execution_context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: &replay_attempt,
            start: &replay_start,
        },
        scenario,
        &source,
        &target,
        &mut current,
        &mut materialization,
    )
    .expect("exact guest branch replay");

    assert_eq!(current, target);
    let replies = replies.lock().expect("fresh lifecycle replies");
    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0].selected_value(),
        Some(ChoiceValue::Boolean(true).canonical_bytes().as_slice())
    );
    {
        let diagnostic_lines = diagnostic_lines.lock().expect("boundary diagnostics");
        assert_eq!(diagnostic_lines.len(), 1);
        assert!(diagnostic_lines[0].contains("stage=replay"));
        assert!(diagnostic_lines[0].contains("decision_index=0"));
        assert!(diagnostic_lines[0].contains("trap_icount=41 stopped_icount=42 vcpu=0"));
        assert!(
            diagnostic_lines[0]
                .contains("expected_opportunity=crucible.campaign.choice-opportunity@")
        );
    }

    let drift_request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)
        .expect("drifted guest request");
    let drift_pending = SelectablePlanPendingRequest::new(drift_request, 42, 0, 0x1000);
    let drift_replies = Arc::new(Mutex::new(Vec::new()));
    let mut drift_lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: vec![
            crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
                NodeId {
                    name: String::from("router-a"),
                },
                drift_pending,
            ),
        ],
        replies: Arc::clone(&drift_replies),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let mut drift_current = parent.clone();
    let mut drift_materialization = QemuFreshStartMaterialization::genesis();

    let failure = apply_replayed_guest_selectables::<std::io::Error, std::io::Error>(
        &mut drift_lifecycle,
        &execution_context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: &replay_attempt,
            start: &replay_start,
        },
        scenario,
        &source,
        &target,
        &mut drift_current,
        &mut drift_materialization,
    )
    .expect_err("drifted runtime opportunity must fail replay");

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(GuestSelectableError::ReplayMismatch(mismatch)),
    )) = &failure
    else {
        panic!("replay mismatch must retain its typed production error chain")
    };
    assert_eq!(
        finding_candidate_incompatibility(&failure),
        Some(QemuFindingCandidateIncompatibility::SelectionMismatch)
    );
    assert_eq!(
        mismatch.mismatch().kind(),
        SelectionReplayMismatchKind::OpportunityIdentity
    );
    assert_eq!(mismatch.phase(), GuestSelectableReplayPhase::FreshStart);
    assert_eq!(
        mismatch.attempt_role(),
        GuestSelectableReplayAttemptRole::ExecutingAttempt
    );
    assert_eq!(
        mismatch.attempt(),
        replay_attempt.id().expect("replay attempt identity")
    );
    assert_eq!(
        mismatch.replayed_configuration(),
        ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes))
    );
    assert_eq!(mismatch.decision_index(), 0);
    assert_eq!(mismatch.node(), "router-a");
    assert_eq!(mismatch.selectable(), "product.recovery");
    assert_eq!(mismatch.request_instance(), "routing-epoch-7");
    assert_eq!(mismatch.request_sequence(), 9);
    assert_eq!(mismatch.request_icount(), 42);
    assert_eq!(mismatch.request_vcpu_index(), 0);
    let expected_opportunity = mismatch
        .expected_opportunity()
        .expect("branch start retains expected opportunity context");
    assert_eq!(
        expected_opportunity.declaration(),
        discovery.opportunity().declaration()
    );
    assert_eq!(
        expected_opportunity.coordinate(),
        discovery.opportunity().coordinate()
    );
    assert_eq!(expected_opportunity.instance(), "routing-epoch-7");
    assert_eq!(
        mismatch.replayed_opportunity().instance(),
        "routing-epoch-7"
    );
    assert_eq!(drift_current, parent);
    assert!(drift_replies.lock().expect("drift replies").is_empty());

    let execution = ExecutionId::from_bytes([0x39; 16]).expect("execution identity");
    let diagnostic =
        crate::packaged_qemu_executor::packaged_attempt_failure_diagnostic(execution, &failure);
    assert!(diagnostic.contains("phase=fresh-start"));
    assert!(diagnostic.contains("attempt-role=executing-attempt"));
    assert!(diagnostic.contains("failed-predicate=selection-opportunity-identity"));
    assert!(diagnostic.contains("decision-index=0"));
    assert!(diagnostic.contains("request-sequence=9"));
    assert!(diagnostic.contains("request-icount=42"));
    assert!(diagnostic.contains("request-vcpu=0"));
    assert!(diagnostic.contains("expected-declaration="));
    assert!(diagnostic.contains("expected-choice-scheduler-coordinate="));

    let oversized = crate::packaged_qemu_executor::packaged_attempt_failure_diagnostic(
        execution,
        &OversizedFailure { source: failure },
    );
    assert!(oversized.contains("phase=fresh-start"));
    assert!(oversized.contains("attempt-role=executing-attempt"));
    assert!(oversized.contains("failed-predicate=selection-opportunity-identity"));
    assert!(oversized.ends_with("\n  ... diagnostic truncated"));
    assert!(
        oversized.len()
            <= crate::packaged_qemu_executor::MAX_PACKAGED_ATTEMPT_FAILURE_DIAGNOSTIC_BYTES
    );
}

#[test]
fn fresh_runner_replay_divergence_cleans_up_without_calling_driver() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
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
            terminal_after_replay: false,
            checkpoint_ready: true,
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
            terminal_after_replay: false,
            checkpoint_ready: true,
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
            QemuFreshStartReplayError::ResourceRefusal(_)
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
            terminal_after_replay: false,
            checkpoint_ready: true,
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
        CrucibleResolvedAttemptStart::Branch { .. }
        | CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
            panic!("expected discovery fixture")
        }
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
fn attempt_start_verifier_seals_the_prefix_before_final_drain() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input();
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"ordinary-attempt-start-proof",
    ))
    .expect("resume checkpoint");
    let resume_context = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let proof = runner
        .verify_attempt_start(&input, &resume_context)
        .expect("cold-replayed attempt-start prefix");

    assert_eq!(
        proof.attempt_event_count(input.start().configuration(), &[]),
        Some(0)
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn attempt_start_verifier_rejects_unsupported_event_count_start_before_factory() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input_with_decisions_for_stop(
        vec![Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::from_name("event-count-resume-override"),
            request_id: 1,
            width: 8,
            value: 7,
        })],
        StopCondition::EventCount(4),
    );
    let expected = input.start().configuration().id();
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"unsupported-event-count-start",
    ))
    .expect("resume checkpoint");
    let resume_context = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let error = runner
        .verify_attempt_start(&input, &resume_context)
        .expect_err("unsupported EventCount start must fail closed");

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
            terminal_after_replay: false,
            checkpoint_ready: true,
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
fn fresh_runner_cleans_up_after_terminal_fingerprint_capture_failure() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let failing = FingerprintFailingFreshLifecycleFactory {
        inner: FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(failing);
    let mut runner = QemuFreshExecutionRunner::new(
        factory,
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("missing terminal fingerprint authority must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::TerminalFingerprintCapture(
            SchedulerError::BoundaryViolation { .. }
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
    assert_eq!(
        evidence
            .snapshot()
            .expect("evidence after capture failure")
            .terminal_fingerprints(),
        None
    );
}

#[test]
fn cleanup_failure_overrides_terminal_fingerprint_capture_failure() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let failing = FingerprintFailingFreshLifecycleFactory {
        inner: FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(failing);
    let mut runner = QemuFreshExecutionRunner::new(
        factory,
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("cleanup failure must retain precedence");

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterRunner {
        failure,
        ..
    }) = error
    else {
        panic!("cleanup failure must retain the prior capture failure");
    };
    assert!(matches!(
        *failure,
        QemuFreshExecutionRunnerError::TerminalFingerprintCapture(
            SchedulerError::BoundaryViolation { .. }
        )
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
    assert_eq!(
        evidence
            .snapshot()
            .expect("evidence after cleanup failure")
            .terminal_fingerprints(),
        None
    );
}

#[test]
fn fresh_cleanup_failure_overrides_driver_retry_and_retains_diagnostics() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
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

#[test]
fn production_continuation_plan_consumes_the_authenticated_reseed() {
    let input = fresh_runner_input();
    let source = step(
        input.start().configuration(),
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("continuation-plan-source"),
            value: 7,
        }),
    );
    let frontier = VirtualTime { ticks: 37 };
    let seed = Seed::from_u64(0x51ec_7ed0);
    let continuation = OwnedQemuAttemptContinuation {
        input: AttemptContinuationInput::scheduler_reseed(
            test_continuation_source_observation(),
            frontier.ticks,
            seed.bytes(),
        ),
        source: source.clone(),
    };

    let plan = production_continuation_plan(input.scenario(), Some(&continuation))
        .expect("production continuation plan");

    assert_eq!(
        plan,
        ProductionContinuationPlan::Reseed {
            base: source,
            frontier,
            seed,
        }
    );
}

fn fresh_runner_input() -> CrucibleAttemptExecution {
    fresh_runner_input_for_stop(StopCondition::Terminal)
}

fn fresh_runner_input_for_stop(stop: StopCondition) -> CrucibleAttemptExecution {
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
        stop,
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

fn modeled_fresh_runner_input_for_stop(stop: StopCondition) -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    modeled_fresh_runner_input_for_scenario(scenario, stop)
}

fn modeled_assertion_candidate_input(
    assertion: AssertionId,
    predicate_at: u64,
) -> CrucibleAttemptExecution {
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty World");
    modeled_assertion_candidate_input_for_world(world, assertion, predicate_at)
}

fn modeled_assertion_candidate_input_with_vm(
    assertion: AssertionId,
    predicate_at: u64,
) -> CrucibleAttemptExecution {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("node-a"),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("finding-replay-production-capture"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("finding replay production capture World");
    modeled_assertion_candidate_input_for_world(world, assertion, predicate_at)
}

fn modeled_assertion_candidate_input_for_world(
    world: World,
    assertion: AssertionId,
    predicate_at: u64,
) -> CrucibleAttemptExecution {
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion,
            message: String::from("candidate safety failed"),
            property: Property::Always {
                predicate: Predicate::At {
                    at: VirtualTime {
                        ticks: predicate_at,
                    },
                },
            },
        }],
    )
    .expect("candidate properties");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &properties,
        Seed::from_u64(0x51a7_5afe),
    )
    .expect("candidate assertion scenario");
    modeled_fresh_runner_input_for_scenario(scenario, StopCondition::Terminal)
}

fn modeled_fresh_runner_input_for_scenario(
    scenario: ScenarioDefForm,
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let definition = scenario.scenario_def();
    let scenario_artifact =
        crate::encode_crucible_scenario_artifact(&scenario).expect("encoded scenario artifact");
    let scenario_id = scenario_artifact.scenario();
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(definition);
    let configuration_artifact =
        crate::encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("encoded configuration artifact");
    let configuration_id = configuration_artifact.configuration();
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
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("campaign lineage");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path id"),
        stop,
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

fn selected_after_genesis_input() -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    selected_after_genesis_input_with_continuation(None)
}

fn selected_after_genesis_input_with_continuation(
    continuation_input: Option<AttemptContinuationInput>,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    let source_stop = continuation_input
        .as_ref()
        .map(|input| StopCondition::VirtualTimeNanoseconds(input.source_frontier_ticks()))
        .unwrap_or(StopCondition::ExecutionQuanta(1));
    selected_after_genesis_input_with_optional_continuation_source_stop(
        continuation_input,
        source_stop.clone(),
        StopOutcome::Reached(source_stop),
    )
}

fn selected_after_genesis_input_with_continuation_source_stop(
    continuation_input: AttemptContinuationInput,
    source_stop: StopCondition,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    selected_after_genesis_input_with_continuation_source_evidence(
        continuation_input,
        source_stop.clone(),
        StopOutcome::Reached(source_stop),
    )
}

fn selected_after_genesis_input_with_continuation_source_evidence(
    continuation_input: AttemptContinuationInput,
    source_stop: StopCondition,
    source_outcome: StopOutcome,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    selected_after_genesis_input_with_optional_continuation_source_stop(
        Some(continuation_input),
        source_stop,
        source_outcome,
    )
}

fn selected_after_genesis_input_with_optional_continuation_source_stop(
    continuation_input: Option<AttemptContinuationInput>,
    source_stop: StopCondition,
    source_outcome: StopOutcome,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    let base = fresh_runner_input();
    let configuration = base.start().configuration().clone();
    let reached = step(
        &configuration,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let AttemptStart::Discover {
        configuration: configuration_artifact,
    } = base.attempt().start()
    else {
        panic!("fresh fixture must discover from genesis");
    };
    let origin = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact,
        },
        base.attempt().path(),
        source_stop.clone(),
    )
    .expect("selected origin attempt");
    let source_attempt = origin.id().expect("selected origin attempt ID");
    let reached_id = ConfigurationId::from_hash(CampaignHash::from_bytes(reached.id().bytes));
    let reached_artifact = ConfigurationArtifact::new(
        base.lineage().scenario(),
        base.lineage().scenario_content(),
        reached_id,
        1,
        b"selected-origin-reached".to_vec(),
    )
    .expect("selected reached configuration artifact")
    .id()
    .expect("selected reached configuration artifact ID");
    let continuation_start = AttemptStart::AfterAttempt {
        origin: source_attempt,
        reached: reached_artifact,
    };
    let continuation = match continuation_input {
        Some(input) => Attempt::new_with_continuation_input(
            continuation_start,
            base.attempt().path(),
            StopCondition::Terminal,
            input,
        ),
        None => Attempt::new(
            continuation_start,
            base.attempt().path(),
            StopCondition::Terminal,
        ),
    }
    .expect("selected continuation attempt");
    let base_replay = crucible::SignalFaultCampaignReplayPlan::empty(configuration.clone());
    let reached_replay = crucible::SignalFaultCampaignReplayPlan::empty(reached.clone());
    let origins = CrucibleAttemptOrigins::new(
        CrucibleAttemptOrigin::new_with_source_stop(
            origin,
            reached,
            reached_replay,
            source_outcome,
        ),
        Vec::new(),
    );
    let input = CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        base.scenario().clone(),
        continuation,
        base.path().clone(),
        CrucibleResolvedAttemptStart::AfterAttempt {
            base: Box::new(CrucibleResolvedAttemptStart::Discover {
                configuration: configuration.clone(),
            }),
            base_signal_fault_replay: base_replay,
            origins: Box::new(origins),
        },
    );
    let source_checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"absent-selected-source-checkpoint",
    ))
    .expect("selected source checkpoint");

    (input, source_attempt, source_checkpoint)
}

fn selected_after_two_controlled_generations() -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
    [(u64, crucible::ContentHash); 2],
) {
    let base = fresh_runner_input();
    let configuration = base.start().configuration().clone();
    let reached_first = step(
        &configuration,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let reached_second = step(
        &reached_first,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let AttemptStart::Discover {
        configuration: configuration_artifact,
    } = base.attempt().start()
    else {
        panic!("fresh fixture must discover from genesis");
    };
    let first = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact,
        },
        base.attempt().path(),
        StopCondition::VirtualTimeNanoseconds(1),
    )
    .expect("first source attempt");
    let first_id = first.id().expect("first source attempt ID");
    let reached_first_artifact =
        test_reached_configuration_artifact(&base, &reached_first, b"two-control-first-reached");
    let second = Attempt::new_with_continuation_input(
        AttemptStart::AfterAttempt {
            origin: first_id,
            reached: reached_first_artifact,
        },
        base.attempt().path(),
        StopCondition::VirtualTimeNanoseconds(2),
        AttemptContinuationInput::scheduler_reseed(
            test_continuation_source_observation_for(b"two-control-first-observation"),
            1,
            [0x29; 32],
        ),
    )
    .expect("first controlled continuation");
    let second_id = second.id().expect("first controlled continuation ID");
    let reached_second_artifact =
        test_reached_configuration_artifact(&base, &reached_second, b"two-control-second-reached");
    let current = Attempt::new_with_continuation_input(
        AttemptStart::AfterAttempt {
            origin: second_id,
            reached: reached_second_artifact,
        },
        base.attempt().path(),
        StopCondition::Terminal,
        AttemptContinuationInput::scheduler_reseed(
            test_continuation_source_observation_for(b"two-control-second-observation"),
            2,
            [0x47; 32],
        ),
    )
    .expect("second controlled continuation");
    let first_origin = CrucibleAttemptOrigin::new_with_source_stop(
        first,
        reached_first.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(reached_first.clone()),
        crucible_campaign::StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(1)),
    );
    let second_origin = CrucibleAttemptOrigin::new_with_source_stop(
        second,
        reached_second.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(reached_second.clone()),
        crucible_campaign::StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(2)),
    );
    let expected_controls = [(1, reached_first.id()), (2, reached_second.id())];
    let input = CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        base.scenario().clone(),
        current,
        base.path().clone(),
        CrucibleResolvedAttemptStart::AfterAttempt {
            base: Box::new(CrucibleResolvedAttemptStart::Discover {
                configuration: configuration.clone(),
            }),
            base_signal_fault_replay: crucible::SignalFaultCampaignReplayPlan::empty(configuration),
            origins: Box::new(CrucibleAttemptOrigins::new(
                first_origin,
                vec![second_origin],
            )),
        },
    );
    let source_checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"two-control-selected-source-checkpoint",
    ))
    .expect("selected source checkpoint");

    (input, second_id, source_checkpoint, expected_controls)
}

fn test_reached_configuration_artifact(
    base: &CrucibleAttemptExecution,
    reached: &Configuration,
    bytes: &[u8],
) -> crucible_campaign::ConfigurationArtifactId {
    let reached_id = ConfigurationId::from_hash(CampaignHash::from_bytes(reached.id().bytes));
    ConfigurationArtifact::new(
        base.lineage().scenario(),
        base.lineage().scenario_content(),
        reached_id,
        1,
        bytes.to_vec(),
    )
    .expect("selected reached configuration artifact")
    .id()
    .expect("selected reached configuration artifact ID")
}

fn campaign_fact_id(byte: u8) -> CampaignFactId {
    let content = ContentId::for_bytes(ObjectKind::CampaignFact, 10, &[byte; 32]);
    CampaignFactId::parse(&format!("crucible.campaign.fact@{}", content.encode()))
        .expect("campaign fact")
}

fn test_continuation_source_observation() -> crucible_campaign::ObservationId {
    test_continuation_source_observation_for(b"controlled-continuation-source-observation")
}

fn test_continuation_source_observation_for(bytes: &[u8]) -> crucible_campaign::ObservationId {
    let content = ContentId::for_bytes(ObjectKind::Observation, 6, bytes);
    crucible_campaign::ObservationId::parse(&format!(
        "crucible.campaign.observation@{}",
        content.encode()
    ))
    .expect("controlled continuation source observation")
}

fn non_genesis_fresh_runner_input() -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    }))
}

fn modeled_non_genesis_fresh_runner_input() -> CrucibleAttemptExecution {
    modeled_non_genesis_fresh_runner_input_for_stop(StopCondition::Terminal)
}

fn modeled_non_genesis_fresh_runner_input_for_stop(
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let base = modeled_fresh_runner_input_for_stop(StopCondition::Terminal);
    let scenario = base.scenario().clone();
    let configuration = step(
        &Configuration::genesis(scenario.scenario_def()),
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let scenario_artifact =
        crate::encode_crucible_scenario_artifact(&scenario).expect("modeled scenario artifact");
    let configuration_artifact =
        crate::encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("modeled non-genesis configuration artifact");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact
                .id()
                .expect("modeled non-genesis artifact ID"),
        },
        path.id().expect("branch path ID"),
        stop,
    )
    .expect("modeled non-genesis attempt");

    CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn non_genesis_fresh_runner_input_with_decision(decision: Decision) -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decisions(vec![decision])
}

fn non_genesis_fresh_runner_input_with_decisions(
    decisions: Vec<Decision>,
) -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decisions_for_stop(decisions, StopCondition::Terminal)
}

fn non_genesis_fresh_runner_input_with_decisions_for_stop(
    decisions: Vec<Decision>,
    stop: StopCondition,
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
        stop,
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

fn test_checkpoint_capture() -> crate::CapturedExactCheckpoint {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.fresh-campaign-runner",
        "sealed-product",
    ));
    test_checkpoint_capture_for_configuration(&configuration)
}

fn test_checkpoint_capture_for_configuration(
    configuration: &Configuration,
) -> crate::CapturedExactCheckpoint {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("fresh runner checkpoint boundary");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("fresh runner QEMU snapshot");
    crate::CapturedExactCheckpoint::new(snapshot, BlobHandle::from_bytes(vec![0x5a; 512]))
}

fn test_checkpoint_product() -> AttemptExecutionProduct {
    AttemptExecutionProduct::exact_checkpoint(test_checkpoint_capture())
}
