//! QEMU campaign lifecycle restart, promotion, and recovery tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible::model::{BindingSearchChoice, SearchChoiceId};
use crucible::{
    AppRandomDecision, AppRandomSelectable, Checkpoint, CheckpointKind, Configuration, Decision,
    Icount, NodeId, NodeTemplate, Plan, Properties, ReadyPoint, RngDecision, RngStreamId,
    ScenarioDef, ScenarioDefForm, ScenarioSelectableLimits, ScenarioSelectables,
    SchedulerEventLogEntry, SearchFrontierChoices, SearchRuntimeFrontier, Seed, SelectionDecision,
    SignalFaultSelectable, VirtualTime, WhiteBoxPolicy, World, WorldNode, step,
};
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig,
    ProductionVmNodeLauncher,
};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BooleanDomain, BranchPath, CampaignHash,
    CampaignLineage, ChoiceClassContext, ChoiceDomain, ChoiceSource, ChoiceValue,
    ConfigurationArtifact, ConfigurationId, ExecutionRetentionIntent, ScenarioArtifact,
    ScenarioDefId, SelectableDeclaration, Selection, StopCondition,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, ImmutableBlobBackend, ObjectKind,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuLiveNodeStepGateConfig,
    QemuNodeChild, QemuPreparedRunDirectory, QemuReplayOracleValidation, QemuVmRealizationError,
    QemuVmSnapshot,
};

use super::*;
use crate::executor_supervisor::{AttemptCheckpointHandoff, ExecutionCheckpointHandoff};
use crate::{
    AttemptExecutionProduct, CapturedAttemptCheckpoint, CheckpointHandoffFailure,
    CrucibleAttemptExecution, CrucibleMaterializationTier, CrucibleResolvedAttemptStart,
    ExactCheckpointStore, ExecutionCancellation, ExecutionCheckpointRequest,
    PreparedAttemptCheckpoint, QemuAttemptOperationalBoundary, QemuAttemptResourceGuard,
};

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
    cleanup_error: bool,
    pending: Vec<crucible_qemu::QemuNodeSelectablePendingRequest>,
    replies: Arc<Mutex<Vec<crucible_protocol::SelectionReply>>>,
    signal_fault_branches: VecDeque<crucible::SignalFaultCampaignBranch>,
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
        if let Some(branch) = self.signal_fault_branches.front().cloned()
            && branch.parent() == &request.configuration
        {
            self.signal_fault_branches.pop_front();
            return Ok(crucible::QuantumOutcome {
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

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, crucible::SchedulerError>
    {
        Ok(std::mem::take(&mut self.pending))
    }

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), crucible::SchedulerError> {
        self.replies
            .lock()
            .expect("fresh lifecycle replies")
            .push(reply.clone());
        Ok(())
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
            cleanup_error: self.cleanup_error,
            pending: Vec::new(),
            replies: Arc::new(Mutex::new(Vec::new())),
            signal_fault_branches: signal_fault_replay.branches().iter().cloned().collect(),
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
    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        unreachable!("fresh genesis capture performs no modeled quantum")
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

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), crucible::SchedulerError> {
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
        Ok(FakeGenesisCheckpointLifecycle {
            order: Arc::clone(&self.order),
            capture: Some(test_checkpoint_capture_for_configuration(&configuration).into()),
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

#[test]
fn fresh_runner_captures_a_sticky_checkpoint_before_shutdown_and_seal() {
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
fn fresh_genesis_checkpoint_capture_uses_no_modeled_quantum_and_tears_down() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
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
fn production_baked_genesis_rejects_legacy_capture_after_guarded_teardown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
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
        vec![declaration],
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
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        cleanup_error: false,
        pending: vec![
            crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(node, pending),
        ],
        replies: Arc::clone(&replies),
        signal_fault_branches: VecDeque::new(),
    };
    let mut current = parent;

    apply_replayed_guest_selectables::<(), ()>(
        &mut lifecycle,
        scenario,
        &source,
        &target,
        &mut current,
    )
    .expect("exact guest branch replay");

    assert_eq!(current, target);
    let replies = replies.lock().expect("fresh lifecycle replies");
    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0].selected_value(),
        Some(ChoiceValue::Boolean(true).canonical_bytes().as_slice())
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
