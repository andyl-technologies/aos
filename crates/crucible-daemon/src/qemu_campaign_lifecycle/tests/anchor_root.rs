//! Anchor roots kept at a branch parent's network fault park.
//!
//! The fixture is a real prepared source world paused after one recorded
//! selection, and a branch attempt whose own selection is a network fault
//! branch at exactly that configuration. A scripted lifecycle replays from
//! genesis to the world's boundary with the world's own scheduler entries,
//! so a kept world authenticates against the replay proof exactly as a
//! production anchor must.

use crucible_api::vm_lifecycle::{
    ProductionVmHotForkSourceWorld,
    prepared_multi_node_hot_fork_source_world_after_selections_for_scenario_for_test,
};
use crucible_campaign::ConfigurationArtifactId;
use crucible_qemu::{QemuTestHotForkOutcome, scripted_hot_fork_source_for_test};

use super::super::test_support::{Order, boundary_violation};
use super::*;
use crate::managed_qemu_hot_fork_source_world_pool::test_support::{
    advanced_published_root_source_for_test, scheduler_selection_for_test,
};
use crate::qemu_hot_fork_source_capture::{
    AuthenticatedPublishedRootQemuHotForkSource, QemuPublishedRootOrigin,
    QemuPublishedRootProvenance,
};
use crate::{
    AttemptExecutionKey, AttemptExecutionRuntimeBasis, QemuFinalBoundaryDrain,
    QemuHotForkSourceWorldBoundary, QemuHotForkSourceWorldKey, QemuPublishedRootAdmission,
    QemuPublishedRootRetirementError, QemuPublishedRootSink, QemuPublishedRootState,
};

/// Scheduler coordinates of the world the fixture replays to.
#[derive(Clone)]
struct WorldBoundary {
    configuration: Configuration,
    entries: Vec<SchedulerEventLogEntry>,
    quanta: u64,
    frontier: VirtualTime,
    offset: crucible::EventLogOffset,
}

impl WorldBoundary {
    fn of(world: &ProductionVmHotForkSourceWorld) -> Self {
        let continuation = world.continuation();
        let scheduler = continuation.scheduler();
        let mut entries = Vec::new();
        scheduler
            .try_for_each_event_log_entry(continuation.event_log_segments(), |entry| {
                entries.push(entry.clone());
                Ok::<_, crucible::SingleSchedulerCheckpointError>(())
            })
            .expect("read world event log");
        Self {
            configuration: continuation.configuration().clone(),
            entries,
            quanta: scheduler.quanta(),
            frontier: scheduler.frontier(),
            offset: scheduler.event_log_offset(),
        }
    }
}

/// Scripted lifecycle that replays to one parked world boundary.
struct AnchorLifecycle {
    order: Order,
    boundary: WorldBoundary,
    completed_quanta: u64,
    parked: bool,
    join_frontier: VirtualTime,
    exact_ready: bool,
    drain: Option<QemuFinalBoundaryDrain>,
    cancel_during_replay: Option<ExecutionCancellation>,
}

impl AnchorLifecycle {
    fn record(&self, effect: &'static str) {
        self.order.lock().expect("anchor order").push(effect);
    }
}

impl QemuFreshAttemptLifecycleOwner for AnchorLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, SchedulerError> {
        self.record("replay");
        if let Some(cancellation) = &self.cancel_during_replay {
            cancellation.cancel();
        }
        self.completed_quanta = self.boundary.quanta;
        Ok(crucible::QuantumOutcome {
            configuration: self.boundary.configuration.clone(),
            frontier: self.boundary.frontier,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: self.boundary.entries.clone(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: self.boundary.offset,
            scheduler_quiescence: None,
        })
    }

    fn park_held_campaign_markers(
        &mut self,
        _markers: &[&str],
        _outcome: &mut crucible::QuantumOutcome,
    ) -> Result<usize, SchedulerError> {
        self.record("park");
        self.parked = true;
        Ok(1)
    }

    fn parked_campaign_marker(
        &mut self,
        _node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        Ok(self.parked.then(|| QemuParkedCampaignMarker {
            marker: String::from("fault.transport.ready"),
            marker_icount: Icount { retired: 1 },
            marker_tick: Icount { retired: 1 },
            physical_raw_icount: Icount { retired: 2 },
            physical_icount: Icount { retired: 2 },
        }))
    }

    fn join_campaign_parks_to_frontier(&mut self) -> Result<Option<VirtualTime>, SchedulerError> {
        self.record("join");
        Ok(self.parked.then_some(self.join_frontier))
    }

    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        Ok(true)
    }

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn event_log_offset(&self) -> Result<crucible::EventLogOffset, SchedulerError> {
        Ok(self.boundary.offset)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        _cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        Err(boundary_violation("anchoring never captures a checkpoint"))
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(self.exact_ready)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &Configuration,
        _decision: SelectionDecision,
        _selected: &Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Err(boundary_violation(
            "anchor fixtures publish no guest requests",
        ))
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        Err(boundary_violation("anchoring never captures a checkpoint"))
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        Err(boundary_violation(
            "anchor fixtures have no launch profiles",
        ))
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(boundary_violation("anchor fixtures have no fault evidence"))
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        Err(boundary_violation(&format!(
            "anchoring never samples `{}`",
            node.name
        )))
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        Err(boundary_violation(
            "anchoring prepares no terminal evidence",
        ))
    }

    fn resolved_effect_trace(
        &self,
    ) -> Result<Option<crucible::model::ResolvedEffectTrace>, SchedulerError> {
        Ok(None)
    }

    fn drain_final_events_for_retention(
        &mut self,
    ) -> Result<QemuFinalBoundaryDrain, SchedulerError> {
        self.record("drain");
        self.drain
            .take()
            .ok_or_else(|| boundary_violation("final boundary drained twice"))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.record("shutdown");
        Ok(Vec::new())
    }
}

/// What source preparation does with the anchoring lifecycle.
enum AnchorPreparation {
    Prepare(Box<ProductionVmHotForkSourceWorld>),
    Recover,
    Quarantine,
}

struct AnchorFactory {
    order: Order,
    lifecycle: Option<AnchorLifecycle>,
    preparation: Option<AnchorPreparation>,
}

impl QemuFreshAttemptLifecycleFactory for AnchorFactory {
    type Lifecycle = AnchorLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order.lock().expect("anchor order").push("begin");
        self.lifecycle
            .take()
            .ok_or(AttemptWorkerFailure::Terminal("anchor fixture runs once"))
    }

    fn prepare_retained_source(
        &mut self,
        lifecycle: Self::Lifecycle,
        _source: &ScenarioDefForm,
        _boundary: &Configuration,
    ) -> QemuRetainedSourcePreparation<Self::Lifecycle> {
        self.order.lock().expect("anchor order").push("prepare");
        match self.preparation.take() {
            Some(AnchorPreparation::Prepare(world)) => {
                QemuRetainedSourcePreparation::Prepared(world)
            }
            Some(AnchorPreparation::Quarantine) => QemuRetainedSourcePreparation::Quarantined,
            Some(AnchorPreparation::Recover) | None => {
                QemuRetainedSourcePreparation::Recovered(lifecycle)
            }
        }
    }
}

/// Anchor sink recording admitted roots and answering with a scripted outcome.
struct RecordingAnchorSink {
    may_admit: bool,
    state: QemuPublishedRootState,
    outcome: QemuPublishedRootAdmission,
    admitted: Mutex<
        Vec<(
            QemuHotForkSourceWorldKey,
            ConfigurationArtifactId,
            QemuPublishedRootProvenance,
        )>,
    >,
}

impl RecordingAnchorSink {
    fn answering(outcome: QemuPublishedRootAdmission) -> Arc<Self> {
        Arc::new(Self {
            may_admit: true,
            state: QemuPublishedRootState::Absent,
            outcome,
            admitted: Mutex::new(Vec::new()),
        })
    }
}

impl QemuPublishedRootSink for RecordingAnchorSink {
    fn may_admit(&self) -> bool {
        self.may_admit
    }

    fn root_state(&self, _key: &QemuHotForkSourceWorldKey) -> QemuPublishedRootState {
        self.state
    }

    fn admit(
        &self,
        _root: AuthenticatedPublishedRootQemuHotForkSource,
    ) -> Result<QemuPublishedRootAdmission, QemuPublishedRootRetirementError> {
        Err(QemuPublishedRootRetirementError::new(
            "anchoring never admits a stop root",
        ))
    }

    fn admit_anchor(
        &self,
        root: AuthenticatedPublishedRootQemuHotForkSource,
    ) -> Result<QemuPublishedRootAdmission, QemuPublishedRootRetirementError> {
        let (key, published, source, provenance) = root.into_parts();
        self.admitted
            .lock()
            .expect("admitted anchors")
            .push((key, published, provenance));
        source
            .retire()
            .map_err(|error| QemuPublishedRootRetirementError::new(error.to_string()))?;
        Ok(self.outcome.clone())
    }
}

/// One anchoring attempt: its input, the parent world, and the branch.
struct AnchorCase {
    input: CrucibleAttemptExecution,
    world: Option<ProductionVmHotForkSourceWorld>,
    boundary: WorldBoundary,
    parent_artifact: ConfigurationArtifactId,
}

fn network_scenario() -> ScenarioDefForm {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let selectables = ScenarioSelectables::new(
        scenario.world(),
        ScenarioSelectableLimits::default(),
        vec![crucible::NetworkFaultSelectable::declaration().expect("network declaration")],
    )
    .expect("network selectables");
    scenario
        .with_selectables(selectables)
        .expect("attach network selectables")
}

/// Builds a branch attempt whose own selection is the network fault branch
/// at `parent`, recorded at `at`.
fn branch_input(
    scenario: &ScenarioDefForm,
    parent: &Configuration,
    at: VirtualTime,
) -> (CrucibleAttemptExecution, ConfigurationArtifactId) {
    let template =
        modeled_fresh_runner_input_for_scenario(scenario.clone(), StopCondition::Terminal);
    let selectable = crucible::NetworkFaultSelectable::next(
        scenario,
        parent,
        crucible::NetworkFaultPhase::First,
        at,
        &[],
    )
    .expect("network choice resolves")
    .expect("network choice is offered");
    let value =
        crucible::NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 0, 0)
            .expect("network fault value");
    let selection = selectable
        .branch_selection(value)
        .expect("branch selection");
    let branch = selectable
        .resolve_branch(&selection)
        .expect("network fault branch");
    let selected = branch.selected().clone();
    let replay = crucible::SignalFaultCampaignReplayPlan::empty(selected.clone())
        .with_network_branches(vec![branch])
        .expect("network replay plan");

    let discovery = selectable.discovery().expect("network discovery");
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("anchor-root-branch", 1024 * 1024)),
        Arc::new(MemoryRefBackend::new()),
    );
    repository
        .publish_choice_domain(discovery.domain())
        .expect("publish network domain");
    repository
        .publish_selectable(discovery.declaration())
        .expect("publish network selectable");
    repository
        .publish_choice_opportunity(discovery.opportunity())
        .expect("publish network opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish network selection");
    let resolved = repository
        .resolve_selection(selection.id().expect("network selection id"))
        .expect("resolve network selection");

    let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
    let parent_artifact = ConfigurationArtifact::new(
        template.lineage().scenario(),
        template.lineage().scenario_content(),
        parent_id,
        1,
        b"anchor-parent-configuration".to_vec(),
    )
    .and_then(|artifact| artifact.id())
    .expect("parent configuration artifact");
    let SelectionOrigin::CampaignBranch { branch_point, edge } = selection.origin() else {
        panic!("network branch selection must be a campaign branch")
    };
    let path =
        BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)]).expect("branch path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: parent_artifact,
            selection: selection.id().expect("network selection id"),
        },
        path.id().expect("branch path id"),
        StopCondition::NextChoice,
    )
    .expect("branch attempt");
    let input = CrucibleAttemptExecution::from_test_parts(
        template.lineage().clone(),
        scenario.clone(),
        attempt,
        path,
        CrucibleResolvedAttemptStart::Branch {
            parent: parent.clone(),
            selection: Box::new(resolved),
            selected,
        },
    )
    .with_test_signal_fault_replay(replay);
    (input, parent_artifact)
}

fn anchor_case() -> AnchorCase {
    let scenario = network_scenario();
    let node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let (_nodes, world) =
        prepared_multi_node_hot_fork_source_world_after_selections_for_scenario_for_test(
            &scenario,
            vec![node],
            vec![scheduler_selection_for_test(&scenario, "anchor.advance")],
        )
        .expect("parent world");
    let boundary = WorldBoundary::of(&world);
    let (input, parent_artifact) =
        branch_input(&scenario, &boundary.configuration, boundary.frontier);
    AnchorCase {
        input,
        world: Some(world),
        boundary,
        parent_artifact,
    }
}

fn anchor_context(input: &CrucibleAttemptExecution) -> AttemptExecutionContext {
    context_with_cancellation(input, ExecutionCancellation::default())
}

/// Binds the execution to the input's own lineage, as the executor does.
fn context_with_cancellation(
    input: &CrucibleAttemptExecution,
    cancellation: ExecutionCancellation,
) -> AttemptExecutionContext {
    context(resources(4), cancellation).with_runtime_basis(AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            input.lineage().id().expect("lineage id"),
            input.attempt().id().expect("attempt id"),
        ),
        ExecutionId::from_bytes([0x5a; 16]).expect("execution id"),
    ))
}

fn anchor_lifecycle(order: &Order, boundary: &WorldBoundary) -> AnchorLifecycle {
    AnchorLifecycle {
        order: Arc::clone(order),
        boundary: boundary.clone(),
        completed_quanta: 0,
        parked: false,
        join_frontier: boundary.frontier,
        exact_ready: true,
        drain: Some(QemuFinalBoundaryDrain::Retainable),
        cancel_during_replay: None,
    }
}

type AnchorRunner = QemuFreshExecutionRunner<AnchorFactory, FakeFreshDriver>;

fn anchor_runner(
    order: &Order,
    lifecycle: AnchorLifecycle,
    preparation: AnchorPreparation,
    sink: Option<Arc<RecordingAnchorSink>>,
) -> AnchorRunner {
    let runner = QemuFreshExecutionRunner::new(
        AnchorFactory {
            order: Arc::clone(order),
            lifecycle: Some(lifecycle),
            preparation: Some(preparation),
        },
        FakeFreshDriver {
            order: Arc::clone(order),
            failure: None,
        },
    );
    match sink {
        Some(sink) => runner.with_published_root_retention(sink),
        None => runner,
    }
}

fn effects(order: &Order) -> Vec<&'static str> {
    order.lock().expect("anchor order").clone()
}

#[test]
fn anchor_root_keeps_the_replayed_parent_park_and_emits_no_product() {
    let mut case = anchor_case();
    let order = Order::default();
    let sink = RecordingAnchorSink::answering(QemuPublishedRootAdmission::Admitted);
    let world = case.world.take().expect("parent world");
    let mut runner = anchor_runner(
        &order,
        anchor_lifecycle(&order, &case.boundary),
        AnchorPreparation::Prepare(Box::new(world)),
        Some(Arc::clone(&sink)),
    );

    let outcome = runner
        .materialize_anchor_root(&case.input, &anchor_context(&case.input))
        .expect("anchoring succeeds");

    assert_eq!(outcome, QemuAnchorRootOutcome::Admitted);
    // The kept world is never shut down, and no observation is sealed.
    assert_eq!(
        effects(&order),
        ["begin", "replay", "park", "join", "drain", "prepare"]
    );
    assert!(runner.pending_retention.is_none());
    let admitted = sink.admitted.lock().expect("admitted anchors");
    let [(key, published, provenance)] = admitted.as_slice() else {
        panic!("exactly one anchor must reach the sink")
    };
    assert_eq!(
        key.boundary(),
        QemuHotForkSourceWorldBoundary::PublishedBoundary
    );
    assert_eq!(key.configuration(), case.boundary.configuration.id());
    assert_eq!(*published, case.parent_artifact);
    assert_eq!(
        provenance.origin(),
        QemuPublishedRootOrigin::BranchParentAnchor
    );
    assert_eq!(provenance.configuration(), &case.boundary.configuration);
    assert_eq!(provenance.live_network_choice_pause(), Some(true));
}

#[test]
fn anchor_preconditions_refuse_before_any_lifecycle_effect() {
    let case = anchor_case();
    let discovery = fresh_runner_input();
    // The same branch attempt with no recorded network fault branch.
    let without_branches = CrucibleAttemptExecution::from_test_parts(
        case.input.lineage().clone(),
        case.input.scenario().clone(),
        case.input.attempt().clone(),
        case.input.path().clone(),
        case.input.start().clone(),
    );
    let context = anchor_context(&case.input);
    let cancellation = ExecutionCancellation::default();
    let canceled = context_with_cancellation(&case.input, cancellation.clone());
    cancellation.cancel();
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"anchor-resume-checkpoint",
    ))
    .expect("resume checkpoint");
    let capture = AttemptStartMode::CaptureMaterializedStart {
        configuration: case.parent_artifact,
    };
    let cases: [(
        &str,
        &CrucibleAttemptExecution,
        AttemptExecutionContext,
        bool,
    ); 8] = [
        ("anchor-not-branch-start", &discovery, context.clone(), true),
        (
            "anchor-parent-not-network-branch",
            &without_branches,
            context.clone(),
            true,
        ),
        (
            "anchor-start-mode-not-execute",
            &case.input,
            context.clone().with_start_mode(capture),
            true,
        ),
        (
            "anchor-resume-checkpoint",
            &case.input,
            context.clone().with_resume_checkpoint(Some(checkpoint)),
            true,
        ),
        ("anchor-attempt-canceled", &case.input, canceled, true),
        (
            "anchor-runtime-basis-absent",
            &case.input,
            fresh_runner_context(),
            true,
        ),
        ("anchor-pool-full", &case.input, context.clone(), false),
        ("anchor-retention-disabled", &case.input, context, true),
    ];

    for (expected, input, context, may_admit) in cases {
        let order = Order::default();
        let sink = (expected != "anchor-retention-disabled").then(|| {
            Arc::new(RecordingAnchorSink {
                may_admit,
                state: QemuPublishedRootState::Absent,
                outcome: QemuPublishedRootAdmission::Admitted,
                admitted: Mutex::new(Vec::new()),
            })
        });
        let mut runner = anchor_runner(
            &order,
            anchor_lifecycle(&order, &case.boundary),
            AnchorPreparation::Recover,
            sink,
        );

        let outcome = runner
            .materialize_anchor_root(input, &context)
            .expect("a refused anchor is a decline");

        assert_eq!(
            outcome,
            QemuAnchorRootOutcome::Declined(expected),
            "{expected}"
        );
        assert!(effects(&order).is_empty(), "{expected} started a lifecycle");
    }
}

/// The pool is read before replay: an invalidated coordinate declines and a
/// live root already serves the attempt, neither starting a lifecycle.
#[test]
fn anchor_reads_the_root_coordinate_before_any_replay() {
    let case = anchor_case();
    let cases = [
        (
            QemuPublishedRootState::Unusable,
            QemuAnchorRootOutcome::Declined("anchor-root-invalidated"),
        ),
        (
            QemuPublishedRootState::Live,
            QemuAnchorRootOutcome::Admitted,
        ),
    ];

    for (state, expected) in cases {
        let order = Order::default();
        // Even a full pool reports a live root as serving the attempt.
        let sink = Arc::new(RecordingAnchorSink {
            may_admit: false,
            state,
            outcome: QemuPublishedRootAdmission::Admitted,
            admitted: Mutex::new(Vec::new()),
        });
        let mut runner = anchor_runner(
            &order,
            anchor_lifecycle(&order, &case.boundary),
            AnchorPreparation::Recover,
            Some(Arc::clone(&sink)),
        );

        let outcome = runner
            .materialize_anchor_root(&case.input, &anchor_context(&case.input))
            .expect("the root coordinate answers without failure");

        assert_eq!(outcome, expected, "{state:?}");
        assert!(effects(&order).is_empty(), "{state:?} started a lifecycle");
        assert!(sink.admitted.lock().expect("admitted anchors").is_empty());
    }
}

/// One change to an otherwise admissible anchoring lifecycle.
type LifecycleScript = dyn Fn(&mut AnchorLifecycle);

#[test]
fn anchor_boundary_refusals_shut_the_replay_world_down() {
    let case = anchor_case();
    let not_ready = |lifecycle: &mut AnchorLifecycle| lifecycle.exact_ready = false;
    let not_retainable = |lifecycle: &mut AnchorLifecycle| {
        lifecycle.drain = Some(QemuFinalBoundaryDrain::Ineligible(
            "held-campaign-marker-stop",
        ));
    };
    let diverged = |lifecycle: &mut AnchorLifecycle| {
        lifecycle.join_frontier = VirtualTime {
            ticks: lifecycle.boundary.frontier.ticks + 1,
        };
    };
    let cases: [(&str, &LifecycleScript, &[&str]); 3] = [
        (
            "anchor-boundary-not-exact-ready",
            &not_ready,
            &["begin", "replay", "park", "join", "shutdown"],
        ),
        (
            "anchor-boundary-not-retainable",
            &not_retainable,
            &["begin", "replay", "park", "join", "drain", "shutdown"],
        ),
        (
            "anchor-replay-failed",
            &diverged,
            &["begin", "replay", "park", "join", "shutdown"],
        ),
    ];

    for (expected, script, expected_effects) in cases {
        let order = Order::default();
        let mut lifecycle = anchor_lifecycle(&order, &case.boundary);
        script(&mut lifecycle);
        let sink = RecordingAnchorSink::answering(QemuPublishedRootAdmission::Admitted);
        let mut runner = anchor_runner(
            &order,
            lifecycle,
            AnchorPreparation::Recover,
            Some(Arc::clone(&sink)),
        );

        let outcome = runner
            .materialize_anchor_root(&case.input, &anchor_context(&case.input))
            .expect("a refused boundary is a decline");

        assert_eq!(
            outcome,
            QemuAnchorRootOutcome::Declined(expected),
            "{expected}"
        );
        assert_eq!(effects(&order), expected_effects, "{expected}");
        assert!(sink.admitted.lock().expect("admitted anchors").is_empty());
    }
}

#[test]
fn anchor_preparation_failures_decline_without_admission() {
    let case = anchor_case();
    let elsewhere = advanced_published_root_source_for_test("anchor.elsewhere");
    let cases = [
        (
            "anchor-source-preparation-declined",
            AnchorPreparation::Recover,
            vec![
                "begin", "replay", "park", "join", "drain", "prepare", "shutdown",
            ],
        ),
        (
            "anchor-source-preparation-failed",
            AnchorPreparation::Quarantine,
            vec!["begin", "replay", "park", "join", "drain", "prepare"],
        ),
        (
            "anchor-prepared-configuration-mismatch",
            AnchorPreparation::Prepare(Box::new(elsewhere)),
            vec!["begin", "replay", "park", "join", "drain", "prepare"],
        ),
    ];

    for (expected, preparation, expected_effects) in cases {
        let order = Order::default();
        let sink = RecordingAnchorSink::answering(QemuPublishedRootAdmission::Admitted);
        let mut runner = anchor_runner(
            &order,
            anchor_lifecycle(&order, &case.boundary),
            preparation,
            Some(Arc::clone(&sink)),
        );

        let outcome = runner
            .materialize_anchor_root(&case.input, &anchor_context(&case.input))
            .expect("a failed preparation is a decline");

        assert_eq!(
            outcome,
            QemuAnchorRootOutcome::Declined(expected),
            "{expected}"
        );
        assert_eq!(effects(&order), expected_effects, "{expected}");
        assert!(sink.admitted.lock().expect("admitted anchors").is_empty());
    }
}

#[test]
fn anchor_pool_answers_map_to_admission_or_named_declines() {
    let cases = [
        (
            QemuPublishedRootAdmission::AlreadyRetained,
            QemuAnchorRootOutcome::Admitted,
        ),
        (
            QemuPublishedRootAdmission::Rejected(String::from("anchor-child-capacity")),
            QemuAnchorRootOutcome::Declined("anchor-child-capacity"),
        ),
        (
            QemuPublishedRootAdmission::Rejected(String::from("catalog full")),
            QemuAnchorRootOutcome::Declined("anchor-pool-rejected"),
        ),
    ];

    for (answer, expected) in cases {
        let mut case = anchor_case();
        let order = Order::default();
        let world = case.world.take().expect("parent world");
        let mut runner = anchor_runner(
            &order,
            anchor_lifecycle(&order, &case.boundary),
            AnchorPreparation::Prepare(Box::new(world)),
            Some(RecordingAnchorSink::answering(answer)),
        );

        let outcome = runner
            .materialize_anchor_root(&case.input, &anchor_context(&case.input))
            .expect("every pool answer is an outcome");

        assert_eq!(outcome, expected);
    }
}

#[test]
fn anchor_cancellation_during_replay_shuts_down_and_cancels() {
    let case = anchor_case();
    let order = Order::default();
    let cancellation = ExecutionCancellation::default();
    let context = context_with_cancellation(&case.input, cancellation.clone());
    let mut lifecycle = anchor_lifecycle(&order, &case.boundary);
    lifecycle.cancel_during_replay = Some(cancellation);
    let mut runner = anchor_runner(
        &order,
        lifecycle,
        AnchorPreparation::Recover,
        Some(RecordingAnchorSink::answering(
            QemuPublishedRootAdmission::Admitted,
        )),
    );

    let failure = runner
        .materialize_anchor_root(&case.input, &context)
        .expect_err("cancellation belongs to the attempt");

    assert!(matches!(failure, AttemptWorkerFailure::Canceled(_)));
    // The quantum completes and parks before replay observes the cancel.
    assert_eq!(effects(&order), ["begin", "replay", "park", "shutdown"]);
}
