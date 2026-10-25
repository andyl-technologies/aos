//! Start replay parks network fault phase markers and crosses recorded
//! network fault branches like the modeled driver.

use super::*;

/// Fake all-VM park at one network fault phase marker.
///
/// Every VM parks once the lifecycle completes `parks_after_quanta`; VMs stay
/// physically parked through the scheduler join until each is released. The
/// park publishes `published` into the parked quantum's outcome, and the
/// branch append returns `branch_entries`, as the production scheduler does.
pub(super) struct FakeNetworkPark {
    parks_after_quanta: u64,
    marker: &'static str,
    joined_at: VirtualTime,
    parked: bool,
    released: BTreeSet<NodeId>,
    pub(super) published: Vec<SchedulerEventLogEntry>,
    pub(super) branch_entries: Vec<SchedulerEventLogEntry>,
}

impl FakeNetworkPark {
    pub(super) fn observe_quantum(&mut self, completed_quanta: u64) {
        self.parked |= completed_quanta == self.parks_after_quanta;
    }

    pub(super) fn parked_marker(&self, node: &NodeId) -> Option<QemuParkedCampaignMarker> {
        (self.parked && !self.released.contains(node)).then(|| QemuParkedCampaignMarker {
            marker: String::from(self.marker),
            marker_icount: Icount { retired: 1 },
            marker_tick: Icount { retired: 1 },
            physical_raw_icount: Icount { retired: 2 },
            physical_icount: Icount { retired: 2 },
        })
    }

    pub(super) fn joined_at(&self) -> Option<VirtualTime> {
        self.parked.then_some(self.joined_at)
    }

    pub(super) fn release(&mut self, node: &NodeId, marker: &str) -> Result<(), SchedulerError> {
        if self.parked_marker(node).is_none() || marker != self.marker {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("fake VM `{}` has no park at `{marker}`", node.name),
            });
        }
        self.released.insert(node.clone());
        Ok(())
    }
}

fn replay_lifecycle() -> FakeFreshLifecycle {
    FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        released_host_outcome: None,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
        network_park: None,
    }
}

fn network_fault_input() -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let selectables = ScenarioSelectables::new(
        scenario.world(),
        ScenarioSelectableLimits::default(),
        vec![crucible::NetworkFaultSelectable::declaration().expect("network declaration")],
    )
    .expect("network selectables");
    let scenario = scenario
        .with_selectables(selectables)
        .expect("attach network selectables");
    modeled_fresh_runner_input_for_scenario(scenario, StopCondition::Terminal)
}

fn replay_step(parent: &Configuration) -> Configuration {
    accepted_step(
        parent,
        Decision::RngDraw(RngDecision::ordinal(
            RngStreamId::from_name("fresh-runner-non-genesis"),
            0,
            7,
        )),
    )
}

/// A replay crossing staggered phase markers parks each held VM per quantum.
#[test]
fn start_replay_parks_network_phase_markers_only_when_declared() {
    let cases = [
        (fresh_runner_input(), vec!["replay", "replay"]),
        (
            network_fault_input(),
            vec!["replay", "park", "replay", "park"],
        ),
    ];

    for (input, expected) in cases {
        let parent = input.start().configuration().clone();
        let target = replay_step(&replay_step(&parent));
        let mut lifecycle = replay_lifecycle();

        let replay = materialize_start_from::<(), ()>(
            &mut lifecycle,
            &input,
            parent,
            &target,
            &fresh_runner_context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("start replay reaches its target");

        assert_eq!(replay.into_parts().1, 2);
        assert_eq!(*lifecycle.order.lock().expect("operation order"), expected);
    }
}

/// Builds a discovery input whose start is the selected child of one
/// recorded network fault branch taken after one replay quantum.
fn network_fault_branch_input(at: VirtualTime) -> (CrucibleAttemptExecution, Configuration) {
    network_fault_branch_input_with_tail(at, 0)
}

/// Builds the same input with `tail` further replay quanta past the branch.
fn network_fault_branch_input_with_tail(
    at: VirtualTime,
    tail: usize,
) -> (CrucibleAttemptExecution, Configuration) {
    let template = network_fault_input();
    let scenario = template.scenario().clone();
    let parent = replay_step(&Configuration::genesis(scenario.scenario_def()));
    let selectable = crucible::NetworkFaultSelectable::next(
        &scenario,
        &parent,
        crucible::NetworkFaultPhase::First,
        at,
        &[],
    )
    .expect("network choice resolves")
    .expect("network choice is offered");
    let value =
        crucible::NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 0, 0)
            .expect("network fault value");
    let branch = selectable
        .resolve_branch(
            &selectable
                .branch_selection(value)
                .expect("branch selection"),
        )
        .expect("network fault branch");
    let target = (0..tail).fold(branch.selected().clone(), |configuration, _| {
        replay_step(&configuration)
    });
    let replay = crucible::SignalFaultCampaignReplayPlan::empty(target.clone())
        .with_network_branches(vec![branch])
        .expect("network replay plan");

    let configuration_id = ConfigurationId::from_hash(CampaignHash::from_bytes(target.id().bytes));
    let configuration_content = ConfigurationArtifact::new(
        template.lineage().scenario(),
        template.lineage().scenario_content(),
        configuration_id,
        1,
        b"network-fault-branch-configuration".to_vec(),
    )
    .and_then(|artifact| artifact.id())
    .expect("branch configuration artifact");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path id"),
        StopCondition::Terminal,
    )
    .expect("branch discovery attempt");
    let input = CrucibleAttemptExecution::from_test_parts(
        template.lineage().clone(),
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover {
            configuration: target.clone(),
        },
    )
    .with_test_signal_fault_replay(replay);
    (input, target)
}

fn parked_lifecycle(joined_at: VirtualTime) -> FakeFreshLifecycle {
    FakeFreshLifecycle {
        network_park: Some(FakeNetworkPark {
            parks_after_quanta: 1,
            marker: "fault.transport.ready",
            joined_at,
            parked: false,
            released: BTreeSet::new(),
            published: Vec::new(),
            branch_entries: Vec::new(),
        }),
        ..replay_lifecycle()
    }
}

/// Parks and branch appends add scheduler entries outside a driven quantum;
/// the observed evidence must still hold every entry, densely.
#[test]
fn observed_lifecycle_records_park_publications_and_branch_entries() {
    let at = VirtualTime { ticks: 40 };
    let (input, _target) = network_fault_branch_input(at);
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let branch = input.signal_fault_replay().network_branches()[0].clone();
    let published = SchedulerEventLogEntry::execution_budget_exhausted(0, at, "park-peer");
    let selection = SchedulerEventLogEntry::execution_budget_exhausted(1, at, "branch-selection");
    let mut lifecycle = parked_lifecycle(at);
    let park = lifecycle.network_park.as_mut().expect("network park");
    park.published = vec![published.clone()];
    park.branch_entries = vec![selection.clone()];
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed =
        QemuObservedFreshAttemptLifecycle::new(lifecycle, Vec::new(), evidence.clone());

    let mut outcome = observed
        .drive_quantum(QuantumRequest {
            configuration: genesis,
            control: Vec::new(),
        })
        .expect("parked quantum");
    observed
        .park_held_campaign_markers(
            &crate::qemu_campaign_driver::NETWORK_FAULT_PHASE_MARKERS,
            &mut outcome,
        )
        .expect("park publishes its peers");
    observed
        .append_network_fault_campaign_branch(&branch)
        .expect("branch append");

    let snapshot = evidence.snapshot().expect("observed evidence");
    assert_eq!(
        snapshot.event_log_entries().expect("recorded entries"),
        vec![published, selection]
    );
}

/// With every VM parked no quantum can advance, so replay joins the parks,
/// commits the recorded Selection, and releases each VM itself.
#[test]
fn start_replay_crosses_a_recorded_network_fault_branch_at_the_joined_park() {
    let at = VirtualTime { ticks: 40 };
    let (input, target) = network_fault_branch_input(at);
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let mut lifecycle = parked_lifecycle(at);

    let replay = materialize_start_from::<(), ()>(
        &mut lifecycle,
        &input,
        genesis,
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis(),
    )
    .expect("start replay crosses the network fault boundary");

    let vm_count = input.scenario().world().vm_nodes().iter().count();
    let mut expected = vec!["replay", "park", "join", "append"];
    expected.extend(std::iter::repeat_n("release", vm_count));
    assert_eq!(*lifecycle.order.lock().expect("operation order"), expected);
    let park = lifecycle.network_park.as_ref().expect("network park");
    assert_eq!(park.released.len(), vm_count);
    assert_eq!(replay.frontier, at);
    assert_eq!(replay.completed_quanta, lifecycle.completed_quanta);
    assert_eq!(replay.completed_quanta, 2);
    assert_eq!(replay.restored_configuration.as_ref(), Some(&target));
}

/// A joined frontier that differs from the recorded boundary is a divergence,
/// and no VM is released into an unrecorded environment.
#[test]
fn start_replay_refuses_a_network_fault_branch_at_another_frontier() {
    let (input, target) = network_fault_branch_input(VirtualTime { ticks: 40 });
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let mut lifecycle = parked_lifecycle(VirtualTime { ticks: 41 });

    let error = materialize_start_from::<(), ()>(
        &mut lifecycle,
        &input,
        genesis,
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis(),
    )
    .expect_err("a mismatched park frontier must not cross the branch");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::DivergedAt {
                reason: "network fault boundary",
                ..
            }
        ))
    ));
    assert_eq!(
        *lifecycle.order.lock().expect("operation order"),
        vec!["replay", "park", "join"]
    );
}

/// Parked lifecycle whose park and branch append publish one entry each.
fn publishing_parked_lifecycle(at: VirtualTime) -> FakeFreshLifecycle {
    let mut lifecycle = parked_lifecycle(at);
    let park = lifecycle.network_park.as_mut().expect("network park");
    park.published = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        at,
        "park-peer",
    )];
    park.branch_entries = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        1,
        at,
        "branch-selection",
    )];
    lifecycle
}

/// An anchor stop joins the parks at the recorded frontier and returns before
/// the branch quantum, so every VM stays parked and nothing is released.
#[test]
fn start_replay_stops_at_an_anchor_with_parks_joined_and_unreleased() {
    let at = VirtualTime { ticks: 40 };
    let (input, target) = network_fault_branch_input(at);
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let branch = input.signal_fault_replay().network_branches()[0].clone();
    let mut lifecycle = publishing_parked_lifecycle(at);

    let replay = materialize_start_from::<(), ()>(
        &mut lifecycle,
        &input,
        genesis,
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis().with_anchor_stop(branch.parent().id()),
    )
    .expect("start replay stops at its anchor");

    assert!(replay.anchor_reached());
    assert_eq!(replay.restored_configuration(), Some(branch.parent()));
    assert_eq!(replay.frontier, branch.at());
    assert_eq!(replay.completed_quanta, 1);
    assert_eq!(replay.completed_quanta, lifecycle.completed_quanta);
    assert_eq!(replay.event_log.len(), 1);
    assert_eq!(
        *lifecycle.order.lock().expect("operation order"),
        vec!["replay", "park", "join"]
    );
    let park = lifecycle.network_park.as_ref().expect("network park");
    assert!(park.released.is_empty());
    assert_eq!(park.branch_entries.len(), 1);
    for vm in input.scenario().world().vm_nodes().iter() {
        assert!(park.parked_marker(&vm.id).is_some());
    }
}

/// Crossing the branch from an anchor stop yields exactly the entries, quantum
/// coordinate, and frontier of one uninterrupted replay to the same target.
#[test]
fn resuming_from_an_anchor_stop_matches_an_uninterrupted_replay() {
    let at = VirtualTime { ticks: 40 };
    let (input, target) = network_fault_branch_input(at);
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let parent = input.signal_fault_replay().network_branches()[0]
        .parent()
        .clone();

    let mut uninterrupted_lifecycle = publishing_parked_lifecycle(at);
    let uninterrupted = materialize_start_from::<(), ()>(
        &mut uninterrupted_lifecycle,
        &input,
        genesis.clone(),
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis(),
    )
    .expect("uninterrupted replay reaches its target");

    let mut anchored_lifecycle = publishing_parked_lifecycle(at);
    let anchored = materialize_start_from::<(), ()>(
        &mut anchored_lifecycle,
        &input,
        genesis,
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis().with_anchor_stop(parent.id()),
    )
    .expect("anchored replay stops at its anchor");
    // A world kept at the anchor carries only its scheduler continuation, so
    // the resumed replay starts from those parts at the anchor, as a forked
    // child does.
    let (log, quanta, frontier, quiescence, verdict) = anchored.into_parts();
    assert!(verdict.is_none());
    let resumed = materialize_start_from::<(), ()>(
        &mut anchored_lifecycle,
        &input,
        parent.clone(),
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::from_resume_parts(
            parent,
            log,
            quanta,
            frontier,
            quiescence.unwrap_or_default(),
            None,
        ),
    )
    .expect("resumed replay crosses the anchored branch");

    assert!(!resumed.anchor_reached());
    assert_eq!(resumed.restored_configuration(), Some(&target));
    assert_eq!(
        resumed.event_log.identity().expect("resumed log identity"),
        uninterrupted
            .event_log
            .identity()
            .expect("uninterrupted log identity")
    );
    assert_eq!(resumed.completed_quanta, uninterrupted.completed_quanta);
    assert_eq!(resumed.frontier, uninterrupted.frontier);
    assert_eq!(
        anchored_lifecycle.completed_quanta,
        uninterrupted_lifecycle.completed_quanta
    );
    let vm_count = input.scenario().world().vm_nodes().iter().count();
    let mut expected = vec!["replay", "park", "join", "join", "append"];
    expected.extend(std::iter::repeat_n("release", vm_count));
    assert_eq!(
        *anchored_lifecycle.order.lock().expect("operation order"),
        expected
    );
}

/// An anchor that names a configuration replay never parks at is inert.
#[test]
fn start_replay_ignores_an_anchor_that_is_not_a_parked_branch_parent() {
    let at = VirtualTime { ticks: 40 };
    let (input, target) = network_fault_branch_input(at);
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let mut lifecycle = parked_lifecycle(at);

    let replay = materialize_start_from::<(), ()>(
        &mut lifecycle,
        &input,
        genesis.clone(),
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis().with_anchor_stop(genesis.id()),
    )
    .expect("replay reaches its target past an inert anchor");

    assert!(!replay.anchor_reached());
    assert_eq!(replay.restored_configuration(), Some(&target));
}

/// Replay starts only where the lifecycle stands: a restored boundary other
/// than the requested source, or a fresh lifecycle asked to start past
/// genesis, fails closed before any quantum runs.
#[test]
fn start_replay_refuses_a_source_the_lifecycle_does_not_stand_at() {
    let at = VirtualTime { ticks: 40 };
    let (input, target) = network_fault_branch_input(at);
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let parent = input.signal_fault_replay().network_branches()[0]
        .parent()
        .clone();
    let restored_at_genesis = QemuFreshStartMaterialization::from_resume_parts(
        genesis,
        RetainedAttemptLog::new(DEFAULT_MAXIMUM_EVENT_LOG_BYTES),
        0,
        VirtualTime::default(),
        SchedulerQuiescence::default(),
        None,
    );
    let cases = [
        (restored_at_genesis, parent.clone(), "genesis-restored"),
        (QemuFreshStartMaterialization::genesis(), parent, "fresh"),
    ];

    for (materialization, source, label) in cases {
        let mut lifecycle = publishing_parked_lifecycle(at);

        let error = materialize_start_from::<(), ()>(
            &mut lifecycle,
            &input,
            source,
            &target,
            &fresh_runner_context(),
            materialization,
        )
        .expect_err("a lifecycle elsewhere must not replay");

        assert!(
            matches!(
                error,
                AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::SourceMismatch { .. }
                ))
            ),
            "{label}: {error:?}"
        );
        assert_eq!(lifecycle.completed_quanta, 0, "{label}");
    }
}

/// The shape of a child forked from an anchor root kept at a network fault
/// park: its suffix opens by crossing that recorded branch, runs on to the
/// parent, and the cursor ends past the edge. A failure after the crossing
/// but before the parent is a suffix failure.
#[test]
fn ancestor_suffix_crosses_a_network_fault_branch_inside_the_suffix() {
    let at = VirtualTime { ticks: 40 };
    // Root C at the park, the branch, two suffix quanta to the parent P, and
    // one edge quantum.
    let (input, target) = network_fault_branch_input_with_tail(at, 3);
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let root = input.signal_fault_replay().network_branches()[0]
        .parent()
        .clone();
    let edge = target.schedule.len() - 1;
    let anchored = |lifecycle: &mut FakeFreshLifecycle| {
        let anchored = materialize_start_from::<(), ()>(
            lifecycle,
            &input,
            genesis.clone(),
            &target,
            &fresh_runner_context(),
            QemuFreshStartMaterialization::genesis().with_anchor_stop(root.id()),
        )
        .expect("replay stops at the root's park");
        let (log, quanta, frontier, quiescence, _verdict) = anchored.into_parts();
        QemuFreshStartMaterialization::from_resume_parts(
            root.clone(),
            log,
            quanta,
            frontier,
            quiescence.unwrap_or_default(),
            None,
        )
    };

    let mut lifecycle = publishing_parked_lifecycle(at);
    let start = anchored(&mut lifecycle);
    let mut cursor = StartReplayCursor::default();
    let replay = materialize_start_from_tracked::<(), ()>(
        &mut lifecycle,
        &input,
        root.clone(),
        &target,
        &fresh_runner_context(),
        start,
        &mut cursor,
    )
    .expect("the suffix crosses the recorded branch and reaches the target");
    assert_eq!(replay.restored_configuration(), Some(&target));
    assert_eq!(cursor.position(), (target.schedule.len(), false));

    // The world turns terminal one quantum past the crossing, inside the
    // suffix: that contradicts the root, not the attempt.
    let mut lifecycle = publishing_parked_lifecycle(at);
    let start = anchored(&mut lifecycle);
    lifecycle.terminal_after_replay = true;
    let mut cursor = StartReplayCursor::default();
    let failure = materialize_start_from_tracked::<(), ()>(
        &mut lifecycle,
        &input,
        root.clone(),
        &target,
        &fresh_runner_context(),
        start,
        &mut cursor,
    )
    .expect_err("a terminal suffix stops replay");
    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Terminated
        ))
    ));
    assert_eq!(cursor.position(), (root.schedule.len() + 2, false));
    assert!(cursor.failed_before(&failure, edge));
}

/// A crossing that fails at the branch is the attempt's own edge when the
/// branch is its edge, and root drift when the branch lies in a suffix.
#[test]
fn network_fault_crossing_failure_belongs_to_the_edge_only_at_the_edge() {
    let (input, target) = network_fault_branch_input(VirtualTime { ticks: 40 });
    let genesis = Configuration::genesis(input.scenario().scenario_def());
    let branch_index = target.schedule.len() - 1;
    let mut lifecycle = parked_lifecycle(VirtualTime { ticks: 41 });
    let mut cursor = StartReplayCursor::default();

    let failure = materialize_start_from_tracked::<(), ()>(
        &mut lifecycle,
        &input,
        genesis,
        &target,
        &fresh_runner_context(),
        QemuFreshStartMaterialization::genesis(),
        &mut cursor,
    )
    .expect_err("a mismatched park frontier must not cross the branch");

    assert!(!cursor.failed_before(&failure, branch_index));
    assert!(cursor.failed_before(&failure, branch_index + 1));
}
