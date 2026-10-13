//! Start replay parks network fault phase markers and crosses recorded
//! network fault branches like the modeled driver.

use super::*;

/// Fake all-VM park at one network fault phase marker.
///
/// Every VM parks once the lifecycle completes `parks_after_quanta`; VMs stay
/// physically parked through the scheduler join until each is released.
pub(super) struct FakeNetworkPark {
    parks_after_quanta: u64,
    marker: &'static str,
    joined_at: VirtualTime,
    parked: bool,
    released: BTreeSet<NodeId>,
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
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
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

        assert_eq!(replay.into_parts().2, 2);
        assert_eq!(*lifecycle.order.lock().expect("operation order"), expected);
    }
}

/// Builds a discovery input whose start is the selected child of one
/// recorded network fault branch taken after one replay quantum.
fn network_fault_branch_input(at: VirtualTime) -> (CrucibleAttemptExecution, Configuration) {
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
    let target = branch.selected().clone();
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
        }),
        ..replay_lifecycle()
    }
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
