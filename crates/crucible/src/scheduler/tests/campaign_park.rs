//! Campaign-marker parks for staggered all-VM atomic boundaries.

use super::*;

fn vm(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn runnable(name: &str, counter: u64) -> SchedulerScenarioNode {
    test_scenario_node(
        name,
        counter,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    )
}

fn logical_time(scheduler: &SingleScheduler, name: &str) -> u64 {
    let node = scheduler
        .nodes
        .iter()
        .find(|node| node.id.node.name == name)
        .unwrap_or_else(|| panic!("test node `{name}` should exist"));
    scheduler
        .node_scheduler_time(node)
        .unwrap_or_else(|error| panic!("test node time should project: {error}"))
        .ticks
}

fn candidate_names(scheduler: &SingleScheduler) -> Vec<String> {
    scheduler
        .advance_candidates()
        .unwrap_or_else(|error| panic!("candidates should project: {error}"))
        .into_iter()
        .map(|candidate| scheduler.nodes[candidate.index].id.node.name.clone())
        .collect()
}

#[test]
fn parked_vm_leaves_runs_frontier_and_quiescence() {
    let mut scheduler = test_scheduler(vec![runnable("a", 20), runnable("b", 40)], Vec::new());
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 20 });

    scheduler
        .park_campaign_marker_node(&vm("a"))
        .unwrap_or_else(|error| panic!("live VM should park: {error}"));

    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });
    assert_eq!(scheduler.campaign_parked_nodes(), vec![vm("a")]);
    assert_eq!(candidate_names(&scheduler), vec![String::from("b")]);
    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should project: {error}"));
    assert!(!quiescence.blockers.iter().any(|blocker| matches!(
        blocker,
        SchedulerQuiescenceBlocker::RunnableNode { node } if node.node.name == "a"
    )));
    assert!(matches!(
        scheduler.checkpoint(),
        Err(SingleSchedulerCheckpointError::Transient)
    ));
    assert!(scheduler.park_campaign_marker_node(&vm("a")).is_err());
}

#[test]
fn staggered_parks_join_the_latest_park_and_keep_timer_durations() {
    let timed = test_scenario_node(
        "a",
        20,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 25 },
        },
    );
    let mut scheduler = test_scheduler(
        vec![timed, runnable("b", 30), runnable("c", 40)],
        Vec::new(),
    );

    for name in ["a", "b", "c"] {
        scheduler
            .park_campaign_marker_node(&vm(name))
            .unwrap_or_else(|error| panic!("VM `{name}` should park: {error}"));
    }
    // The last live participant defined the retained frontier.
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });

    let joined = scheduler
        .join_campaign_parks_to_frontier()
        .unwrap_or_else(|error| panic!("all-parked world should join: {error}"));

    assert_eq!(joined, vec![vm("a"), vm("b"), vm("c")]);
    assert!(!scheduler.has_campaign_parks());
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });
    for name in ["a", "b", "c"] {
        assert_eq!(logical_time(&scheduler, name), 40);
    }
    // Physical counters stay at each park; only the logical clock moves.
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 20 });
    assert_eq!(
        scheduler.nodes[0].exact_local_event,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 45 },
        }
    );
    assert!(scheduler.checkpoint().is_ok());
}

#[test]
fn all_parked_join_advances_to_a_park_ahead_of_the_frontier() {
    let mut scheduler = test_scheduler(vec![runnable("a", 50), runnable("b", 30)], Vec::new());

    scheduler
        .park_campaign_marker_node(&vm("a"))
        .unwrap_or_else(|error| panic!("leading VM should park: {error}"));
    scheduler
        .park_campaign_marker_node(&vm("b"))
        .unwrap_or_else(|error| panic!("trailing VM should park: {error}"));
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 30 });

    scheduler
        .join_campaign_parks_to_frontier()
        .unwrap_or_else(|error| panic!("all-parked world should join: {error}"));

    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 50 });
    assert_eq!(logical_time(&scheduler, "a"), 50);
    assert_eq!(logical_time(&scheduler, "b"), 50);
}

#[test]
fn join_with_a_live_peer_rejects_a_park_beyond_the_frontier() {
    let mut scheduler = test_scheduler(vec![runnable("a", 50), runnable("b", 30)], Vec::new());
    scheduler
        .park_campaign_marker_node(&vm("a"))
        .unwrap_or_else(|error| panic!("leading VM should park: {error}"));

    assert!(scheduler.join_campaign_parks_to_frontier().is_err());

    assert_eq!(scheduler.campaign_parked_nodes(), vec![vm("a")]);
    assert_eq!(logical_time(&scheduler, "a"), 50);
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 30 });
}

fn network_fault_scenario() -> crate::ScenarioDefForm {
    use crate::model::{
        Icount, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioSelectableLimits,
        ScenarioSelectables, Seed, WhiteBoxPolicy, World, WorldNode,
    };

    let world = World::from_nodes(vec![WorldNode {
        id: vm("a"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("network-fault-branch-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .unwrap_or_else(|error| panic!("test world should build: {error}"));
    let declaration = crate::NetworkFaultSelectable::declaration()
        .unwrap_or_else(|error| panic!("network fault declaration should build: {error}"));
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::default(),
        vec![declaration],
    )
    .unwrap_or_else(|error| panic!("test selectables should build: {error}"));
    crate::ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(21),
    )
    .and_then(|base| base.with_selectables(selectables))
    .unwrap_or_else(|error| panic!("test scenario should build: {error}"))
}

fn network_fault_branch(
    scenario: &crate::ScenarioDefForm,
    parent: &Configuration,
    at: VirtualTime,
) -> crate::NetworkFaultCampaignBranch {
    let selectable = crate::NetworkFaultSelectable::next(
        scenario,
        parent,
        crate::NetworkFaultPhase::First,
        at,
        &[],
    )
    .unwrap_or_else(|error| panic!("network choice should resolve: {error}"))
    .unwrap_or_else(|| panic!("network choice should be offered"));
    let value = crate::NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 0, 0)
        .unwrap_or_else(|error| panic!("fault value should encode: {error}"));
    let selection = selectable
        .branch_selection(value)
        .unwrap_or_else(|error| panic!("branch selection should bind: {error}"));
    selectable
        .resolve_branch(&selection)
        .unwrap_or_else(|error| panic!("branch should resolve: {error}"))
}

#[test]
fn network_fault_branch_commits_only_at_its_joined_boundary() {
    let scenario = network_fault_scenario();
    let mut scheduler = test_scheduler(vec![runnable("a", 50), runnable("b", 30)], Vec::new());
    scheduler.configuration = Configuration::genesis(scenario.scenario_def());
    let parent = scheduler.configuration().clone();
    for node in ["a", "b"] {
        scheduler
            .park_campaign_marker_node(&vm(node))
            .unwrap_or_else(|error| panic!("VM should park: {error}"));
    }
    scheduler
        .join_campaign_parks_to_frontier()
        .unwrap_or_else(|error| panic!("all-parked world should join: {error}"));

    // A branch recorded at another boundary must not commit here.
    let early = network_fault_branch(&scenario, &parent, VirtualTime { ticks: 30 });
    assert!(matches!(
        scheduler.append_network_fault_campaign_branch(&early),
        Err(SchedulerError::BoundaryViolation { .. })
    ));
    assert_eq!(scheduler.configuration(), &parent);

    let branch = network_fault_branch(&scenario, &parent, scheduler.frontier());
    let quanta = scheduler.quanta();
    let (selected, append) = scheduler
        .append_network_fault_campaign_branch(&branch)
        .unwrap_or_else(|error| panic!("joined boundary should commit the branch: {error}"));

    assert_eq!(&selected, branch.selected());
    assert_eq!(scheduler.configuration(), branch.selected());
    assert_eq!(scheduler.quanta(), quanta + 1);
    assert_eq!(scheduler.frontier(), branch.at());
    assert!(append.entries.iter().any(|entry| {
        entry.payload() == &SchedulerEventLogPayload::Decision(branch.decision().clone())
    }));

    // The consumed branch's parent no longer matches the scheduler.
    assert!(matches!(
        scheduler.append_network_fault_campaign_branch(&branch),
        Err(SchedulerError::BoundaryViolation { .. })
    ));
}

#[test]
fn join_resumes_frames_a_parked_vm_missed_at_its_first_deliverable_instant() {
    let mut scheduler = test_scheduler(vec![runnable("a", 50), runnable("b", 30)], Vec::new());
    let tick = |scheduler: &SingleScheduler, ticks: u64| {
        scheduler.network_tick_for_time(SimInstant { ticks })
    };
    let (parked_at, missed_at, later_at, resume) = (
        tick(&scheduler, 30),
        tick(&scheduler, 45),
        tick(&scheduler, 58),
        tick(&scheduler, 50),
    );

    // Router `a` keeps sending toward `b` after `b` parked at 30: one frame
    // falls due inside the interval `b` will skip, one after the join.
    let link_id = scheduler_link_id_for_nodes(&vm("a"), &vm("b"));
    let direction = NetworkLinkDirection::EndpointAToEndpointB;
    let mut link = crucible_device::NetLink::new(0, 1, 1, crucible_device::LinkFaults::none())
        .unwrap_or_else(|error| panic!("test link should build: {error}"));
    link.advance_to(parked_at)
        .unwrap_or_else(|error| panic!("receiver clock should reach its park: {error}"));
    for (emit_icount, frame_id) in [(missed_at, 1), (later_at, 2)] {
        link.emit(
            &crucible_device::Frame::new(emit_icount, frame_id, vec![frame_id as u8]),
            &crucible_device::FrameDraws::default(),
            crucible_device::PastDeliveryPolicy::FailLoud,
        )
        .unwrap_or_else(|error| panic!("test frame should enter flight: {error}"));
    }
    let delivery_icounts = |scheduler: &SingleScheduler| {
        scheduler.world_network_links[&(link_id.clone(), direction)]
            .link
            .snapshot()
            .inflight()
            .iter()
            .map(|pending| pending.delivery_icount())
            .collect::<Vec<_>>()
    };
    scheduler.world_network_links.insert(
        (link_id.clone(), direction),
        WorldNetworkLinkRuntime {
            canonical_id: link_id.clone(),
            endpoint_a: vm("a"),
            endpoint_b: vm("b"),
            direction,
            scheduler_node: scheduler_node("link-a-b", SchedulingNodeKind::Network),
            rng_stream: RngStreamId::for_link(link_id.name.clone()),
            fault_id: crate::DeviceId::from_name("link-a-b"),
            link,
        },
    );
    let later_delivery = delivery_icounts(&scheduler)[1];
    for node in ["a", "b"] {
        scheduler
            .park_campaign_marker_node(&vm(node))
            .unwrap_or_else(|error| panic!("VM should park: {error}"));
    }

    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should project: {error}"));
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::NetworkFrameInFlight { target: vm("b") })
    );
    assert!(!quiescence.blockers.iter().any(|blocker| matches!(
        blocker,
        SchedulerQuiescenceBlocker::DeviceCompletionInFlight { .. }
    )));

    scheduler
        .join_campaign_parks_to_frontier()
        .unwrap_or_else(|error| panic!("all-parked world should join: {error}"));

    assert_eq!(logical_time(&scheduler, "b"), 50);
    assert_eq!(
        delivery_icounts(&scheduler),
        vec![resume + 1, later_delivery]
    );
    let link = &scheduler.world_network_links[&(link_id, direction)].link;
    assert_eq!(link.current_icount(), resume);
}
