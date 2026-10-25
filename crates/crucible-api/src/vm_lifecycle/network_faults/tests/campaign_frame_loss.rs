//! Selected campaign frame-loss evidence tests.

use super::*;

/// Selection time of the follow-up loss window, after genesis so frames
/// released before it prove the window starts at the selection.
const SELECTED_AT_TICKS: u64 = 5 * 1_000 * 1_000 * crucible::model::SIM_TICKS_PER_NS;

/// Selected loss duration, in microseconds.
const LOSS_DURATION_US: u64 = 10_000;

/// Selected loss rate, in basis points: one frame in ten.
const LOSS_BPS: u64 = 1_000;

/// Frames released inside the selected window.
const FRAMES_IN_WINDOW: u64 = 40;

/// Builds a two-node World whose backup domain is the right-to-left direction.
fn backup_loss_world()
-> Result<(crucible::World, crucible::model::WorldFaultTopology), Box<dyn Error>> {
    let (base_world, segment) = availability_world();
    let mut topology = base_world.fault_topology().clone();
    topology.network_segments[0].fault_domains = vec![signal_id("primary"), signal_id("backup")];
    topology.fault_domains = vec![
        WorldFaultDomain {
            id: signal_id("primary"),
            targets: vec![WorldFaultTargetRef::NetworkSegment {
                segment: signal_id(segment.as_str()),
                direction: FaultDirection::AToB,
            }],
        },
        WorldFaultDomain {
            id: signal_id("backup"),
            targets: vec![WorldFaultTargetRef::NetworkSegment {
                segment: signal_id(segment.as_str()),
                direction: FaultDirection::BToA,
            }],
        },
    ];
    let world = base_world.with_fault_topology(topology.clone())?;
    Ok((world, topology))
}

/// Routes one right-to-left frame released at `ticks` and returns whether it survived.
fn route_backup_frame(
    interceptor: &mut ProductionFaultNetworkInterceptor,
    scheduler: &mut SingleScheduler,
    nodes: &mut QemuNodeSet,
    ticks: u64,
    sequence: u64,
) -> Result<bool, Box<dyn Error>> {
    let mut payload = vec![0_u8; 14];
    payload[..6].copy_from_slice(&deterministic_node_mac(&node("left").id));
    let mut pending = Vec::new();
    let mut outputs = vec![BackendNetworkOutput {
        source: node("right").id,
        destination: node("left").id,
        emit_icount: Icount { retired: 0 },
        sequence,
        payload,
        route: None,
        fault_continuation: Default::default(),
    }];
    interceptor.intercept_network_outputs(
        scheduler,
        nodes,
        VirtualTime { ticks },
        &mut pending,
        &mut outputs,
    )?;
    Ok(!outputs.is_empty() || !pending.is_empty())
}

#[test]
fn selected_packet_loss_records_every_frame_it_evaluates() -> Result<(), Box<dyn Error>> {
    let (world, topology) = backup_loss_world()?;
    let scenario = crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        crucible::Seed::from_u64(21),
    )?;
    let selectables = crucible::model::ScenarioSelectables::new(
        &world,
        crucible::model::ScenarioSelectableLimits::default(),
        vec![crucible::NetworkFaultSelectable::declaration()?],
    )?;
    let scenario = scenario.with_selectables(selectables)?;
    // Envoy's shape: a brief primary outage first, then follow-up loss on
    // the backup direction selected at its own later boundary.
    let genesis = Configuration::genesis(scenario.scenario_def());
    let first = crucible::NetworkFaultSelectable::next(
        &scenario,
        &genesis,
        crucible::NetworkFaultPhase::First,
        VirtualTime { ticks: 0 },
        &[],
    )?
    .ok_or("active first network group")?;
    let outage =
        crucible::NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 0, 0)?;
    let first = first.resolve_branch(&first.branch_selection(outage)?)?;
    let followup = crucible::NetworkFaultSelectable::next(
        &scenario,
        first.selected(),
        crucible::NetworkFaultPhase::Followup,
        VirtualTime {
            ticks: SELECTED_AT_TICKS,
        },
        std::slice::from_ref(&first),
    )?
    .ok_or("active follow-up network group")?;
    let loss = crucible::NetworkFaultSelectable::selected_value(
        "packet_loss",
        "backup",
        LOSS_DURATION_US,
        LOSS_BPS,
        0,
    )?;
    let followup = followup.resolve_branch(&followup.branch_selection(loss)?)?;
    let replay = crucible::NetworkFaultCampaignReplayPlan::new(
        followup.selected().clone(),
        vec![first, followup],
    )?;
    replay.validate_topology(&topology)?;
    let window_end =
        SELECTED_AT_TICKS + LOSS_DURATION_US * 1_000 * crucible::model::SIM_TICKS_PER_NS;

    let scheduler_scenario = SchedulerLivenessScenario::from_runnable_world(
        "production-campaign-packet-loss",
        16,
        SimInstant {
            ticks: 128 * crucible::model::SIM_TICKS_PER_NS,
        },
        0,
        &world,
    );
    let mut scheduler = SingleScheduler::from_world(
        scheduler_scenario,
        &world,
        &MemoryDagStore::new(),
        WorldIoLayoutPolicy::default(),
    )?;
    let mut nodes = QemuNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        crucible::model::FaultSignalPlan::empty(),
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        scenario.scenario_def().id(),
        super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )?;
    let mut interceptor =
        ProductionFaultNetworkInterceptor::new(runtime, topology.clone(), world.links().to_vec());
    interceptor.install_campaign_replay(Some(replay.clone()), None)?;
    for (branch, marker) in replay
        .branches()
        .iter()
        .zip(["fault.transport.ready", "fault.followup.ready"])
    {
        interceptor.record_campaign_marker_release(
            &node("right").id,
            marker,
            Icount { retired: 10 },
            Icount { retired: 11 },
            Icount { retired: 100 },
            branch.selected().id(),
        )?;
    }

    // A frame released before the selection lies outside the window.
    let mut sequence = 1;
    assert!(route_backup_frame(
        &mut interceptor,
        &mut scheduler,
        &mut nodes,
        SELECTED_AT_TICKS - 1,
        sequence,
    )?);
    assert!(interceptor.campaign_effect_records().is_empty());

    // Every frame released inside the window is evaluated and recorded,
    // whether its draw drops it or preserves it.
    let spacing = (window_end - SELECTED_AT_TICKS) / FRAMES_IN_WINDOW;
    let mut survived = 0_u64;
    for index in 0..FRAMES_IN_WINDOW {
        sequence += 1;
        if route_backup_frame(
            &mut interceptor,
            &mut scheduler,
            &mut nodes,
            SELECTED_AT_TICKS + index * spacing,
            sequence,
        )? {
            survived += 1;
        }
    }
    assert_eq!(
        interceptor.campaign_effect_records().len(),
        usize::try_from(FRAMES_IN_WINDOW)?
    );
    assert!(
        survived > 0,
        "a ten percent loss rate preserves most frames, which still record"
    );

    // The primary direction and the window's exclusive end are untouched.
    sequence += 1;
    assert!(route_backup_frame(
        &mut interceptor,
        &mut scheduler,
        &mut nodes,
        window_end,
        sequence,
    )?);
    assert_eq!(
        interceptor.campaign_effect_records().len(),
        usize::try_from(FRAMES_IN_WINDOW)?
    );

    let trace = trace_with_campaign_network_records(
        None,
        interceptor.campaign_effect_log(),
        FaultReplayMode::RecomputedCause,
    )?
    .ok_or("evaluated frame-loss actions produce trace evidence")?;
    let records = trace_records(&bundle_round_trip(&trace));
    assert_eq!(records.len(), usize::try_from(FRAMES_IN_WINDOW)?);
    assert!(records.iter().all(|record| matches!(
        record.request.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::FrameLoss { .. })
    )));
    Ok(())
}
