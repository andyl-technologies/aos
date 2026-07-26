//! Checks T-FAULT-15 fault determinism gate wiring.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible::{
    Action, BlockFault, ConditionLeaf, ConditionLeafOracle, ContentAddressedBlobRef, ContentHash,
    DagStore, DeviceDelivery, EventGraphState, Fault, FaultBandwidthBitsPerSecond, FaultDecision,
    FaultDuration, FaultPlan, FaultPlanEntry, FaultRateBasisPoints, FaultSlowdownFactorBasisPoints,
    FaultTag, Icount, IoFailureMode, LinkDef, LinkId, MemoryDagStore, NetworkCorruptionFault,
    NetworkFault, NetworkLinkDirection, NinePErrno, NinePFault, NodeCounter, NodeFault, NodeId,
    NodeTemplate, PartitionDirection, Plan, ReadyPoint, RestartPolicy,
    SchedulerEvaluationBoundaryKind, SchedulerLivenessScenario, SchedulerLookaheadEdge,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Seed, Shift,
    SimDuration, SimInstant, SimOffset, SingleScheduler, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldBlockLatency, WorldIoCoreConfig, WorldIoLayoutPolicy, WorldIoNode,
    WorldNinePLatency, WorldNode, WorldNodeDef,
};
use crucible_device::ninep::codec;
use crucible_device::{
    BaseImage, BlockRequest, Delivery, Frame, FrameDraws, FsTree, IoFaults, LinkFaults, NetLink,
    Node, PastDeliveryPolicy,
};

#[path = "fault_determinism_gate/support.rs"]
mod support;
use support::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultGateFingerprint {
    activations: Vec<FaultActivationRecord>,
    crash_applications: Vec<crucible::SchedulerNodeCrashApplication>,
    active_tags: Vec<(String, String)>,
    active_table: crucible::ActiveFaultTable,
    live_links: Vec<LinkEffectProbe>,
    live_devices: Vec<DeviceEffectProbe>,
    decisions: Vec<crucible::Decision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultActivationRecord {
    at: u64,
    activation_icount: u64,
    node_icounts: Vec<(String, u64)>,
    tag: String,
    action: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinkEffectProbe {
    label: &'static str,
    link_faults: LinkFaults,
    deliveries: Vec<Delivery>,
    injected_deliveries: Vec<Delivery>,
    decisions: Vec<crucible::Decision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeviceEffectProbe {
    kind: SchedulingNodeKind,
    faults: IoFaults,
    deliveries: Vec<DeviceDelivery>,
}

const PARTITION_A: &str = "partition-a";
const PARTITION_B: &str = "partition-b";
const LOSS_A: &str = "loss-a";
const LOSS_B: &str = "loss-b";
const DUPLICATE_A: &str = "duplicate-a";
const DUPLICATE_B: &str = "duplicate-b";
const BIT_FLIP_A: &str = "bit-flip-a";
const BIT_FLIP_B: &str = "bit-flip-b";
const FIELD_MUTATION_A: &str = "field-mutation-a";
const FIELD_MUTATION_B: &str = "field-mutation-b";
const TRUNCATION_A: &str = "truncation-a";
const TRUNCATION_B: &str = "truncation-b";
const REORDER_A: &str = "reorder-a";
const REORDER_B: &str = "reorder-b";
const LATENCY_A: &str = "latency-a";
const LATENCY_B: &str = "latency-b";
const BANDWIDTH_A: &str = "bandwidth-a";
const BANDWIDTH_B: &str = "bandwidth-b";

#[test]
fn gate_fault_determinism_run_twice_matches_activation_effects_and_draws() {
    let first = run_fault_gate();
    let second = run_fault_gate();
    let world = world();

    assert_eq!(
        first, second,
        "same seed and fault plan must produce identical activation/effect/draw fingerprints"
    );
    assert_eq!(first.activations.len(), fault_plan_entries(&world).len());
    assert!(
        first
            .activations
            .iter()
            .all(|activation| activation.activation_icount == activation.at),
        "shift-zero gate boundaries must record identical activation virtual times and node icounts"
    );
    assert!(
        first
            .activations
            .iter()
            .all(|activation| !activation.node_icounts.is_empty()),
        "every activation must capture the live scheduler node counters"
    );
    assert!(
        first
            .decisions
            .iter()
            .any(|decision| matches!(decision, crucible::Decision::RngDraw(_))),
        "the gate must record the decision-RNG draw sequence"
    );
    assert!(
        first
            .decisions
            .iter()
            .any(|decision| matches!(decision, crucible::Decision::FaultFires(_))),
        "the gate must record derived fault decisions"
    );
    for (left, right, label) in [
        (PARTITION_A, PARTITION_B, "partition"),
        (LOSS_A, LOSS_B, "loss"),
        (DUPLICATE_A, DUPLICATE_B, "duplicate"),
        (BIT_FLIP_A, BIT_FLIP_B, "bit-flip corruption"),
        (
            FIELD_MUTATION_A,
            FIELD_MUTATION_B,
            "field-mutation corruption",
        ),
        (TRUNCATION_A, TRUNCATION_B, "truncation corruption"),
        (REORDER_A, REORDER_B, "reorder"),
        (LATENCY_A, LATENCY_B, "latency"),
        (BANDWIDTH_A, BANDWIDTH_B, "bandwidth"),
    ] {
        assert!(
            first
                .active_table
                .combined
                .network
                .contains_key(&link_id(left, right)),
            "{label} effects must be materialized"
        );
    }

    let node_effects = first
        .active_table
        .combined
        .node
        .get(&node("db-0"))
        .expect("node effects must be materialized");
    assert_eq!(node_effects.crash_restart, Some(RestartPolicy::StayDown));
    assert_eq!(
        node_effects.slow_factor,
        Some(
            FaultSlowdownFactorBasisPoints::from_basis_points(20_000)
                .expect("slowdown should be valid")
        )
    );
    assert_eq!(node_effects.clock_skew, SimOffset { nanos: 11 });
    let [crash] = first.crash_applications.as_slice() else {
        panic!("the all-fault gate must apply exactly one concrete node crash");
    };
    assert_eq!(crash.node, node("db-0"));
    assert_eq!(crash.counter, NodeCounter { ticks: 0 });
    assert!(
        !crash.discarded_io.is_empty(),
        "the concrete crash must discard work that was already in flight"
    );
    assert_eq!(
        crash.discarded_io[0].delivery_icount,
        Icount { retired: 108 }
    );

    let partition = link_probe(&first, "partition");
    assert!(partition.link_faults.partitioned);
    assert!(
        partition.deliveries.is_empty(),
        "partitioned links must not deliver frames"
    );

    let loss = link_probe(&first, "loss");
    assert!(loss.link_faults.loss.fires(0));
    assert!(loss.deliveries.is_empty(), "100% loss must drop the frame");
    assert_fault_fired(&loss.decisions, "loss", true);

    let duplicate = link_probe(&first, "duplicate");
    assert!(duplicate.link_faults.duplicate.fires(0));
    assert_eq!(duplicate.link_faults.duplicate_gap_ns, 1);
    assert_eq!(
        duplicate.deliveries.len(),
        2,
        "100% duplicate fault must emit a second delivery"
    );
    assert_eq!(duplicate.deliveries[0].payload, frame_payload());
    assert_eq!(duplicate.deliveries[1].payload, frame_payload());
    assert!(
        duplicate.deliveries[1].delivery_icount() > duplicate.deliveries[0].delivery_icount(),
        "duplicate delivery must be ordered after the primary"
    );
    assert_fault_fired(&duplicate.decisions, "duplicate", true);

    let bit_flip = link_probe(&first, "corruption-bit-flip");
    assert!(bit_flip.link_faults.corrupt.fires(0));
    assert_eq!(bit_flip.link_faults.corruption_strategies.len(), 1);
    assert_eq!(bit_flip.injected_deliveries.len(), 1);
    assert_ne!(
        bit_flip.injected_deliveries[0].payload,
        frame_payload(),
        "bit-flip corruption must mutate the frame payload"
    );
    assert_eq!(
        bit_flip.injected_deliveries[0].payload.len(),
        frame_payload().len(),
        "bit-flip corruption must not mask itself as truncation"
    );
    assert_eq!(bit_flip.injected_deliveries[0].payload, vec![0, 0, 3, 4]);
    assert_fault_fired(&bit_flip.decisions, "corrupt", true);

    let field_mutation = link_probe(&first, "corruption-field-mutation");
    assert!(field_mutation.link_faults.corrupt.fires(0));
    assert_eq!(field_mutation.link_faults.corruption_strategies.len(), 1);
    assert_eq!(field_mutation.injected_deliveries.len(), 1);
    assert_eq!(
        field_mutation.injected_deliveries[0].payload,
        vec![1, 130, 3, 4],
        "field mutation must flip the selected modeled byte field"
    );
    assert_fault_fired(&field_mutation.decisions, "corrupt", true);

    let truncation = link_probe(&first, "corruption-truncation");
    assert!(truncation.link_faults.corrupt.fires(0));
    assert_eq!(truncation.link_faults.corruption_strategies.len(), 1);
    assert_eq!(truncation.injected_deliveries.len(), 1);
    assert_eq!(
        truncation.injected_deliveries[0].payload,
        vec![1, 2],
        "truncation must be represented in the delivered payload"
    );
    assert_fault_fired(&truncation.decisions, "corrupt", true);

    let reorder = link_probe(&first, "reorder");
    assert_eq!(reorder.link_faults.reorder_window_ns, 3);
    assert_eq!(reorder.injected_deliveries.len(), 1);
    assert_eq!(
        reorder.injected_deliveries[0].delivery_icount(),
        13,
        "reorder must shift delivery timing by the injected draw"
    );

    let latency = link_probe(&first, "latency");
    assert_eq!(latency.link_faults.added_latency_ns, 7);
    assert_eq!(latency.deliveries.len(), 1);
    assert_eq!(
        latency.deliveries[0].delivery_icount(),
        8,
        "latency bump must be visible in delivery timing"
    );

    let bandwidth = link_probe(&first, "bandwidth");
    assert_eq!(bandwidth.link_faults.bandwidth_bits_per_sec, vec![1_000]);
    assert_eq!(bandwidth.deliveries.len(), 1);
    assert_eq!(
        bandwidth.deliveries[0].delivery_icount(),
        32_000_001,
        "bandwidth cap must be visible in delivery timing"
    );

    let block = device_probe(&first, SchedulingNodeKind::Disk);
    assert_eq!(block.faults.added_latency_ns, 13);
    assert_eq!(block.faults.jitter_window_ns, 5);
    assert_eq!(block.faults.reorder_window_ns, 7);
    assert_eq!(block.faults.bandwidth_bits_per_sec, vec![8_000_000]);
    assert!(block.faults.loss.fires(0));
    assert!(block.faults.duplicate.fires(0));
    assert!(block.faults.corrupt.fires(0));
    assert_eq!(block.deliveries.len(), 2);
    assert!(
        block
            .deliveries
            .iter()
            .any(|delivery| !delivery.decisions.is_empty())
    );

    let ninep = device_probe(&first, SchedulingNodeKind::NineP);
    assert_eq!(ninep.faults.added_latency_ns, 17);
    assert_eq!(ninep.faults.jitter_window_ns, 6);
    assert_eq!(ninep.faults.reorder_window_ns, 8);
    assert_eq!(ninep.faults.bandwidth_bits_per_sec, vec![9_000_000]);
    assert!(ninep.faults.loss.fires(0));
    assert!(ninep.faults.duplicate.fires(0));
    assert!(ninep.faults.corrupt.fires(0));
    assert_eq!(ninep.deliveries.len(), 2);
    assert!(
        ninep
            .deliveries
            .iter()
            .any(|delivery| !delivery.decisions.is_empty())
    );
}

#[test]
fn gate_fault_determinism_divergence_localizes_to_first_fault_decision() {
    let baseline = run_fault_gate();
    let mut changed = baseline.decisions.clone();
    let changed_index = changed
        .iter()
        .position(|decision| matches!(decision, crucible::Decision::FaultFires(_)))
        .expect("gate fingerprint should contain a fault decision");
    if let crucible::Decision::FaultFires(decision) = &mut changed[changed_index] {
        decision.fired = !decision.fired;
    }

    let divergence = first_differing_fault_decision(&baseline.decisions, &changed)
        .expect("changed fault outcome should localize");
    assert_eq!(divergence.index, changed_index);
    assert_ne!(
        divergence
            .expected
            .as_ref()
            .expect("baseline fault decision should be present")
            .fired,
        divergence
            .actual
            .as_ref()
            .expect("changed fault decision should be present")
            .fired
    );

    let rng_draw = baseline
        .decisions
        .iter()
        .find(|decision| matches!(decision, crucible::Decision::RngDraw(_)))
        .cloned()
        .expect("gate fingerprint should contain an RNG draw");
    let mut inserted = baseline.decisions.clone();
    inserted.insert(changed_index, rng_draw);
    let shifted = first_differing_fault_decision(&baseline.decisions, &inserted)
        .expect("inserted decision should localize at the shifted fault decision");
    assert_eq!(shifted.index, changed_index);
    assert!(shifted.expected.is_some());
    assert!(shifted.actual.is_none());

    let truncated = baseline.decisions[..changed_index].to_vec();
    let missing = first_differing_fault_decision(&baseline.decisions, &truncated)
        .expect("truncated stream should localize at the missing fault decision");
    assert_eq!(missing.index, changed_index);
    assert!(missing.expected.is_some());
    assert!(missing.actual.is_none());

    let mut draw_changed = baseline.decisions.clone();
    let draw_index = draw_changed
        .iter()
        .position(|decision| matches!(decision, crucible::Decision::RngDraw(_)))
        .expect("gate fingerprint should contain an RNG draw");
    if let crucible::Decision::RngDraw(decision) = &mut draw_changed[draw_index] {
        decision.value ^= 1;
    }
    let draw_divergence = first_differing_decision(&baseline.decisions, &draw_changed)
        .expect("changed raw draw should localize");
    assert_eq!(draw_divergence.index, draw_index);
    assert!(matches!(
        draw_divergence.expected,
        Some(crucible::Decision::RngDraw(_))
    ));
    assert!(matches!(
        draw_divergence.actual,
        Some(crucible::Decision::RngDraw(_))
    ));
}

#[test]
fn gate_fault_determinism_plan_covers_every_currently_plan_valid_fault_kind() {
    let plan = fault_plan_entries(&world());
    let kinds = plan
        .iter()
        .filter_map(|entry| match entry {
            FaultPlanEntry::At { fault, .. } | FaultPlanEntry::PermanentAt { fault, .. } => {
                Some(fault.kind_key())
            }
            FaultPlanEntry::Heal { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    for expected in [
        "network.partition",
        "network.loss",
        "network.reorder",
        "network.duplicate",
        "network.corruption.bit-flip",
        "network.corruption.field-mutation",
        "network.corruption.truncation",
        "network.bandwidth",
        "network.latency-bump",
        "node.crash",
        "node.slow",
        "node.clock-skew",
        "block.latency",
        "block.failure",
        "block.reorder",
        "block.duplicate",
        "block.corruption.bit-flip",
        "block.bandwidth",
        "9p.latency",
        "9p.failure",
        "9p.reorder",
        "9p.duplicate",
        "9p.corruption.bit-flip",
        "9p.bandwidth",
    ] {
        assert!(kinds.contains(expected), "missing fault kind {expected}");
    }

    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Partition { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Loss { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Reorder { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Duplicate { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Corruption {
                kind: NetworkCorruptionFault::BitFlip { .. },
                ..
            }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Corruption {
                kind: NetworkCorruptionFault::FieldMutation { .. },
                ..
            }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Corruption {
                kind: NetworkCorruptionFault::Truncation { .. },
                ..
            }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::Bandwidth { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Network(NetworkFault::LatencyBump { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Node(NodeFault::Crash { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Node(NodeFault::Slow { .. }),
            ..
        }
    )));
    assert!(plan.iter().any(|entry| matches!(
        entry,
        FaultPlanEntry::PermanentAt {
            fault: Fault::Node(NodeFault::ClockSkew { .. }),
            ..
        }
    )));
}

#[test]
fn gate_fault_determinism_accepts_declared_device_taxonomy() {
    let world = world();
    let taxonomy = full_fault_taxonomy_kinds(&world);
    for expected in [
        "block.latency",
        "block.failure",
        "block.reorder",
        "block.duplicate",
        "block.corruption.bit-flip",
        "block.bandwidth",
        "9p.latency",
        "9p.failure",
        "9p.reorder",
        "9p.duplicate",
        "9p.corruption.bit-flip",
        "9p.bandwidth",
    ] {
        assert!(
            taxonomy.contains(expected),
            "full taxonomy must still account for device fault kind {expected}"
        );
    }

    for fault in device_taxonomy_faults(&world) {
        Plan::from_fault_plan_for_world(
            &world,
            FaultPlan::from_entries(vec![permanent(0, fault.kind_key(), fault)]),
        )
        .expect("declared block/9p targets must be plan-valid");
    }
}

fn run_fault_gate() -> FaultGateFingerprint {
    let (world, store) = world_and_store();
    let entries = fault_plan_entries(&world);
    let plan = Plan::from_fault_plan_for_world(&world, FaultPlan::from_entries(entries.clone()))
        .expect("fault determinism gate plan should validate");
    let graph = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault determinism gate plan should lower");
    let mut scheduler = SingleScheduler::from_world(
        scheduler_scenario("fault-determinism-gate", &world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("World-backed scheduler should build");
    let mut state = EventGraphState::new();
    let mut activations = Vec::new();
    let mut observed_applications = 0;

    {
        let block = scheduler
            .device_sub_nodes_for_mut(&node("db-0"))
            .expect("db-0 must own its declared block device")
            .iter_mut()
            .find(|node| node.sub_node().kind == SchedulingNodeKind::Disk)
            .expect("declared block device must be attached");
        block
            .submit(0, &BlockRequest::read(0xface, 0, 4))
            .expect("pre-crash block work should enter the in-flight queue");
    }

    for tick in 0..entries.len() as u64 {
        scheduler
            .append_evaluation_boundary(time(tick), SchedulerEvaluationBoundaryKind::Quantum)
            .expect("evaluation boundary should append");
        let firings = scheduler.evaluate_event_graph(graph.event_graph(), &mut state, NoLeaves);
        scheduler
            .apply_trigger_firings(&firings)
            .expect("trigger fault firing should apply");
        for application in scheduler
            .trigger_actions()
            .applications
            .iter()
            .skip(observed_applications)
        {
            if let Some(record) = fault_activation_record(application, &scheduler, &world) {
                activations.push(record);
            }
        }
        observed_applications = scheduler.trigger_actions().applications.len();
    }

    let materialized = scheduler.materialized_scheduler_state();
    let mut active_tags = materialized
        .active_fault_tags
        .iter()
        .map(|(tag, fault)| (tag.name.clone(), membership_kind(fault).to_owned()))
        .collect::<Vec<_>>();
    active_tags.sort();
    let live_links = probe_live_links(&mut scheduler);
    let live_devices = probe_live_devices(&mut scheduler);
    let mut decisions = live_links
        .iter()
        .flat_map(|probe| probe.decisions.iter().cloned())
        .collect::<Vec<_>>();
    decisions.extend(
        live_devices
            .iter()
            .flat_map(|probe| probe.deliveries.iter())
            .flat_map(|delivery| delivery.decisions.iter().cloned()),
    );

    FaultGateFingerprint {
        activations,
        crash_applications: scheduler.node_crash_applications().to_vec(),
        active_tags,
        active_table: materialized.active_fault_table,
        live_links,
        live_devices,
        decisions,
    }
}

fn probe_live_links(scheduler: &mut SingleScheduler) -> Vec<LinkEffectProbe> {
    vec![
        probe_link(
            scheduler,
            100,
            "partition",
            PARTITION_A,
            PARTITION_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            0,
            None,
        ),
        probe_link(
            scheduler,
            101,
            "loss",
            LOSS_A,
            LOSS_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            1,
            None,
        ),
        probe_link(
            scheduler,
            102,
            "duplicate",
            DUPLICATE_A,
            DUPLICATE_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            2,
            None,
        ),
        probe_link(
            scheduler,
            103,
            "corruption-bit-flip",
            BIT_FLIP_A,
            BIT_FLIP_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            3,
            Some(draws_with_corruption_selectors(vec![0, 9])),
        ),
        probe_link(
            scheduler,
            104,
            "corruption-field-mutation",
            FIELD_MUTATION_A,
            FIELD_MUTATION_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            4,
            Some(draws_with_corruption_selectors(vec![1])),
        ),
        probe_link(
            scheduler,
            105,
            "corruption-truncation",
            TRUNCATION_A,
            TRUNCATION_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            5,
            Some(draws_with_corruption_selectors(vec![1])),
        ),
        probe_link(
            scheduler,
            106,
            "reorder",
            REORDER_A,
            REORDER_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            6,
            Some(draws_with_reorder(3)),
        ),
        probe_link(
            scheduler,
            107,
            "latency",
            LATENCY_A,
            LATENCY_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            7,
            None,
        ),
        probe_link(
            scheduler,
            108,
            "bandwidth",
            BANDWIDTH_A,
            BANDWIDTH_B,
            NetworkLinkDirection::EndpointAToEndpointB,
            8,
            None,
        ),
    ]
}

fn probe_live_devices(scheduler: &mut SingleScheduler) -> Vec<DeviceEffectProbe> {
    let block = {
        let node = scheduler
            .device_sub_nodes_for_mut(&node("db-0"))
            .expect("db-0 must own its declared block device")
            .iter_mut()
            .find(|node| node.sub_node().kind == SchedulingNodeKind::Disk)
            .expect("declared block device must be attached");
        let faults = node.io_faults().clone();
        node.submit(0, &BlockRequest::read(42, 0, 4))
            .expect("faulted block request should compute");
        DeviceEffectProbe {
            kind: SchedulingNodeKind::Disk,
            faults,
            deliveries: node.deliver_due(u64::MAX),
        }
    };
    let ninep = {
        let node = scheduler
            .device_sub_nodes_for_mut(&node("db-1"))
            .expect("db-1 must own its declared 9p device")
            .iter_mut()
            .find(|node| node.sub_node().kind == SchedulingNodeKind::NineP)
            .expect("declared 9p device must be attached");
        let faults = node.io_faults().clone();
        node.submit_ninep_frame(0, &tversion(7, 4096, codec::PROTOCOL_VERSION))
            .expect("faulted 9p request should compute");
        DeviceEffectProbe {
            kind: SchedulingNodeKind::NineP,
            faults,
            deliveries: node.deliver_due(u64::MAX),
        }
    };
    vec![block, ninep]
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn probe_link(
    scheduler: &mut SingleScheduler,
    _sequence: u64,
    label: &'static str,
    endpoint_a: &str,
    endpoint_b: &str,
    direction: NetworkLinkDirection,
    source_id: u32,
    injected_draws: Option<FrameDraws>,
) -> LinkEffectProbe {
    let link_id = legacy_link_id(endpoint_a, endpoint_b);
    let link_faults = scheduler
        .world_network_link(&link_id, direction)
        .expect("declared World link must be scheduler-owned")
        .faults()
        .clone();
    let record = scheduler
        .emit_world_network_frame(
            &link_id,
            direction,
            Seed::from_u64(0x17_15),
            &Frame::new(0, 1, frame_payload()),
            PastDeliveryPolicy::FailLoud,
        )
        .expect("link frame should resolve with recorded faults");
    let injected_deliveries = injected_draws
        .map(|draws| {
            let mut injected_link = NetLink::new(0, source_id, 10, 1, link_faults.clone())
                .expect("injected link should build");
            injected_link
                .emit(
                    &Frame::new(0, 1, frame_payload()),
                    &draws,
                    PastDeliveryPolicy::FailLoud,
                )
                .expect("injected link frame should resolve")
                .deliveries
        })
        .unwrap_or_default();

    LinkEffectProbe {
        label,
        link_faults,
        deliveries: record.outcome.deliveries,
        injected_deliveries,
        decisions: record.decisions,
    }
}

fn draws_with_reorder(reorder: u64) -> FrameDraws {
    FrameDraws {
        reorder,
        ..FrameDraws::default()
    }
}

fn draws_with_corruption_selectors(corrupt_bits: Vec<u64>) -> FrameDraws {
    FrameDraws {
        corrupt: 0,
        corrupt_bits,
        ..FrameDraws::default()
    }
}

fn link_probe<'a>(fingerprint: &'a FaultGateFingerprint, label: &str) -> &'a LinkEffectProbe {
    fingerprint
        .live_links
        .iter()
        .find(|probe| probe.label == label)
        .unwrap_or_else(|| panic!("missing link effect probe {label}"))
}

fn device_probe(
    fingerprint: &FaultGateFingerprint,
    kind: SchedulingNodeKind,
) -> &DeviceEffectProbe {
    fingerprint
        .live_devices
        .iter()
        .find(|probe| probe.kind == kind)
        .unwrap_or_else(|| panic!("missing {kind:?} device effect probe"))
}

fn assert_fault_fired(decisions: &[crucible::Decision], kind: &str, fired: bool) {
    let suffix = format!("/{kind}");
    assert!(
        decisions.iter().any(|decision| {
            matches!(
                decision,
                crucible::Decision::FaultFires(FaultDecision { fault, fired: actual, .. })
                    if fault.name.ends_with(&suffix) && *actual == fired
            )
        }),
        "missing fault decision {kind}={fired}"
    );
}

fn frame_payload() -> Vec<u8> {
    vec![1, 2, 3, 4]
}

fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
    let mut body = msize.to_le_bytes().to_vec();
    body.extend_from_slice(&(version.len() as u16).to_le_bytes());
    body.extend_from_slice(version.as_bytes());
    let size = (codec::HEADER_LEN + body.len()) as u32;
    let mut frame = Vec::new();
    frame.extend_from_slice(&size.to_le_bytes());
    frame.push(codec::TVERSION);
    frame.extend_from_slice(&tag.to_le_bytes());
    frame.extend_from_slice(&body);
    frame
}

fn fault_activation_record(
    application: &crucible::TriggerActionApplication,
    scheduler: &SingleScheduler,
    world: &World,
) -> Option<FaultActivationRecord> {
    let node_icounts = world
        .vm_nodes()
        .iter()
        .map(|node| {
            let projection = scheduler
                .node_timing_projection(&node.id)
                .expect("fault activation target must have a live scheduler projection");
            (node.id.name.clone(), projection.counter.ticks)
        })
        .collect();
    match &application.action {
        Action::InjectFault { tag, .. } => Some(FaultActivationRecord {
            at: application.at.ticks,
            activation_icount: application.at.ticks,
            node_icounts,
            tag: tag.name.clone(),
            action: "inject",
        }),
        Action::HealFault { tag } => Some(FaultActivationRecord {
            at: application.at.ticks,
            activation_icount: application.at.ticks,
            node_icounts,
            tag: tag.name.clone(),
            action: "heal",
        }),
        _ => None,
    }
}

fn fault_plan_entries(world: &World) -> Vec<FaultPlanEntry> {
    let mut entries = vec![
        permanent(
            0,
            "partition",
            Fault::Network(NetworkFault::Partition {
                link: link_id(PARTITION_A, PARTITION_B),
                direction: PartitionDirection::EndpointAToEndpointB,
            }),
        ),
        permanent(
            1,
            "loss",
            Fault::Network(NetworkFault::Loss {
                link: link_id(LOSS_A, LOSS_B),
                rate: rate(10_000),
            }),
        ),
        permanent(
            2,
            "reorder",
            Fault::Network(NetworkFault::Reorder {
                link: link_id(REORDER_A, REORDER_B),
                window: FaultDuration::from_nanos(3),
            }),
        ),
        permanent(
            3,
            "duplicate",
            Fault::Network(NetworkFault::Duplicate {
                link: link_id(DUPLICATE_A, DUPLICATE_B),
                rate: rate(10_000),
                gap: FaultDuration::from_nanos(1),
            }),
        ),
        permanent(
            4,
            "corruption-bit-flip",
            Fault::Network(NetworkFault::Corruption {
                link: link_id(BIT_FLIP_A, BIT_FLIP_B),
                kind: NetworkCorruptionFault::BitFlip {
                    rate: rate(10_000),
                    max_bits: 2,
                },
            }),
        ),
        permanent(
            5,
            "corruption-field-mutation",
            Fault::Network(NetworkFault::Corruption {
                link: link_id(FIELD_MUTATION_A, FIELD_MUTATION_B),
                kind: NetworkCorruptionFault::FieldMutation { rate: rate(10_000) },
            }),
        ),
        permanent(
            6,
            "corruption-truncation",
            Fault::Network(NetworkFault::Corruption {
                link: link_id(TRUNCATION_A, TRUNCATION_B),
                kind: NetworkCorruptionFault::Truncation {
                    rate: rate(10_000),
                    max_bytes: 2,
                },
            }),
        ),
        permanent(
            7,
            "bandwidth",
            Fault::Network(NetworkFault::Bandwidth {
                link: link_id(BANDWIDTH_A, BANDWIDTH_B),
                limit: FaultBandwidthBitsPerSecond::new(1_000).expect("bandwidth should be valid"),
            }),
        ),
        permanent(
            8,
            "latency",
            Fault::Network(NetworkFault::LatencyBump {
                link: link_id(LATENCY_A, LATENCY_B),
                extra: FaultDuration::from_nanos(7),
            }),
        ),
        permanent(
            9,
            "crash",
            Fault::Node(NodeFault::Crash {
                node: node("db-0"),
                restart: RestartPolicy::StayDown,
            }),
        ),
        permanent(
            10,
            "slow",
            Fault::Node(NodeFault::Slow {
                node: node("db-0"),
                factor: FaultSlowdownFactorBasisPoints::from_basis_points(20_000)
                    .expect("slowdown should be valid"),
            }),
        ),
        permanent(
            11,
            "clock-skew",
            Fault::Node(NodeFault::ClockSkew {
                node: node("db-0"),
                offset: SimOffset { nanos: 11 },
            }),
        ),
    ];
    entries.extend(
        device_taxonomy_faults(world)
            .into_iter()
            .enumerate()
            .map(|(index, fault)| {
                permanent(
                    12 + index as u64,
                    &format!("device-{}", fault.kind_key()),
                    fault,
                )
            }),
    );
    entries
}

fn full_fault_taxonomy_kinds(world: &World) -> BTreeSet<&'static str> {
    representative_fault_taxonomy(world)
        .into_iter()
        .map(|fault| fault.kind_key())
        .collect()
}

fn representative_fault_taxonomy(world: &World) -> Vec<Fault> {
    let mut faults = vec![
        Fault::Network(NetworkFault::Partition {
            link: link_id(PARTITION_A, PARTITION_B),
            direction: PartitionDirection::EndpointAToEndpointB,
        }),
        Fault::Network(NetworkFault::Loss {
            link: link_id(LOSS_A, LOSS_B),
            rate: rate(1),
        }),
        Fault::Network(NetworkFault::Reorder {
            link: link_id(REORDER_A, REORDER_B),
            window: FaultDuration::from_nanos(1),
        }),
        Fault::Network(NetworkFault::Duplicate {
            link: link_id(DUPLICATE_A, DUPLICATE_B),
            rate: rate(1),
            gap: FaultDuration::from_nanos(1),
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link_id(BIT_FLIP_A, BIT_FLIP_B),
            kind: NetworkCorruptionFault::BitFlip {
                rate: rate(1),
                max_bits: 1,
            },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link_id(FIELD_MUTATION_A, FIELD_MUTATION_B),
            kind: NetworkCorruptionFault::FieldMutation { rate: rate(1) },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link_id(TRUNCATION_A, TRUNCATION_B),
            kind: NetworkCorruptionFault::Truncation {
                rate: rate(1),
                max_bytes: 1,
            },
        }),
        Fault::Network(NetworkFault::Bandwidth {
            link: link_id(BANDWIDTH_A, BANDWIDTH_B),
            limit: bandwidth(1_000),
        }),
        Fault::Network(NetworkFault::LatencyBump {
            link: link_id(LATENCY_A, LATENCY_B),
            extra: FaultDuration::from_nanos(1),
        }),
        Fault::Node(NodeFault::Crash {
            node: node("db-0"),
            restart: RestartPolicy::StayDown,
        }),
        Fault::Node(NodeFault::Slow {
            node: node("db-0"),
            factor: FaultSlowdownFactorBasisPoints::from_basis_points(10_001)
                .expect("slowdown should be valid"),
        }),
        Fault::Node(NodeFault::ClockSkew {
            node: node("db-0"),
            offset: SimOffset { nanos: 1 },
        }),
    ];
    faults.extend(device_taxonomy_faults(world));
    faults
}

fn device_taxonomy_faults(world: &World) -> Vec<Fault> {
    let disk = world
        .io_node(&node("disk0"))
        .expect("gate world declares disk0")
        .device_id();
    let share = world
        .io_node(&node("fs0"))
        .expect("gate world declares fs0")
        .device_id();
    vec![
        Fault::Block(BlockFault::Latency {
            device: disk.clone(),
            extra: FaultDuration::from_nanos(13),
            jitter: FaultDuration::from_nanos(5),
        }),
        Fault::Block(BlockFault::Failure {
            device: disk.clone(),
            rate: rate(10_000),
            mode: IoFailureMode::ErrorStatus,
        }),
        Fault::Block(BlockFault::Reorder {
            device: disk.clone(),
            window: FaultDuration::from_nanos(7),
        }),
        Fault::Block(BlockFault::Duplicate {
            device: disk.clone(),
            rate: rate(10_000),
            gap: FaultDuration::from_nanos(11),
        }),
        Fault::Block(BlockFault::Corruption {
            device: disk.clone(),
            rate: rate(10_000),
            bit_flips: 1,
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: disk,
            limit: bandwidth(8_000_000),
        }),
        Fault::NineP(NinePFault::Latency {
            device: share.clone(),
            extra: FaultDuration::from_nanos(17),
            jitter: FaultDuration::from_nanos(6),
        }),
        Fault::NineP(NinePFault::Failure {
            device: share.clone(),
            rate: rate(10_000),
            errno: errno(5),
        }),
        Fault::NineP(NinePFault::Reorder {
            device: share.clone(),
            window: FaultDuration::from_nanos(8),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: share.clone(),
            rate: rate(10_000),
            gap: FaultDuration::from_nanos(12),
        }),
        Fault::NineP(NinePFault::Corruption {
            device: share.clone(),
            rate: rate(10_000),
            bit_flips: 1,
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: share,
            limit: bandwidth(9_000_000),
        }),
    ]
}

fn permanent(at: u64, tag_name: &str, fault: Fault) -> FaultPlanEntry {
    FaultPlanEntry::PermanentAt {
        at: time(at),
        tag: tag(tag_name),
        fault,
    }
}

fn scheduler_scenario(name: &str, world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        Shift { bits: 0 },
        256,
        SimInstant { nanos: 64 },
        world
            .vm_nodes()
            .iter()
            .map(|node| scenario_node(&node.id.name))
            .collect(),
        Vec::new(),
    )
    .with_trigger_world(world)
    .with_effective_topology_edges(world_lookahead_edges(world))
}

fn scenario_node(name: &str) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: 0 },
        activity: SchedulerNodeActivity::Idle,
        network_lookahead: crucible::NetworkLookahead::Infinite,
        exact_local_event: crucible::ExactLocalEvent::NoArmedTimer,
    }
}

fn world() -> World {
    world_and_store().0
}

fn world_and_store() -> (World, MemoryDagStore) {
    let block_bytes = vec![0xab; 4096];
    let base = BaseImage::new(block_bytes.clone());
    let tree = FsTree::try_new(Node::Directory {
        children: [(
            String::from("alpha"),
            Node::File {
                content: b"alpha".to_vec(),
            },
        )]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    })
    .expect("gate 9p tree should validate");
    let store = MemoryDagStore::new();
    let block_key = store
        .put(&block_bytes)
        .expect("block artifact should store");
    let tree_key = store
        .put(&tree.canonical_bytes())
        .expect("9p artifact should store");
    assert_eq!(block_key, ContentHash { bytes: base.hash() });
    assert_eq!(
        tree_key,
        ContentHash {
            bytes: tree.content_hash()
        }
    );

    let mut nodes = [
        "db-0",
        "db-1",
        PARTITION_A,
        PARTITION_B,
        LOSS_A,
        LOSS_B,
        DUPLICATE_A,
        DUPLICATE_B,
        BIT_FLIP_A,
        BIT_FLIP_B,
        FIELD_MUTATION_A,
        FIELD_MUTATION_B,
        TRUNCATION_A,
        TRUNCATION_B,
        REORDER_A,
        REORDER_B,
        LATENCY_A,
        LATENCY_B,
        BANDWIDTH_A,
        BANDWIDTH_B,
    ]
    .into_iter()
    .map(ready_node)
    .map(WorldNodeDef::Vm)
    .collect::<Vec<_>>();
    nodes.push(WorldNodeDef::Io(WorldIoNode::block(
        node("disk0"),
        node("db-0"),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(block_key),
        block_bytes.len() as u64,
        WorldBlockLatency::new(100, 200, 30, 40, 2),
    )));
    nodes.push(WorldNodeDef::Io(WorldIoNode::ninep(
        node("fs0"),
        node("db-1"),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(tree_key),
        WorldNinePLatency::new(80, 120, 1),
    )));
    let world = World::from_node_defs_and_links(
        nodes,
        [
            (PARTITION_A, PARTITION_B),
            (LOSS_A, LOSS_B),
            (DUPLICATE_A, DUPLICATE_B),
            (BIT_FLIP_A, BIT_FLIP_B),
            (FIELD_MUTATION_A, FIELD_MUTATION_B),
            (TRUNCATION_A, TRUNCATION_B),
            (REORDER_A, REORDER_B),
            (LATENCY_A, LATENCY_B),
            (BANDWIDTH_A, BANDWIDTH_B),
        ]
        .into_iter()
        .map(|(left, right)| LinkDef::new(node(left), node(right)).expect("test link should build"))
        .collect(),
    )
    .expect("test world should build");
    (world, store)
}

fn world_lookahead_edges(world: &World) -> Vec<SchedulerLookaheadEdge> {
    world
        .links()
        .iter()
        .flat_map(|link| {
            let (endpoint_a, endpoint_b) = link.endpoints();
            [
                SchedulerLookaheadEdge::new(
                    scheduler_node(&endpoint_a.name),
                    scheduler_node(&endpoint_b.name),
                    SimDuration { nanos: 1 },
                ),
                SchedulerLookaheadEdge::new(
                    scheduler_node(&endpoint_b.name),
                    scheduler_node(&endpoint_a.name),
                    SimDuration { nanos: 1 },
                ),
            ]
        })
        .collect()
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid fault rate: {error}"))
}

fn bandwidth(bits_per_second: u64) -> FaultBandwidthBitsPerSecond {
    FaultBandwidthBitsPerSecond::new(bits_per_second)
        .unwrap_or_else(|error| panic!("valid fault bandwidth: {error}"))
}

fn errno(code: i32) -> NinePErrno {
    NinePErrno::from_code(code).unwrap_or_else(|error| panic!("valid 9p errno: {error}"))
}

fn link_id(left: &str, right: &str) -> LinkId {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.len(),
        endpoint_a,
        endpoint_b.len(),
        endpoint_b
    ))
}

fn legacy_link_id(left: &str, right: &str) -> LinkId {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    LinkId::from_name(format!("{endpoint_a}--{endpoint_b}"))
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("fault determinism gate uses only At leaves")
            }
        }
    }
}
