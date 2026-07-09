//! Checks T-FAULT-15 fault determinism gate wiring.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use crucible::{
    Action, BlockFault, ConditionLeaf, ConditionLeafOracle, DeviceId, EngineError, EventGraphState,
    Fault, FaultBandwidthBitsPerSecond, FaultDecision, FaultDuration, FaultPlan, FaultPlanEntry,
    FaultRateBasisPoints, FaultSlowdownFactorBasisPoints, FaultTag, Icount, IoFailureMode, LinkDef,
    LinkId, MembershipFault, NetworkCorruptionFault, NetworkFault, NetworkLinkDirection,
    NinePErrno, NinePFault, NodeCounter, NodeFault, NodeId, NodeTemplate, PartitionDirection, Plan,
    ReadyPoint, RestartPolicy, SchedulerEvaluationBoundaryKind, SchedulerLivenessScenario,
    SchedulerLookaheadEdge, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, Seed, Shift, SimDuration, SimInstant, SimOffset, SingleScheduler,
    VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};
use crucible_device::{Delivery, Frame, FrameDraws, LinkFaults, NetLink, PastDeliveryPolicy};

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultGateFingerprint {
    activations: Vec<FaultActivationRecord>,
    active_tags: Vec<(String, String)>,
    active_table: crucible::ActiveFaultTable,
    live_links: Vec<LinkEffectProbe>,
    decisions: Vec<crucible::Decision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultActivationRecord {
    at: u64,
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
struct DecisionDivergence {
    index: usize,
    expected: Option<crucible::Decision>,
    actual: Option<crucible::Decision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultDecisionDivergence {
    index: usize,
    expected: Option<FaultDecision>,
    actual: Option<FaultDecision>,
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

    assert_eq!(
        first, second,
        "same seed and fault plan must produce identical activation/effect/draw fingerprints"
    );
    assert_eq!(first.activations.len(), fault_plan_entries().len());
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
        17,
        "latency bump must be visible in delivery timing"
    );

    let bandwidth = link_probe(&first, "bandwidth");
    assert_eq!(bandwidth.link_faults.bandwidth_bits_per_sec, vec![1_000]);
    assert_eq!(bandwidth.deliveries.len(), 1);
    assert_eq!(
        bandwidth.deliveries[0].delivery_icount(),
        32_000_010,
        "bandwidth cap must be visible in delivery timing"
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
    let plan = fault_plan_entries();
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
fn gate_fault_determinism_documents_device_taxonomy_boundary() {
    let taxonomy = full_fault_taxonomy_kinds();
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

    for fault in device_taxonomy_faults() {
        let error = Plan::from_fault_plan_for_world(
            &world(),
            FaultPlan::from_entries(vec![permanent(0, fault.kind_key(), fault)]),
        )
        .expect_err("block/9p plan faults require declared world device targets");
        assert!(
            matches!(error, EngineError::PlanFaultUnknownDevice { .. }),
            "device-target validation must reject undeclared block/9p faults"
        );
    }
}

fn run_fault_gate() -> FaultGateFingerprint {
    let world = world();
    let plan =
        Plan::from_fault_plan_for_world(&world, FaultPlan::from_entries(fault_plan_entries()))
            .expect("fault determinism gate plan should validate");
    let graph = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault determinism gate plan should lower");
    let mut scheduler = SingleScheduler::new(scheduler_scenario("fault-determinism-gate", &world))
        .expect("scheduler should build");
    let mut state = EventGraphState::new();

    for tick in 0..fault_plan_entries().len() as u64 {
        scheduler
            .append_evaluation_boundary(time(tick), SchedulerEvaluationBoundaryKind::Quantum)
            .expect("evaluation boundary should append");
        let firings = scheduler.evaluate_event_graph(graph.event_graph(), &mut state, NoLeaves);
        scheduler
            .apply_trigger_firings(&firings)
            .expect("trigger fault firing should apply");
    }

    let materialized = scheduler.materialized_scheduler_state();
    let mut active_tags = materialized
        .active_fault_tags
        .iter()
        .map(|(tag, fault)| (tag.name.clone(), membership_kind(fault).to_owned()))
        .collect::<Vec<_>>();
    active_tags.sort();
    let live_links = probe_live_links(&mut scheduler);
    let decisions = live_links
        .iter()
        .flat_map(|probe| probe.decisions.iter().cloned())
        .collect();

    FaultGateFingerprint {
        activations: scheduler
            .trigger_actions()
            .applications
            .iter()
            .filter_map(fault_activation_record)
            .collect(),
        active_tags,
        active_table: materialized.active_fault_table,
        live_links,
        decisions,
    }
}

fn first_differing_fault_decision(
    expected: &[crucible::Decision],
    actual: &[crucible::Decision],
) -> Option<FaultDecisionDivergence> {
    let len = expected.len().max(actual.len());
    (0..len).find_map(|index| {
        let expected = expected.get(index);
        let actual = actual.get(index);
        if expected == actual {
            return None;
        }

        let expected = fault_decision(expected);
        let actual = fault_decision(actual);
        if expected.is_some() || actual.is_some() {
            Some(FaultDecisionDivergence {
                index,
                expected,
                actual,
            })
        } else {
            None
        }
    })
}

fn first_differing_decision(
    expected: &[crucible::Decision],
    actual: &[crucible::Decision],
) -> Option<DecisionDivergence> {
    let len = expected.len().max(actual.len());
    (0..len).find_map(|index| {
        let expected = expected.get(index).cloned();
        let actual = actual.get(index).cloned();
        if expected == actual {
            None
        } else {
            Some(DecisionDivergence {
                index,
                expected,
                actual,
            })
        }
    })
}

fn fault_decision(decision: Option<&crucible::Decision>) -> Option<FaultDecision> {
    match decision {
        Some(crucible::Decision::FaultFires(decision)) => Some(decision.clone()),
        _ => None,
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

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn probe_link(
    scheduler: &mut SingleScheduler,
    sequence: u64,
    label: &'static str,
    endpoint_a: &str,
    endpoint_b: &str,
    direction: NetworkLinkDirection,
    source_id: u32,
    injected_draws: Option<FrameDraws>,
) -> LinkEffectProbe {
    let mut link =
        NetLink::new(0, source_id, 10, 1, LinkFaults::none()).expect("link should build");
    let application = scheduler
        .apply_trigger_network_faults_to_link(
            sequence,
            &legacy_link_id(endpoint_a, endpoint_b),
            scheduler_node(endpoint_a),
            scheduler_node(endpoint_b),
            &mut link,
            direction,
            Vec::new(),
        )
        .expect("trigger network faults should apply");
    let record = crucible::emit_link_frame_with_recorded_faults(
        Seed::from_u64(0x17_15),
        &device(label),
        &mut link,
        &Frame::new(0, 1, frame_payload()),
        PastDeliveryPolicy::FailLoud,
    )
    .expect("link frame should resolve with recorded faults");
    let injected_deliveries = injected_draws
        .map(|draws| {
            let mut injected_link =
                NetLink::new(0, source_id, 10, 1, application.link_faults.clone())
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
        link_faults: application.link_faults,
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

fn fault_activation_record(
    application: &crucible::TriggerActionApplication,
) -> Option<FaultActivationRecord> {
    match &application.action {
        Action::InjectFault { tag, .. } => Some(FaultActivationRecord {
            at: application.at.ticks,
            tag: tag.name.clone(),
            action: "inject",
        }),
        Action::HealFault { tag } => Some(FaultActivationRecord {
            at: application.at.ticks,
            tag: tag.name.clone(),
            action: "heal",
        }),
        _ => None,
    }
}

fn fault_plan_entries() -> Vec<FaultPlanEntry> {
    vec![
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
    ]
}

fn full_fault_taxonomy_kinds() -> BTreeSet<&'static str> {
    representative_fault_taxonomy()
        .into_iter()
        .map(|fault| fault.kind_key())
        .collect()
}

fn representative_fault_taxonomy() -> Vec<Fault> {
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
    faults.extend(device_taxonomy_faults());
    faults
}

fn device_taxonomy_faults() -> Vec<Fault> {
    vec![
        block_latency_fault(),
        Fault::Block(BlockFault::Failure {
            device: device("disk0"),
            rate: rate(1),
            mode: IoFailureMode::ErrorStatus,
        }),
        Fault::Block(BlockFault::Reorder {
            device: device("disk0"),
            window: FaultDuration::from_nanos(1),
        }),
        Fault::Block(BlockFault::Duplicate {
            device: device("disk0"),
            rate: rate(1),
            gap: FaultDuration::from_nanos(1),
        }),
        Fault::Block(BlockFault::Corruption {
            device: device("disk0"),
            rate: rate(1),
            bit_flips: 1,
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: device("disk0"),
            limit: bandwidth(1_000),
        }),
        ninep_latency_fault(),
        Fault::NineP(NinePFault::Failure {
            device: device("fs0"),
            rate: rate(1),
            errno: errno(5),
        }),
        Fault::NineP(NinePFault::Reorder {
            device: device("fs0"),
            window: FaultDuration::from_nanos(1),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: device("fs0"),
            rate: rate(1),
            gap: FaultDuration::from_nanos(1),
        }),
        Fault::NineP(NinePFault::Corruption {
            device: device("fs0"),
            rate: rate(1),
            bit_flips: 1,
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: device("fs0"),
            limit: bandwidth(1_000),
        }),
    ]
}

fn block_latency_fault() -> Fault {
    Fault::Block(BlockFault::Latency {
        device: device("disk0"),
        extra: FaultDuration::from_nanos(1),
        jitter: FaultDuration::ZERO,
    })
}

fn ninep_latency_fault() -> Fault {
    Fault::NineP(NinePFault::Latency {
        device: device("fs0"),
        extra: FaultDuration::from_nanos(1),
        jitter: FaultDuration::ZERO,
    })
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
            .nodes()
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
    World::from_nodes_and_links(
        [
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
        .collect(),
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
    .expect("test world should build")
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

fn device(name: &str) -> DeviceId {
    DeviceId {
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

fn membership_kind(fault: &MembershipFault) -> &'static str {
    match fault {
        MembershipFault::Crash { .. } => "crash",
        MembershipFault::Partition { .. } => "partition",
        MembershipFault::Isolate { .. } => "isolate",
        MembershipFault::NotYetJoined { .. } => "not-yet-joined",
        MembershipFault::Taxonomy { fault } => fault.kind_key(),
    }
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
