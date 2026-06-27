//! Checks T-IO-9 deterministic network-link sub-node planning.

#![forbid(unsafe_code)]

use crucible::{
    Icount, LinkDef, LinkLossProbability, NETWORK_ROUTER_SLOT_INDEX, NETWORK_ROUTER_SLOT_NAME,
    NETWORK_ROUTER_SLOT_NODE_NAME, NetworkLinkEffectiveFaults, NetworkLinkError, NetworkLinkFrame,
    NetworkLinkSubNode, ScheduledEventPayload, SchedulerNodeId, SchedulingNodeKind, Shift,
    SimDuration, SimInstant, network_router_node, resolve_due_scheduled_events,
    resolve_network_link_frame, sort_network_link_deliveries,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostInterleaving {
    ProducerSkewed,
    ConsumerSkewed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedInjection {
    frame_sequence: u64,
    observed_icount: u64,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostStep {
    frame_index: usize,
    producer_host_tick: u64,
}

#[test]
fn network_link_observed_vectors_match_across_host_interleavings() {
    let producer_skewed = run_two_vm_injection(HostInterleaving::ProducerSkewed);
    let consumer_skewed = run_two_vm_injection(HostInterleaving::ConsumerSkewed);

    assert_eq!(producer_skewed, consumer_skewed);
    assert_eq!(
        producer_skewed,
        vec![
            observed(0, 10, b"first"),
            observed(1, 15, b"second"),
            observed(2, 18, b"third"),
        ]
    );
}

#[test]
fn network_link_host_timing_negative_control_differs() {
    let producer_skewed = host_timing_observed_vector(HostInterleaving::ProducerSkewed);
    let consumer_skewed = host_timing_observed_vector(HostInterleaving::ConsumerSkewed);

    assert_ne!(producer_skewed, consumer_skewed);
}

#[test]
fn network_link_latency_bandwidth_jitter_and_reorder_set_delivery_icount() {
    let link = transport_link("a", "b", 10, 4, 0, Some(8_000_000_000));
    let model = network_link(link, "a", "b");
    let faults = NetworkLinkEffectiveFaults {
        link_jitter_draw: 7,
        extra_latency: SimDuration { nanos: 3 },
        reorder_window: SimDuration { nanos: 9 },
        reorder_draw: 4,
        ..NetworkLinkEffectiveFaults::default()
    };

    let plan = model
        .plan_frame(frame(3, 100, b"ab"), &faults)
        .expect("link planning should succeed");

    assert!(!plan.dropped);
    assert_eq!(plan.deliveries.len(), 1);
    assert_eq!(plan.perturbations.base_latency, SimDuration { nanos: 10 });
    assert_eq!(plan.perturbations.bandwidth_delay, SimDuration { nanos: 2 });
    assert_eq!(plan.perturbations.jitter_delay, SimDuration { nanos: 2 });
    assert_eq!(plan.perturbations.extra_latency, SimDuration { nanos: 3 });
    assert_eq!(plan.perturbations.reorder_delay, SimDuration { nanos: 4 });
    assert_eq!(plan.deliveries[0].delivery_icount, Icount { retired: 121 });
    assert_eq!(plan.deliveries[0].delivery_time.ticks, 121);

    let event = plan.deliveries[0]
        .to_scheduled_event(&model)
        .expect("event sequence should fit");
    assert_eq!(event.key.producer(), model.source());
    assert_eq!(event.key.consumer(), model.target());
    assert_eq!(event.key.virtual_time().ticks, 121);
    assert_eq!(event.key.sequence(), 6);
    match event.payload {
        ScheduledEventPayload::BackendInput(input) => {
            assert_eq!(input.node, scheduler_node("b", SchedulingNodeKind::Vm).node);
            assert_eq!(input.payload, b"ab");
        }
        other => panic!("network link should emit backend input, got {other:?}"),
    }
    assert_eq!(NETWORK_ROUTER_SLOT_NAME, "SLOT_NET_ROUTER");
    assert_eq!(NETWORK_ROUTER_SLOT_INDEX, 31);
    assert_eq!(model.router().node.name, NETWORK_ROUTER_SLOT_NODE_NAME);
    assert_eq!(model.router(), &network_router_node());
}

#[test]
fn network_link_shifted_delivery_key_uses_observable_icount_boundary() {
    let link = transport_link("a", "b", 5, 0, 0, None);
    let model = network_link_with_shift(link, "a", "b", 2);
    let plan = model
        .plan_frame(
            frame(0, 0, b"unaligned"),
            &NetworkLinkEffectiveFaults::default(),
        )
        .expect("unaligned shifted delivery should plan");

    assert_eq!(plan.deliveries[0].delivery_icount, Icount { retired: 2 });
    assert_eq!(plan.deliveries[0].delivery_time.ticks, 8);

    let event = plan.deliveries[0]
        .to_scheduled_event(&model)
        .expect("event sequence should fit");
    assert_eq!(event.key.virtual_time().ticks, 8);

    let mut pending = vec![event];
    let resolved = resolve_due_scheduled_events(
        &mut pending,
        model.target(),
        SimInstant { nanos: 8 },
        model.shift(),
    )
    .expect("shifted network event should resolve at its observable boundary");

    assert!(pending.is_empty());
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].key.virtual_time().ticks, 8);
}

#[test]
fn network_link_loss_drops_before_duplicate_or_corrupt_outputs() {
    let model = network_link(transport_link("a", "b", 10, 0, 1_000_000, None), "a", "b");
    let faults = NetworkLinkEffectiveFaults {
        link_loss_draw: 0,
        duplicate_rate: LinkLossProbability::ONE,
        duplicate_draw: 0,
        corruption_rate: LinkLossProbability::ONE,
        corruption_draw: 0,
        corruption_bit_draw: 0,
        ..NetworkLinkEffectiveFaults::default()
    };

    let plan = model
        .plan_frame(frame(0, 1, b"drop-me"), &faults)
        .expect("loss planning should succeed");

    assert!(plan.dropped);
    assert!(plan.deliveries.is_empty());
    assert!(plan.perturbations.link_loss_fired);
    assert!(!plan.perturbations.duplicate_fired);
    assert!(!plan.perturbations.corruption_fired);
}

#[test]
fn network_link_duplicate_and_corruption_are_seeded_payload_perturbations() {
    let model = network_link(transport_link("a", "b", 10, 0, 0, None), "a", "b");
    let faults = NetworkLinkEffectiveFaults {
        duplicate_rate: LinkLossProbability::ONE,
        duplicate_draw: 0,
        corruption_rate: LinkLossProbability::ONE,
        corruption_draw: 0,
        corruption_bit_draw: 9,
        ..NetworkLinkEffectiveFaults::default()
    };

    let plan = model
        .plan_frame(frame(2, 5, &[0b0000_0000, 0b0000_0010]), &faults)
        .expect("duplicate/corrupt planning should succeed");

    assert!(!plan.dropped);
    assert!(plan.perturbations.duplicate_fired);
    assert!(plan.perturbations.corruption_fired);
    assert_eq!(plan.deliveries.len(), 2);
    assert_eq!(plan.deliveries[0].copy_index, 0);
    assert_eq!(plan.deliveries[1].copy_index, 1);
    assert_eq!(plan.deliveries[0].payload, vec![0b0000_0000, 0b0000_0000]);
    assert_eq!(plan.deliveries[0].payload, plan.deliveries[1].payload);
    assert_eq!(
        plan.deliveries[0]
            .event_sequence()
            .expect("primary sequence should fit"),
        4
    );
    assert_eq!(
        plan.deliveries[1]
            .event_sequence()
            .expect("duplicate sequence should fit"),
        5
    );
}

#[test]
fn network_link_reorder_can_pass_peer_frame_deterministically() {
    let model = network_link(transport_link("a", "b", 10, 0, 0, None), "a", "b");
    let slow = NetworkLinkEffectiveFaults {
        reorder_window: SimDuration { nanos: 20 },
        reorder_draw: 20,
        ..NetworkLinkEffectiveFaults::default()
    };
    let fast = NetworkLinkEffectiveFaults::default();

    let mut deliveries = Vec::new();
    deliveries.extend(
        model
            .plan_frame(frame(0, 0, b"first"), &slow)
            .expect("slow frame should plan")
            .deliveries,
    );
    deliveries.extend(
        model
            .plan_frame(frame(1, 5, b"second"), &fast)
            .expect("fast frame should plan")
            .deliveries,
    );

    sort_network_link_deliveries(&mut deliveries);

    assert_eq!(deliveries[0].frame_sequence, 1);
    assert_eq!(deliveries[0].delivery_icount, Icount { retired: 15 });
    assert_eq!(deliveries[1].frame_sequence, 0);
    assert_eq!(deliveries[1].delivery_icount, Icount { retired: 30 });
}

#[test]
fn network_link_event_keys_stay_unique_for_source_local_sequences() {
    let link_ab = network_link(transport_link("a", "b", 10, 0, 0, None), "a", "b");
    let link_cb = network_link(transport_link("c", "b", 10, 0, 0, None), "c", "b");
    let event_ab = link_ab
        .plan_frame(
            frame(0, 0, b"a-to-b"),
            &NetworkLinkEffectiveFaults::default(),
        )
        .expect("a->b should plan")
        .deliveries[0]
        .to_scheduled_event(&link_ab)
        .expect("a->b event should encode");
    let event_cb = link_cb
        .plan_frame(
            frame(0, 0, b"c-to-b"),
            &NetworkLinkEffectiveFaults::default(),
        )
        .expect("c->b should plan")
        .deliveries[0]
        .to_scheduled_event(&link_cb)
        .expect("c->b event should encode");

    assert_eq!(event_ab.key.consumer(), event_cb.key.consumer());
    assert_eq!(event_ab.key.sequence(), event_cb.key.sequence());
    assert_ne!(event_ab.key.producer(), event_cb.key.producer());
    assert_ne!(event_ab.key, event_cb.key);
}

#[test]
fn scheduler_resolve_network_link_frame_applies_effective_fault_table() {
    let model = network_link(transport_link("a", "b", 10, 0, 0, None), "a", "b");
    let faults = NetworkLinkEffectiveFaults {
        duplicate_rate: LinkLossProbability::ONE,
        duplicate_draw: 0,
        corruption_rate: LinkLossProbability::ONE,
        corruption_draw: 0,
        corruption_bit_draw: 0,
        ..NetworkLinkEffectiveFaults::default()
    };

    let events = resolve_network_link_frame(&model, frame(4, 3, &[1]), &faults)
        .expect("network RESOLVE helper should apply link model");

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].key.producer(), model.source());
    assert_eq!(events[0].key.consumer(), model.target());
    assert_eq!(events[0].key.virtual_time().ticks, 13);
    assert_eq!(events[0].key.sequence(), 8);
    assert_eq!(events[1].key.sequence(), 9);
    for event in events {
        match event.payload {
            ScheduledEventPayload::BackendInput(input) => {
                assert_eq!(input.node, model.target().node.clone());
                assert_eq!(input.payload, vec![0]);
            }
            other => panic!("network RESOLVE helper emitted {other:?}"),
        }
    }

    let dropped = resolve_network_link_frame(
        &model,
        frame(5, 3, b"dropped"),
        &NetworkLinkEffectiveFaults {
            additional_loss_rate: LinkLossProbability::ONE,
            additional_loss_draw: 0,
            ..NetworkLinkEffectiveFaults::default()
        },
    )
    .expect("dropped frame should resolve without target events");
    assert!(dropped.is_empty());
}

#[test]
fn network_link_rejects_invalid_endpoints_bandwidth_and_sequence_overflow() {
    let link = transport_link("a", "b", 10, 0, 0, None);
    let non_vm = SchedulerNodeId {
        node: node("a"),
        kind: SchedulingNodeKind::Disk,
    };
    assert!(matches!(
        NetworkLinkSubNode::new(
            link.clone(),
            non_vm,
            scheduler_node("b", SchedulingNodeKind::Vm),
            shift(0),
        ),
        Err(NetworkLinkError::InvalidEndpointKind { .. })
    ));
    assert!(matches!(
        NetworkLinkSubNode::new(
            link.clone(),
            scheduler_node("a", SchedulingNodeKind::Vm),
            scheduler_node("c", SchedulingNodeKind::Vm),
            shift(0),
        ),
        Err(NetworkLinkError::EndpointMismatch { .. })
    ));

    let zero_bandwidth = NetworkLinkEffectiveFaults {
        bandwidth_bps: Some(0),
        ..NetworkLinkEffectiveFaults::default()
    };
    let model = network_link(link, "a", "b");
    assert_eq!(
        model.plan_frame(frame(0, 0, b"x"), &zero_bandwidth),
        Err(NetworkLinkError::ZeroBandwidth)
    );
    assert!(matches!(
        model.plan_frame(
            frame(u64::MAX, 0, b"x"),
            &NetworkLinkEffectiveFaults::default()
        ),
        Err(NetworkLinkError::EventSequenceOverflow { .. })
    ));
}

fn run_two_vm_injection(interleaving: HostInterleaving) -> Vec<ObservedInjection> {
    let model = network_link(transport_link("a", "b", 10, 0, 0, None), "a", "b");
    let frames = scenario_frames();
    let mut deliveries = Vec::new();
    for step in host_script(interleaving) {
        let frame = frames[step.frame_index].clone();
        let plan = model
            .plan_frame(frame, &NetworkLinkEffectiveFaults::default())
            .expect("frame should plan deterministically");
        deliveries.extend(plan.deliveries);
    }
    sort_network_link_deliveries(&mut deliveries);
    deliveries
        .into_iter()
        .map(|delivery| ObservedInjection {
            frame_sequence: delivery.frame_sequence,
            observed_icount: delivery.delivery_icount.retired,
            payload: delivery.payload,
        })
        .collect()
}

fn host_timing_observed_vector(interleaving: HostInterleaving) -> Vec<ObservedInjection> {
    let frames = scenario_frames();
    host_script(interleaving)
        .into_iter()
        .map(|step| ObservedInjection {
            frame_sequence: frames[step.frame_index].sequence,
            observed_icount: step.producer_host_tick,
            payload: frames[step.frame_index].payload.clone(),
        })
        .collect()
}

fn host_script(interleaving: HostInterleaving) -> Vec<HostStep> {
    match interleaving {
        HostInterleaving::ProducerSkewed => vec![
            HostStep {
                frame_index: 2,
                producer_host_tick: 900,
            },
            HostStep {
                frame_index: 0,
                producer_host_tick: 120,
            },
            HostStep {
                frame_index: 1,
                producer_host_tick: 610,
            },
        ],
        HostInterleaving::ConsumerSkewed => vec![
            HostStep {
                frame_index: 0,
                producer_host_tick: 700,
            },
            HostStep {
                frame_index: 1,
                producer_host_tick: 300,
            },
            HostStep {
                frame_index: 2,
                producer_host_tick: 40,
            },
        ],
    }
}

fn scenario_frames() -> Vec<NetworkLinkFrame> {
    vec![
        frame(0, 0, b"first"),
        frame(1, 5, b"second"),
        frame(2, 8, b"third"),
    ]
}

fn observed(frame_sequence: u64, observed_icount: u64, payload: &[u8]) -> ObservedInjection {
    ObservedInjection {
        frame_sequence,
        observed_icount,
        payload: payload.to_vec(),
    }
}

fn network_link(link: LinkDef, source: &str, target: &str) -> NetworkLinkSubNode {
    network_link_with_shift(link, source, target, 0)
}

fn network_link_with_shift(
    link: LinkDef,
    source: &str,
    target: &str,
    shift_bits: u8,
) -> NetworkLinkSubNode {
    NetworkLinkSubNode::new(
        link,
        scheduler_node(source, SchedulingNodeKind::Vm),
        scheduler_node(target, SchedulingNodeKind::Vm),
        shift(shift_bits),
    )
    .expect("network link should be valid")
}

fn frame(sequence: u64, emit_icount: u64, payload: &[u8]) -> NetworkLinkFrame {
    NetworkLinkFrame {
        sequence,
        emit_icount: Icount {
            retired: emit_icount,
        },
        payload: payload.to_vec(),
    }
}

fn transport_link(
    left: &str,
    right: &str,
    latency_ns: u64,
    jitter_ns: u64,
    loss_millionths: u32,
    bandwidth_bps: Option<u64>,
) -> LinkDef {
    LinkDef::with_transport(
        node(left),
        node(right),
        SimDuration { nanos: latency_ns },
        SimDuration { nanos: jitter_ns },
        LinkLossProbability::from_millionths(loss_millionths)
            .expect("loss probability should be valid"),
        bandwidth_bps,
    )
    .expect("transport link should be valid")
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind,
    }
}

fn node(name: &str) -> crucible::NodeId {
    crucible::NodeId {
        name: name.to_owned(),
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
