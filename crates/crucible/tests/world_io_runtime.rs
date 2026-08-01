//! Exercises production World artifact resolution and scheduler attachment.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixtures.
#![allow(clippy::expect_used)]

use crucible::{
    BlockFault, ContentAddressedBlobRef, ContentHash, ControlOperation, ControlOperationKind,
    DagStore, Decision, EngineError, ExactLocalEvent, Fault, FaultDuration, FaultTag, LinkDef,
    LinkId, MemoryDagStore, NetworkFault, NetworkLinkDirection, NetworkLookahead, NinePFault,
    NodeCounter, NodeId, NodeTemplate, PartitionDirection, QuantumLoop, QuantumRequest, ReadyPoint,
    RngStreamId, ScheduledEventPayload, SchedulerLivenessScenario, SchedulerNodeActivity,
    SchedulerNodeId, SchedulerQuiescenceBlocker, SchedulerScenarioNode,
    SchedulerTopologyChangeTrigger, SchedulingNodeKind, Seed, Shift, SimInstant, SingleScheduler,
    VmArchitecture, WhiteBoxPolicy, World, WorldBlockLatency, WorldIoCoreConfig,
    WorldIoLayoutPolicy, WorldIoNode, WorldNinePLatency, WorldNode, WorldNodeDef,
};
use crucible_device::ninep::codec;
use crucible_device::{BaseImage, BlockRequest, Frame, FsTree, Node, PastDeliveryPolicy};

#[test]
fn production_scheduler_resolves_artifacts_and_applies_live_block_and_ninep_faults() {
    let (world, store) = runtime_world_and_store();
    let mut scheduler = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy {
            inbox_capacity: 32,
            outbox_capacity: 64,
        },
    )
    .expect("production World scheduler should instantiate");

    let static_topology = world.static_topology();
    assert_eq!(scheduler.world_scheduling_nodes().len(), 5);
    assert_eq!(scheduler.world_network_link_count(), 2);
    assert_eq!(
        scheduler
            .world_scheduling_nodes()
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        static_topology.scheduling_nodes
    );
    assert_eq!(
        scheduler
            .world_scheduling_nodes()
            .iter()
            .filter(|node| node.kind == SchedulingNodeKind::Network)
            .count(),
        world.links().len()
    );

    let disk = world
        .io_node(&node_id("disk"))
        .expect("disk declaration")
        .device_id();
    let share = world
        .io_node(&node_id("share"))
        .expect("9p declaration")
        .device_id();
    scheduler
        .apply_control_at_boundary(vec![
            ControlOperation {
                sequence: 0,
                kind: ControlOperationKind::InjectFault {
                    tag: FaultTag::from_name("disk-latency"),
                    fault: Fault::Block(BlockFault::Latency {
                        device: disk,
                        extra: FaultDuration::from_nanos(1_000),
                        jitter: FaultDuration::ZERO,
                    }),
                },
            },
            ControlOperation {
                sequence: 1,
                kind: ControlOperationKind::InjectFault {
                    tag: FaultTag::from_name("share-latency"),
                    fault: Fault::NineP(NinePFault::Latency {
                        device: share,
                        extra: FaultDuration::from_nanos(2_000),
                        jitter: FaultDuration::ZERO,
                    }),
                },
            },
            ControlOperation {
                sequence: 2,
                kind: ControlOperationKind::InjectFault {
                    tag: FaultTag::from_name("network-latency"),
                    fault: Fault::Network(NetworkFault::LatencyBump {
                        link: LinkId::from_name("vm-a--vm-b"),
                        extra: FaultDuration::from_nanos(300),
                    }),
                },
            },
        ])
        .expect("valid device faults should apply at the scheduler boundary");

    let disk_due = {
        let nodes = scheduler
            .device_sub_nodes_for_mut(&node_id("vm-a"))
            .expect("vm-a owns a concrete device");
        let disk = nodes
            .iter_mut()
            .find(|node| node.sub_node().kind == SchedulingNodeKind::Disk)
            .expect("block device is attached");
        assert_eq!(disk.io_faults().added_latency_ns, 1_000);
        disk.submit(0, &BlockRequest::read(7, 0, 4))
            .expect("block request computes");
        disk.next_exact_local_event()
            .expect("faulted block completion is scheduled")
    };
    assert_eq!(disk_due, 1_108, "base latency plus live fault shift");

    let share_due = {
        let nodes = scheduler
            .device_sub_nodes_for_mut(&node_id("vm-b"))
            .expect("vm-b owns a concrete device");
        let share = nodes
            .iter_mut()
            .find(|node| node.sub_node().kind == SchedulingNodeKind::NineP)
            .expect("9p device is attached");
        assert_eq!(share.io_faults().added_latency_ns, 2_000);
        share
            .submit_ninep_frame(0, &tversion(9, 4096, codec::PROTOCOL_VERSION))
            .expect("9p request computes");
        share
            .next_exact_local_event()
            .expect("faulted 9p completion is scheduled")
    };
    assert!(share_due > 2_000, "9p base latency plus live fault shift");

    let link_id = LinkId::from_name("vm-a--vm-b");
    assert_eq!(
        scheduler
            .world_network_link(&link_id, NetworkLinkDirection::EndpointAToEndpointB,)
            .expect("World link is a concrete scheduler-owned device")
            .faults()
            .added_latency_ns,
        300
    );
    let delivery = scheduler
        .emit_world_network_frame(
            &link_id,
            NetworkLinkDirection::EndpointAToEndpointB,
            Seed::from_u64(7),
            &Frame::new(0, 1, vec![1, 2, 3]),
            PastDeliveryPolicy::FailLoud,
        )
        .expect("scheduler-owned link should resolve a frame");
    assert_eq!(delivery.outcome.deliveries[0].delivery_icount(), 301);
}

#[test]
fn production_device_attachment_and_fault_effects_are_run_twice_deterministic() {
    assert_eq!(runtime_fault_fingerprint(), runtime_fault_fingerprint());
}

#[test]
fn physical_ring_policy_cannot_change_production_scheduler_identity_or_effects() {
    let (world, store) = runtime_world_and_store();
    let mut compact = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy {
            inbox_capacity: 8,
            outbox_capacity: 8,
        },
    )
    .expect("compact layout should instantiate");
    let mut roomy = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy {
            inbox_capacity: 1024,
            outbox_capacity: 2048,
        },
    )
    .expect("roomy layout should instantiate");

    assert_eq!(compact.configuration(), roomy.configuration());
    assert_eq!(
        compact.world_scheduling_nodes(),
        roomy.world_scheduling_nodes()
    );
    assert_eq!(block_probe(&mut compact), block_probe(&mut roomy));
}

#[test]
fn applying_the_same_world_projection_twice_is_identity_idempotent() {
    let (world, _) = runtime_world_and_store();
    let once = scheduler_scenario(&world).with_world(&world);
    let twice = once.clone().with_world(&world);

    assert_eq!(once.authored_material, twice.authored_material);
    assert_eq!(
        once.canonical_configuration(),
        twice.canonical_configuration()
    );
    assert_eq!(once.effective_topology, twice.effective_topology);
    assert_eq!(once.trigger_static_topology, twice.trigger_static_topology);
}

#[test]
fn distinct_world_launch_material_changes_scheduler_identity() {
    let mut first_vm = vm("vm-a");
    first_vm.cmdline = String::from("mode=first");
    let mut second_vm = vm("vm-a");
    second_vm.cmdline = String::from("mode=second");
    let first = World::from_nodes(vec![first_vm]).expect("first World should validate");
    let second = World::from_nodes(vec![second_vm]).expect("second World should validate");

    let first_scenario = scheduler_scenario(&first).with_world(&first);
    let second_scenario = scheduler_scenario(&second).with_world(&second);

    assert_ne!(first.id(), second.id());
    assert_ne!(
        first_scenario.canonical_configuration(),
        second_scenario.canonical_configuration(),
        "VM launch material must remain in scheduler identity through the World reference"
    );
}

#[test]
fn scheduler_owned_link_uses_declared_rng_stream_and_resolves_on_the_live_path() {
    let (world, store) = runtime_world_and_store();
    let link_id = canonical_link_id("vm-a", "vm-b");
    let seed = Seed::from_u64(0x10_0010);
    let frame = Frame::new(0, 1, vec![9, 8, 7]);
    let mut first = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("first production World scheduler should instantiate");
    let mut second = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("second production World scheduler should instantiate");

    let first_record = first
        .emit_world_network_frame(
            &link_id,
            NetworkLinkDirection::EndpointAToEndpointB,
            seed,
            &frame,
            PastDeliveryPolicy::FailLoud,
        )
        .expect("scheduler-owned link should emit");
    let second_record = second
        .emit_world_network_frame(
            &link_id,
            NetworkLinkDirection::EndpointAToEndpointB,
            seed,
            &frame,
            PastDeliveryPolicy::FailLoud,
        )
        .expect("repeated scheduler-owned link should emit");
    assert_eq!(first_record, second_record);

    let expected_stream = RngStreamId::for_link(link_id.name.clone());
    let draw_streams = first_record
        .decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::RngDraw(draw) => Some(&draw.stream),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!draw_streams.is_empty());
    assert!(
        draw_streams
            .iter()
            .all(|stream| **stream == expected_stream)
    );

    let materialized = first.materialized_scheduler_state();
    assert_eq!(materialized.network_link_cursors.len(), 2);
    assert_eq!(
        materialized
            .pending_frames
            .get(&node_id("vm-b"))
            .map(Vec::len),
        Some(1)
    );
    assert!(
        first
            .quiescence()
            .expect("quiescence should materialize")
            .blockers
            .contains(&SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                target: node_id("vm-b"),
            })
    );

    let outcome = first
        .drive_quantum(QuantumRequest {
            configuration: first.configuration().clone(),
            control: Vec::new(),
        })
        .expect("the target VM should advance to the network delivery");
    let declared_network_node = world.links()[0].scheduler_node_id();
    assert!(outcome.resolved_events.iter().any(|event| matches!(
        &event.payload,
        ScheduledEventPayload::BackendInput(input)
            if input.node == node_id("vm-b")
                && input.payload == frame.payload
                && event.key.producer() == &declared_network_node
    )));
    assert!(
        first
            .materialized_scheduler_state()
            .pending_frames
            .get(&node_id("vm-b"))
            .is_none_or(Vec::is_empty)
    );
    assert!(
        !first
            .quiescence()
            .expect("post-delivery quiescence should materialize")
            .blockers
            .contains(&SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                target: node_id("vm-b"),
            })
    );
}

#[test]
fn both_link_directions_consume_one_uninterrupted_declared_rng_stream() {
    let (world, store) = runtime_world_and_store();
    let link = canonical_link_id("vm-a", "vm-b");
    let seed = Seed::from_u64(0x51aa_0010);
    let mut alternating = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("alternating scheduler should instantiate");
    let mut forward_only = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("forward-only scheduler should instantiate");

    let alternating_records = [
        alternating
            .emit_world_network_frame(
                &link,
                NetworkLinkDirection::EndpointAToEndpointB,
                seed,
                &Frame::new(0, 10, vec![1]),
                PastDeliveryPolicy::FailLoud,
            )
            .expect("forward frame should emit"),
        alternating
            .emit_world_network_frame(
                &link,
                NetworkLinkDirection::EndpointBToEndpointA,
                seed,
                &Frame::new(0, 11, vec![2]),
                PastDeliveryPolicy::FailLoud,
            )
            .expect("reverse frame should emit"),
    ];
    let forward_records = [
        forward_only
            .emit_world_network_frame(
                &link,
                NetworkLinkDirection::EndpointAToEndpointB,
                seed,
                &Frame::new(0, 10, vec![1]),
                PastDeliveryPolicy::FailLoud,
            )
            .expect("first baseline frame should emit"),
        forward_only
            .emit_world_network_frame(
                &link,
                NetworkLinkDirection::EndpointAToEndpointB,
                seed,
                &Frame::new(0, 11, vec![2]),
                PastDeliveryPolicy::FailLoud,
            )
            .expect("second baseline frame should emit"),
    ];

    assert_eq!(
        rng_draw_values(&alternating_records),
        rng_draw_values(&forward_records),
        "direction changes must not restart the declared logical-link stream"
    );
    let positions = alternating
        .materialized_scheduler_state()
        .network_link_cursors
        .values()
        .map(|cursor| cursor.rng_position)
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 2);
    assert_eq!(positions[0], positions[1]);
    assert!(positions[0] > 0);
}

#[test]
fn materialized_world_link_queues_resume_byte_identically() {
    let (world, store) = runtime_world_and_store();
    let link = canonical_link_id("vm-a", "vm-b");
    let seed = Seed::from_u64(0x5a_0010);
    let scenario = scheduler_scenario(&world);
    let mut original = SingleScheduler::from_world(
        scenario.clone(),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("original scheduler should instantiate");
    original
        .emit_world_network_frame(
            &link,
            NetworkLinkDirection::EndpointAToEndpointB,
            seed,
            &Frame::new(0, 21, vec![3, 4, 5]),
            PastDeliveryPolicy::FailLoud,
        )
        .expect("forward frame should emit");
    original
        .emit_world_network_frame(
            &link,
            NetworkLinkDirection::EndpointBToEndpointA,
            seed,
            &Frame::new(0, 22, vec![6, 7]),
            PastDeliveryPolicy::FailLoud,
        )
        .expect("reverse frame should emit");

    let checkpoint = original
        .materialized_scheduler_state_with_store(&store)
        .expect("checkpoint payloads should persist");
    let mut resumed = SingleScheduler::from_world_with_scheduler_state(
        scenario,
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
        &checkpoint,
    )
    .expect("materialized link queues should restore");
    assert_eq!(
        checkpoint,
        resumed
            .materialized_scheduler_state_with_store(&store)
            .expect("resumed state should materialize")
    );

    let original_outcome = original
        .drive_quantum(QuantumRequest {
            configuration: original.configuration().clone(),
            control: Vec::new(),
        })
        .expect("original scheduler should deliver deterministically");
    let resumed_outcome = resumed
        .drive_quantum(QuantumRequest {
            configuration: resumed.configuration().clone(),
            control: Vec::new(),
        })
        .expect("resumed scheduler should deliver deterministically");
    assert_eq!(original_outcome, resumed_outcome);
    assert_eq!(
        original
            .materialized_scheduler_state_with_store(&store)
            .expect("original continuation should materialize"),
        resumed
            .materialized_scheduler_state_with_store(&store)
            .expect("resumed continuation should materialize")
    );
}

#[test]
fn materialized_active_network_faults_restore_link_and_topology_together() {
    let (world, store) = runtime_world_and_store();
    let link = canonical_link_id("vm-a", "vm-b");
    let scenario = scheduler_scenario(&world);
    let mut original = SingleScheduler::from_world(
        scenario.clone(),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("original scheduler should instantiate");
    original
        .apply_control_at_boundary(vec![
            ControlOperation {
                sequence: 0,
                kind: ControlOperationKind::InjectFault {
                    tag: FaultTag::from_name("resume-partition"),
                    fault: Fault::Network(NetworkFault::Partition {
                        link: link.clone(),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    }),
                },
            },
            ControlOperation {
                sequence: 1,
                kind: ControlOperationKind::InjectFault {
                    tag: FaultTag::from_name("resume-latency"),
                    fault: Fault::Network(NetworkFault::LatencyBump {
                        link: link.clone(),
                        extra: FaultDuration::from_nanos(40),
                    }),
                },
            },
        ])
        .expect("active network faults should apply");
    assert!(
        original
            .apply_queued_topology_changes_at_boundary()
            .expect("fault topology should apply")
    );

    let checkpoint = original
        .materialized_scheduler_state_with_store(&store)
        .expect("faulted checkpoint should materialize");
    let resumed = SingleScheduler::from_world_with_scheduler_state(
        scenario,
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
        &checkpoint,
    )
    .expect("faulted scheduler should resume");
    let endpoint_a = SchedulerNodeId {
        node: node_id("vm-a"),
        kind: SchedulingNodeKind::Vm,
    };
    let endpoint_b = SchedulerNodeId {
        node: node_id("vm-b"),
        kind: SchedulingNodeKind::Vm,
    };

    assert!(
        resumed
            .world_network_link(&link, NetworkLinkDirection::EndpointAToEndpointB)
            .expect("restored forward link")
            .faults()
            .partitioned
    );
    assert_eq!(
        resumed
            .world_network_link(&link, NetworkLinkDirection::EndpointAToEndpointB)
            .expect("restored forward link")
            .faults()
            .added_latency_ns,
        40
    );
    assert!(
        original
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err()
    );
    assert!(
        resumed
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err(),
        "the restored topology must reject the actively partitioned direction"
    );
    assert_eq!(
        original
            .authorize_cross_node_send(&endpoint_b, &endpoint_a)
            .expect("original reverse direction remains live"),
        resumed
            .authorize_cross_node_send(&endpoint_b, &endpoint_a)
            .expect("restored reverse direction remains live")
    );
    assert_eq!(checkpoint, resumed.materialized_scheduler_state());
}

#[test]
fn materialized_pending_topology_change_resumes_at_the_same_boundary() {
    let (world, store) = runtime_world_and_store();
    let link = canonical_link_id("vm-a", "vm-b");
    let scenario = scheduler_scenario(&world);
    let mut original = SingleScheduler::from_world(
        scenario.clone(),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("original scheduler should instantiate");
    original
        .apply_control_at_boundary(vec![ControlOperation {
            sequence: 0,
            kind: ControlOperationKind::InjectFault {
                tag: FaultTag::from_name("pending-resume-partition"),
                fault: Fault::Network(NetworkFault::Partition {
                    link: link.clone(),
                    direction: PartitionDirection::EndpointAToEndpointB,
                }),
            },
        }])
        .expect("partition should queue a topology transition");

    let checkpoint = original
        .materialized_scheduler_state_with_store(&store)
        .expect("pending topology checkpoint should materialize");
    assert_eq!(checkpoint.pending_topology_changes.len(), 1);
    let mut resumed = SingleScheduler::from_world_with_scheduler_state(
        scenario,
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
        &checkpoint,
    )
    .expect("pending topology checkpoint should resume");
    assert_eq!(checkpoint, resumed.materialized_scheduler_state());

    let endpoint_a = SchedulerNodeId {
        node: node_id("vm-a"),
        kind: SchedulingNodeKind::Vm,
    };
    let endpoint_b = SchedulerNodeId {
        node: node_id("vm-b"),
        kind: SchedulingNodeKind::Vm,
    };
    assert!(
        original
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err()
    );
    assert!(
        resumed
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err(),
        "the resumed scheduler must retain the boundary send freeze"
    );
    assert!(
        original
            .apply_queued_topology_changes_at_boundary()
            .expect("original transition should apply")
    );
    assert!(
        resumed
            .apply_queued_topology_changes_at_boundary()
            .expect("resumed transition should apply")
    );
    assert!(
        original
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err()
    );
    assert!(
        resumed
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err()
    );
    assert_eq!(
        original.materialized_scheduler_state(),
        resumed.materialized_scheduler_state()
    );
}

#[test]
fn world_links_reject_declared_non_vm_endpoints() {
    let image = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"disk"));
    let result = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(vm("vm-a")),
            WorldNodeDef::Io(WorldIoNode::block(
                node_id("disk"),
                node_id("vm-a"),
                WorldIoCoreConfig::new(0),
                image,
                4,
                WorldBlockLatency::new(1, 1, 0, 0, 0),
            )),
        ],
        vec![LinkDef::new(node_id("vm-a"), node_id("disk")).expect("syntactic link")],
    );

    assert!(matches!(
        result,
        Err(EngineError::WorldLinkNonVmEndpoint { node, .. }) if node == node_id("disk")
    ));
}

#[test]
fn ambiguous_legacy_link_id_cannot_select_a_scheduler_owned_link() {
    let world = World::from_nodes_and_links(
        vec![vm("a"), vm("b--c"), vm("a--b"), vm("c")],
        vec![
            LinkDef::new(node_id("a"), node_id("b--c")).expect("first link"),
            LinkDef::new(node_id("a--b"), node_id("c")).expect("second link"),
        ],
    )
    .expect("collision World should validate");
    let store = MemoryDagStore::new();
    let scheduler = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("collision World scheduler should instantiate");
    let ambiguous = LinkId::from_name("a--b--c");

    assert!(
        scheduler
            .world_network_link(&ambiguous, NetworkLinkDirection::EndpointAToEndpointB)
            .is_none()
    );
    assert!(
        scheduler
            .world_network_link(
                &canonical_link_id("a", "b--c"),
                NetworkLinkDirection::EndpointAToEndpointB,
            )
            .is_some()
    );
    assert!(
        scheduler
            .world_network_link(
                &canonical_link_id("a--b", "c"),
                NetworkLinkDirection::EndpointAToEndpointB,
            )
            .is_some()
    );
}

#[test]
fn live_network_latency_and_partition_activate_and_heal_at_scheduler_boundaries() {
    let (world, store) = runtime_world_and_store();
    let mut scheduler = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("production World scheduler should instantiate");
    let endpoint_a = SchedulerNodeId {
        node: node_id("vm-a"),
        kind: SchedulingNodeKind::Vm,
    };
    let endpoint_b = SchedulerNodeId {
        node: node_id("vm-b"),
        kind: SchedulingNodeKind::Vm,
    };
    let link = canonical_link_id("vm-a", "vm-b");
    let latency_tag = FaultTag::from_name("live-network-latency");
    let partition_tag = FaultTag::from_name("live-network-partition");

    scheduler
        .apply_control_at_boundary(vec![ControlOperation {
            sequence: 0,
            kind: ControlOperationKind::InjectFault {
                tag: latency_tag.clone(),
                fault: Fault::Network(NetworkFault::LatencyBump {
                    link: link.clone(),
                    extra: FaultDuration::from_nanos(40),
                }),
            },
        }])
        .expect("latency activation should apply to the live link");
    assert_eq!(
        scheduler
            .world_network_link(&link, NetworkLinkDirection::EndpointAToEndpointB)
            .expect("forward live link")
            .faults()
            .added_latency_ns,
        40
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err(),
        "cross-node sends must remain frozen until the topology boundary"
    );
    assert!(
        scheduler
            .apply_queued_topology_changes_at_boundary()
            .expect("latency topology change should apply")
    );
    let latency_application = scheduler
        .topology_change_applications()
        .last()
        .expect("latency activation application");
    assert_eq!(
        latency_application.trigger,
        SchedulerTopologyChangeTrigger::FaultActivation
    );
    assert!(latency_application.updates.iter().any(|update| {
        update.node == endpoint_b
            && update.recomputed_lookahead
                == NetworkLookahead::Finite(crucible::SimDuration { nanos: 41 })
    }));

    scheduler
        .apply_control_at_boundary(vec![ControlOperation {
            sequence: 1,
            kind: ControlOperationKind::InjectFault {
                tag: partition_tag.clone(),
                fault: Fault::Network(NetworkFault::Partition {
                    link: link.clone(),
                    direction: PartitionDirection::EndpointAToEndpointB,
                }),
            },
        }])
        .expect("partition activation should apply to the live link");
    assert!(
        scheduler
            .world_network_link(&link, NetworkLinkDirection::EndpointAToEndpointB)
            .expect("forward live link")
            .faults()
            .partitioned
    );
    assert!(
        scheduler
            .apply_queued_topology_changes_at_boundary()
            .expect("partition topology change should apply")
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err()
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_b, &endpoint_a)
            .is_ok()
    );

    scheduler
        .apply_control_at_boundary(vec![ControlOperation {
            sequence: 2,
            kind: ControlOperationKind::HealFault { tag: partition_tag },
        }])
        .expect("partition heal should update the live link");
    assert!(
        !scheduler
            .world_network_link(&link, NetworkLinkDirection::EndpointAToEndpointB)
            .expect("forward live link")
            .faults()
            .partitioned
    );
    assert!(
        scheduler
            .apply_queued_topology_changes_at_boundary()
            .expect("partition heal topology change should apply")
    );
    assert_eq!(
        scheduler
            .topology_change_applications()
            .last()
            .expect("partial heal application")
            .trigger,
        SchedulerTopologyChangeTrigger::Heal,
        "healing a partition remains a heal while latency is still active"
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_ok()
    );

    scheduler
        .apply_control_at_boundary(vec![ControlOperation {
            sequence: 3,
            kind: ControlOperationKind::HealFault { tag: latency_tag },
        }])
        .expect("latency heal should update the live link");
    assert!(
        scheduler
            .apply_queued_topology_changes_at_boundary()
            .expect("latency heal topology change should apply")
    );
    assert_eq!(
        scheduler
            .world_network_link(&link, NetworkLinkDirection::EndpointAToEndpointB)
            .expect("forward live link")
            .faults()
            .added_latency_ns,
        0
    );
    let healed = scheduler
        .topology_change_applications()
        .last()
        .expect("latency heal application");
    assert_eq!(healed.trigger, SchedulerTopologyChangeTrigger::Heal);
    assert!(healed.updates.iter().any(|update| {
        update.node == endpoint_b
            && update.recomputed_lookahead
                == NetworkLookahead::Finite(crucible::SimDuration { nanos: 1 })
    }));
}

fn runtime_fault_fingerprint() -> (
    u64,
    Vec<crucible::DeviceDelivery>,
    u64,
    Vec<crucible::DeviceDelivery>,
) {
    let (world, store) = runtime_world_and_store();
    let mut scheduler = SingleScheduler::from_world(
        scheduler_scenario(&world),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("production World scheduler should instantiate");
    let disk = world.io_node(&node_id("disk")).expect("disk").device_id();
    let share = world.io_node(&node_id("share")).expect("share").device_id();
    scheduler
        .apply_control_at_boundary(vec![
            ControlOperation {
                sequence: 0,
                kind: ControlOperationKind::InjectFault {
                    tag: FaultTag::from_name("disk-latency"),
                    fault: Fault::Block(BlockFault::Latency {
                        device: disk,
                        extra: FaultDuration::from_nanos(1_000),
                        jitter: FaultDuration::from_nanos(17),
                    }),
                },
            },
            ControlOperation {
                sequence: 1,
                kind: ControlOperationKind::InjectFault {
                    tag: FaultTag::from_name("share-latency"),
                    fault: Fault::NineP(NinePFault::Latency {
                        device: share,
                        extra: FaultDuration::from_nanos(2_000),
                        jitter: FaultDuration::from_nanos(19),
                    }),
                },
            },
        ])
        .expect("device faults apply");

    let (disk_due, disk_deliveries) = {
        let disk = scheduler
            .device_sub_nodes_for_mut(&node_id("vm-a"))
            .expect("vm-a devices")
            .iter_mut()
            .find(|node| node.sub_node().kind == SchedulingNodeKind::Disk)
            .expect("disk attached");
        disk.submit(0, &BlockRequest::read(7, 0, 4))
            .expect("block request computes");
        let due = disk.next_exact_local_event().expect("block due");
        (due, disk.deliver_due(u64::MAX))
    };
    let (share_due, share_deliveries) = {
        let share = scheduler
            .device_sub_nodes_for_mut(&node_id("vm-b"))
            .expect("vm-b devices")
            .iter_mut()
            .find(|node| node.sub_node().kind == SchedulingNodeKind::NineP)
            .expect("share attached");
        share
            .submit_ninep_frame(0, &tversion(9, 4096, codec::PROTOCOL_VERSION))
            .expect("9p request computes");
        let due = share.next_exact_local_event().expect("9p due");
        (due, share.deliver_due(u64::MAX))
    };
    (disk_due, disk_deliveries, share_due, share_deliveries)
}

fn rng_draw_values(records: &[crucible::LinkEmitDecisionRecord]) -> Vec<u64> {
    records
        .iter()
        .flat_map(|record| record.decisions.iter())
        .filter_map(|decision| match decision {
            Decision::RngDraw(draw) => Some(draw.value),
            _ => None,
        })
        .collect()
}

fn block_probe(scheduler: &mut SingleScheduler) -> Vec<crucible::DeviceDelivery> {
    let disk = scheduler
        .device_sub_nodes_for_mut(&node_id("vm-a"))
        .expect("vm-a devices")
        .iter_mut()
        .find(|node| node.sub_node().kind == SchedulingNodeKind::Disk)
        .expect("disk attached");
    disk.submit(0, &BlockRequest::read(55, 0, 4))
        .expect("block probe computes");
    disk.deliver_due(u64::MAX)
}

fn runtime_world_and_store() -> (World, MemoryDagStore) {
    let block_bytes = (0_u16..512).flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    let base = BaseImage::new(block_bytes.clone());
    let tree = FsTree::try_new(Node::Directory {
        children: [(
            String::from("config"),
            Node::File {
                content: b"stable".to_vec(),
            },
        )]
        .into_iter()
        .collect(),
    })
    .expect("test 9p tree is valid");
    let tree_bytes = tree.canonical_bytes();
    let store = MemoryDagStore::new();
    let block_key = store.put(&block_bytes).expect("block artifact stores");
    let tree_key = store.put(&tree_bytes).expect("9p artifact stores");
    assert_eq!(block_key, ContentHash { bytes: base.hash() });
    assert_eq!(
        tree_key,
        ContentHash {
            bytes: tree.content_hash()
        }
    );

    let world = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(vm("vm-a")),
            WorldNodeDef::Vm(vm("vm-b")),
            WorldNodeDef::Io(WorldIoNode::block(
                node_id("disk"),
                node_id("vm-a"),
                WorldIoCoreConfig::new(0),
                ContentAddressedBlobRef::from_hash(block_key),
                block_bytes.len() as u64,
                WorldBlockLatency::new(100, 200, 30, 40, 2),
            )),
            WorldNodeDef::Io(WorldIoNode::ninep(
                node_id("share"),
                node_id("vm-b"),
                WorldIoCoreConfig::new(0),
                ContentAddressedBlobRef::from_hash(tree_key),
                WorldNinePLatency::new(80, 120, 1),
            )),
        ],
        vec![LinkDef::new(node_id("vm-a"), node_id("vm-b")).expect("test link")],
    )
    .expect("runtime World should validate");
    (world, store)
}

fn scheduler_scenario(world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        "world-io-runtime",
        Shift { bits: 0 },
        8,
        SimInstant { nanos: 100_000 },
        world
            .vm_nodes()
            .iter()
            .map(|node| SchedulerScenarioNode {
                id: SchedulerNodeId {
                    node: node.id.clone(),
                    kind: SchedulingNodeKind::Vm,
                },
                counter: NodeCounter { ticks: 0 },
                activity: SchedulerNodeActivity::Idle,
                network_lookahead: NetworkLookahead::Infinite,
                exact_local_event: ExactLocalEvent::NoArmedTimer,
            })
            .collect(),
        Vec::new(),
    )
}

fn vm(name: &str) -> WorldNode {
    WorldNode {
        id: node_id(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn canonical_link_id(left: &str, right: &str) -> LinkId {
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
