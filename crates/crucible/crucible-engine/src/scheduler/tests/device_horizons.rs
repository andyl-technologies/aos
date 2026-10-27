//! Complete device horizon calculation without transient scheduler-history copies.
//!
//! Real disk/link queues exercise explicit completion minima and read-only
//! enumeration; these are modeled scheduler tests, not native custody.

use super::*;

fn add_link(scheduler: &mut SingleScheduler, source: &str, target: &str, latency: u64) {
    let link_id = LinkId {
        name: format!("horizon-{source}-{target}"),
    };
    let direction = NetworkLinkDirection::EndpointAToEndpointB;
    let mut link =
        crucible_device::NetLink::new(0, latency, 1, crucible_device::LinkFaults::none())
            .unwrap_or_else(|error| panic!("horizon link should build: {error}"));
    link.emit(
        &crucible_device::Frame::new(0, 7, vec![1, 2, 3]),
        &crucible_device::FrameDraws::default(),
        crucible_device::PastDeliveryPolicy::FailLoud,
    )
    .unwrap_or_else(|error| panic!("horizon frame should enter flight: {error}"));
    scheduler.world_network_links.insert(
        (link_id.clone(), direction),
        WorldNetworkLinkRuntime {
            canonical_id: link_id.clone(),
            endpoint_a: NodeId {
                name: source.into(),
            },
            endpoint_b: NodeId {
                name: target.into(),
            },
            direction,
            scheduler_node: scheduler_node(&link_id.name, SchedulingNodeKind::Network),
            rng_stream: RngStreamId::for_link(link_id.name.clone()),
            fault_id: crate::DeviceId::from_name(&link_id.name),
            link,
        },
    );
}

fn mixed_queues() -> SingleScheduler {
    let nodes = ["c", "b", "a"]
        .into_iter()
        .map(|name| {
            test_scenario_node(
                name,
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )
        })
        .collect();
    let mut scheduler = test_scheduler(nodes, Vec::new())
        .with_device_sub_node(disk_with_reads("a", "disk-a-late", &[(300, 8)]))
        .with_device_sub_node(disk_with_reads("a", "disk-a-early", &[(1, 8)]))
        .with_device_sub_node(disk_with_reads("b", "disk-b-empty", &[]))
        .with_device_sub_node(disk_with_reads("c", "disk-c", &[(5, 8)]));
    add_link(&mut scheduler, "b", "a", 10);
    add_link(&mut scheduler, "c", "a", 7);
    add_link(&mut scheduler, "a", "b", 20);
    scheduler
}

fn refused_error<T>(result: Result<T, SchedulerError>) -> SchedulerError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("invalid horizon inventory should refuse"),
    }
}

fn device_checkpoints(
    scheduler: &SingleScheduler,
) -> Vec<crate::device_subnode::DeviceSchedulingSubNodeCheckpoint> {
    scheduler
        .device_sub_nodes
        .values()
        .flatten()
        .map(|device| device.checkpoint())
        .collect()
}

fn activities(scheduler: &SingleScheduler) -> Vec<(SchedulerNodeId, SchedulerNodeActivity)> {
    scheduler
        .nodes
        .iter()
        .map(|node| (node.id.clone(), node.activity))
        .collect()
}

#[test]
fn complete_horizons_preserve_explicit_queue_minima_and_read_only_state() {
    let scheduler = mixed_queues();
    let before_activity = activities(&scheduler);
    let before_pending = scheduler.pending_events.clone();
    let before_network = scheduler.network_checkpoint();
    let before_devices = device_checkpoints(&scheduler);
    let calculated = scheduler
        .complete_device_horizons()
        .unwrap_or_else(|error| panic!("complete enumeration should succeed: {error}"));

    assert_eq!(activities(&scheduler), before_activity);
    assert_eq!(scheduler.pending_events, before_pending);
    assert_eq!(scheduler.network_checkpoint(), before_network);
    assert_eq!(device_checkpoints(&scheduler), before_devices);
    assert!(scheduler.device_horizons.is_empty());
    // Link responses win on a and b; c retains the real disk completion.
    let expected = vec![
        (
            NodeId { name: "a".into() },
            scheduler.network_time_for_tick(7),
        ),
        (
            NodeId { name: "b".into() },
            scheduler.network_time_for_tick(20),
        ),
        (NodeId { name: "c".into() }, SimInstant { ticks: 1_008_005 }),
    ];
    assert_eq!(calculated, expected);

    let mut refreshed = scheduler.clone();
    refreshed
        .refresh_device_horizons()
        .unwrap_or_else(|error| panic!("shared refresh should succeed: {error}"));
    let installed = refreshed
        .device_horizons
        .iter()
        .map(|(target, instant)| (target.clone(), *instant))
        .collect::<Vec<_>>();
    assert_eq!(installed, expected);
    let expected_activity = before_activity
        .iter()
        .map(|(id, _)| (id.clone(), SchedulerNodeActivity::Runnable))
        .collect::<Vec<_>>();
    assert_eq!(activities(&refreshed), expected_activity);
    assert_eq!(refreshed.network_checkpoint(), before_network);
    assert_eq!(refreshed.pending_events, before_pending);
    assert_eq!(device_checkpoints(&refreshed), before_devices);

    refreshed
        .refresh_device_horizons()
        .unwrap_or_else(|error| panic!("second refresh should succeed: {error}"));
    assert_eq!(
        refreshed
            .device_horizons
            .iter()
            .map(|(target, instant)| (target.clone(), *instant))
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn prepared_input_refuses_missing_extra_and_changed_horizon_cache_entries() {
    let mut scheduler = mixed_queues();
    scheduler
        .refresh_device_horizons()
        .unwrap_or_else(|error| panic!("fixture cache should refresh: {error}"));
    let node = scheduler
        .nodes
        .iter()
        .find(|node| node.id.node.name == "b")
        .unwrap_or_else(|| panic!("requester b should exist"))
        .clone();
    for mutation in 0..3 {
        let mut stale = scheduler.clone();
        match mutation {
            0 => {
                stale.device_horizons.remove(&NodeId { name: "a".into() });
            }
            1 => {
                stale.device_horizons.insert(
                    NodeId {
                        name: "ghost".into(),
                    },
                    SimInstant { ticks: 1 },
                );
            }
            _ => {
                stale
                    .device_horizons
                    .insert(NodeId { name: "a".into() }, SimInstant { ticks: 8 });
            }
        }
        let before = stale.device_horizons.clone();
        let before_activity = activities(&stale);
        let result = stale.prepared_run_next_input(&node);
        assert!(
            matches!(result, Err(SchedulerError::BoundaryViolation { ref message })
            if message == "RUN input inventory has stale device horizons")
        );
        assert_eq!(stale.device_horizons, before);
        assert_eq!(activities(&stale), before_activity);
    }
}

#[test]
fn horizon_conversion_errors_keep_original_order_and_leave_refresh_untouched() {
    let mut scheduler = mixed_queues().with_device_sub_node(disk_with_reads(
        "z-missing",
        "disk-missing",
        &[(1, 8)],
    ));
    let index = scheduler
        .vm_node_index(&NodeId { name: "a".into() })
        .unwrap_or_else(|error| panic!("node a should exist: {error}"));
    scheduler.nodes[index].time_mapping.anchor_time = SimInstant { ticks: u64::MAX };
    scheduler.device_horizons.insert(
        NodeId {
            name: "sentinel".into(),
        },
        SimInstant { ticks: 42 },
    );
    let before = scheduler.device_horizons.clone();
    let before_activity = activities(&scheduler);
    // Conversion follows attachment order, before completion minima are selected.
    let expected = SchedulerError::TimeConversion(TimeConversionError::VirtualTimeOverflow {
        icount: crate::Icount { retired: 1_008_300 },
    });
    let actual = refused_error(scheduler.complete_device_horizons());
    assert_eq!(actual, expected);
    let refresh_error = refused_error(scheduler.refresh_device_horizons());
    assert_eq!(refresh_error, expected);
    assert_eq!(scheduler.device_horizons, before);
    assert_eq!(activities(&scheduler), before_activity);

    scheduler.nodes[index].time_mapping = NodeTimeMapping::IDENTITY;
    let expected = SchedulerError::BoundaryViolation {
        message: "node timing fault targets missing VM node: z-missing".into(),
    };
    assert_eq!(
        refused_error(scheduler.complete_device_horizons()),
        expected
    );
    assert_eq!(refused_error(scheduler.refresh_device_horizons()), expected);
    assert_eq!(scheduler.device_horizons, before);
    assert_eq!(activities(&scheduler), before_activity);
}

#[test]
fn prepared_input_preserves_known_absence_and_the_earliest_actual_pending_input() {
    let mut empty = test_scheduler(
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    let node = empty.nodes[0].clone();
    assert!(
        empty
            .complete_device_horizons()
            .unwrap_or_else(|error| panic!("empty inventory should enumerate: {error}"))
            .is_empty()
    );
    assert_eq!(
        empty
            .prepared_run_next_input(&node)
            .unwrap_or_else(|error| panic!("known absence should validate: {error}")),
        None
    );
    assert_eq!(
        activities(&empty),
        vec![(node.id.clone(), SchedulerNodeActivity::Idle)]
    );

    empty.pending_events.push(event(
        12,
        &node.id,
        &scheduler_node("peer", SchedulingNodeKind::Vm),
        0,
        b"input",
    ));
    assert_eq!(
        empty
            .prepared_run_next_input(&node)
            .unwrap_or_else(|error| panic!("real pending input should validate: {error}")),
        Some(NodeCounter { ticks: 12 })
    );
    assert_eq!(empty.pending_events.len(), 1);
    assert!(empty.device_horizons.is_empty());
}
