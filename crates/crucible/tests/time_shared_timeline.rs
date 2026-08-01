//! Public API tests for shared virtual timeline projection.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Icount, NodeCounter, NodeId, ScheduledEventKey, SchedulerNodeId, SchedulingNodeKind,
    SharedTimeline, SharedTimelineKey, Shift, SimInstant, VirtualTime, ordered_timeline_keys,
};

#[test]
fn vm_and_io_counters_project_to_one_shared_timeline() {
    let timeline = shared_timeline(3);
    let vm = scheduler_node("vm-a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("vm-a", SchedulingNodeKind::Disk);

    let vm_projection = project_counter(
        &timeline,
        vm.clone(),
        NodeCounter::from_icount(Icount { retired: 6 }),
    );
    let disk_projection = project_counter(&timeline, disk.clone(), NodeCounter { ticks: 6 });

    assert_eq!(timeline.shift(), shift(3));
    assert_eq!(vm_projection.node, vm);
    assert_eq!(disk_projection.node, disk);
    assert_eq!(vm_projection.virtual_time, SimInstant { nanos: 48 });
    assert_eq!(disk_projection.virtual_time, SimInstant { nanos: 48 });
}

#[test]
fn shared_timeline_keys_are_arrival_order_independent() {
    let timeline = shared_timeline(0);
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
    let forward = vec![
        timeline_key(&timeline, vm_b, 1, 0),
        timeline_key(&timeline, vm_a.clone(), 1, 9),
        timeline_key(&timeline, vm_a, 1, 2),
    ];
    let reverse = vec![forward[2].clone(), forward[1].clone(), forward[0].clone()];

    assert_eq!(
        ordered_timeline_keys(&forward)
            .iter()
            .map(|key| key.sequence)
            .collect::<Vec<_>>(),
        vec![2, 9, 0]
    );
    assert_eq!(
        ordered_timeline_keys(&forward),
        ordered_timeline_keys(&reverse)
    );
}

#[test]
fn scheduled_event_keys_consume_shared_timeline_keys() {
    let timeline = shared_timeline(0);
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let disk = scheduler_node("consumer", SchedulingNodeKind::Disk);
    let network = scheduler_node("consumer", SchedulingNodeKind::Network);
    let mut keys = [
        ScheduledEventKey::new(timeline_key(&timeline, consumer.clone(), 5, 10), network),
        ScheduledEventKey::new(timeline_key(&timeline, consumer.clone(), 5, 2), disk),
    ];

    keys.sort();

    assert_eq!(keys[0].producer.kind, SchedulingNodeKind::Disk);
    assert_eq!(keys[0].consumer(), &consumer);
    assert_eq!(keys[0].virtual_time(), VirtualTime { ticks: 5 });
    assert_eq!(keys[0].sequence(), 2);
    assert_eq!(keys[1].sequence(), 10);
}

fn shift(bits: u8) -> Shift {
    match Shift::new(bits) {
        Ok(shift) => shift,
        Err(error) => panic!("test shift should be valid: {error}"),
    }
}

fn shared_timeline(bits: u8) -> SharedTimeline {
    match SharedTimeline::new(shift(bits)) {
        Ok(timeline) => timeline,
        Err(error) => panic!("test timeline should be valid: {error}"),
    }
}

fn project_counter(
    timeline: &SharedTimeline,
    node: SchedulerNodeId,
    counter: NodeCounter,
) -> crucible::NodeTimelineProjection {
    match timeline.project_counter(node, counter) {
        Ok(projection) => projection,
        Err(error) => panic!("test counter should project: {error}"),
    }
}

fn timeline_key(
    timeline: &SharedTimeline,
    node: SchedulerNodeId,
    counter: u64,
    sequence: u64,
) -> SharedTimelineKey {
    match timeline.timeline_key(node, NodeCounter { ticks: counter }, sequence) {
        Ok(key) => key,
        Err(error) => panic!("test timeline key should project: {error}"),
    }
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}
