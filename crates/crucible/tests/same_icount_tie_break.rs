//! Checks the same-icount scheduler tie-break contract.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, NodeId, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerNodeId, SchedulingNodeKind, VirtualTime, ordered_scheduled_events,
};

#[test]
fn same_icount_inputs_resolve_by_virtual_time_consumer_producer_sequence() {
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let vm_b = scheduler_node("b", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let network_a = scheduler_node("a", SchedulingNodeKind::Network);
    let arrival_order = vec![
        event(1, &vm_b, &disk_a, 0, b"third"),
        event(1, &vm_a, &network_a, 1, b"second"),
        event(2, &vm_a, &disk_a, 0, b"fourth"),
        event(1, &vm_a, &disk_a, 7, b"first"),
    ];

    let resolved = ordered_scheduled_events(&arrival_order);

    assert_eq!(
        resolved
            .iter()
            .map(|event| backend_payload(event))
            .collect::<Vec<_>>(),
        vec![
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
            b"fourth".as_slice(),
        ]
    );
}

#[test]
fn same_icount_inputs_keep_order_when_arrival_order_reverses() {
    let vm_a = scheduler_node("a", SchedulingNodeKind::Vm);
    let disk_a = scheduler_node("a", SchedulingNodeKind::Disk);
    let network_a = scheduler_node("a", SchedulingNodeKind::Network);
    let forward = vec![
        event(8, &vm_a, &network_a, 3, b"producer-b"),
        event(8, &vm_a, &disk_a, 9, b"producer-a"),
    ];
    let reverse = vec![forward[1].clone(), forward[0].clone()];

    assert_eq!(
        ordered_scheduled_events(&forward)
            .iter()
            .map(|event| backend_payload(event))
            .collect::<Vec<_>>(),
        ordered_scheduled_events(&reverse)
            .iter()
            .map(|event| backend_payload(event))
            .collect::<Vec<_>>()
    );
}

fn event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn backend_payload(event: &ScheduledEvent) -> &[u8] {
    match &event.payload {
        ScheduledEventPayload::BackendInput(input) => input.payload.as_slice(),
        _ => panic!("test event should carry a backend input"),
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
