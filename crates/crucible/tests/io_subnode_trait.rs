//! Checks T-IO-1 uniform deterministic I/O sub-node lifecycle.

#![forbid(unsafe_code)]

use crucible::{
    DeterministicIoSubNode, Icount, IoSubNode, IoSubNodeError, IoSubNodeQueue, IoSubNodeRequest,
    NodeId, SchedulerNodeId, SchedulingNodeKind, Shift, SimDuration,
};

#[test]
fn completion_icount_is_derived_from_request_icount_latency_and_shift() {
    let mut subnode = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    subnode
        .enqueue_request(request(7, "vm-a", 3, 3, Some(0xfeed), b"read"))
        .expect("request should enqueue");

    assert_eq!(
        subnode.next_exact_local_event(),
        Some(Icount { retired: 5 })
    );
    assert_eq!(
        subnode
            .advance_to(Icount { retired: 4 })
            .expect("advance before completion should succeed"),
        Vec::new()
    );
    assert_eq!(subnode.current_icount(), Icount { retired: 4 });

    let due = subnode
        .advance_to(Icount { retired: 5 })
        .expect("advance to completion should succeed");

    assert_eq!(due.len(), 1);
    assert_eq!(due[0].request_icount, Icount { retired: 3 });
    assert_eq!(due[0].delivery_icount, Icount { retired: 5 });
    assert_eq!(due[0].modeled_latency, SimDuration { nanos: 3 });
    assert_eq!(due[0].rng_draw, Some(0xfeed));
    assert_eq!(due[0].payload, response_payload(b"read", Some(0xfeed)));
    assert_eq!(subnode.next_exact_local_event(), None);
    assert_eq!(subnode.drain_response_outbox(), due);
}

#[test]
fn completions_are_ordered_by_delivery_consumer_and_sequence() {
    let mut subnode = subnode("net", SchedulingNodeKind::Network, 8, 8);
    subnode
        .enqueue_request(request(2, "vm-b", 1, 4, None, b"b-later"))
        .expect("request should enqueue");
    subnode
        .enqueue_request(request(3, "vm-b", 1, 2, None, b"b-early"))
        .expect("request should enqueue");
    subnode
        .enqueue_request(request(1, "vm-a", 1, 2, None, b"a-early"))
        .expect("request should enqueue");

    let due = subnode
        .advance_to(Icount { retired: 3 })
        .expect("all completions should drain");

    let ordered = due
        .iter()
        .map(|completion| {
            (
                completion.delivery_icount.retired,
                completion.requester.node.name.as_str(),
                completion.sequence,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ordered,
        vec![(2, "vm-a", 1), (2, "vm-b", 3), (3, "vm-b", 2)]
    );
}

#[test]
fn deterministic_backpressure_rejects_without_drop_or_reorder() {
    let mut subnode = subnode("disk", SchedulingNodeKind::Disk, 1, 1);
    subnode
        .enqueue_request(request(1, "vm-a", 0, 4, None, b"first"))
        .expect("first request should enqueue");

    let error = subnode
        .enqueue_request(request(2, "vm-a", 0, 5, None, b"second"))
        .expect_err("full request queue should reject deterministically");

    assert!(matches!(
        error,
        IoSubNodeError::Backpressure {
            queue: IoSubNodeQueue::RequestInbox,
            capacity: 1,
        }
    ));
    assert_eq!(
        subnode.next_exact_local_event(),
        Some(Icount { retired: 2 })
    );
    assert_eq!(
        subnode
            .advance_to(Icount { retired: 2 })
            .expect("first completion should still drain")[0]
            .sequence,
        1
    );

    let error = subnode
        .enqueue_request(request(3, "vm-a", 0, 6, None, b"third"))
        .and_then(|()| subnode.advance_to(Icount { retired: 3 }).map(|_| ()))
        .expect_err("full response outbox should reject deterministically");

    assert!(matches!(
        error,
        IoSubNodeError::Backpressure {
            queue: IoSubNodeQueue::ResponseOutbox,
            capacity: 1,
        }
    ));
}

#[test]
fn snapshot_restore_preserves_inflight_and_outbox_state() {
    let mut original = subnode("9p", SchedulingNodeKind::NineP, 4, 4);
    original
        .enqueue_request(request(1, "vm-a", 0, 5, None, b"pending"))
        .expect("pending request should enqueue");
    original
        .enqueue_request(request(2, "vm-a", 0, 2, None, b"due"))
        .expect("due request should enqueue");
    original
        .advance_to(Icount { retired: 2 })
        .expect("due completion should enter outbox");

    let snapshot = original.snapshot();
    let mut restored = subnode("9p", SchedulingNodeKind::NineP, 1, 1);
    restored
        .restore(snapshot)
        .expect("matching node snapshot should restore");

    assert_eq!(restored.current_icount(), Icount { retired: 2 });
    assert_eq!(
        restored.next_exact_local_event(),
        Some(Icount { retired: 3 })
    );
    assert_eq!(
        restored
            .drain_response_outbox()
            .into_iter()
            .map(|completion| completion.sequence)
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(
        restored
            .advance_to(Icount { retired: 3 })
            .expect("restored pending completion should drain")[0]
            .sequence,
        1
    );
}

#[test]
fn monotonic_clock_rejects_backward_advance_and_past_completion() {
    let mut subnode = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    subnode
        .advance_to(Icount { retired: 100 })
        .expect("scheduler may advance an idle sub-node clock");

    let rewind = subnode
        .advance_to(Icount { retired: 99 })
        .expect_err("sub-node clock must not rewind");
    assert!(matches!(
        rewind,
        IoSubNodeError::ClockRewind {
            current_icount: Icount { retired: 100 },
            requested_icount: Icount { retired: 99 },
        }
    ));

    let past_completion = subnode
        .enqueue_request(request(1, "vm-a", 0, 0, None, b"past"))
        .expect_err("completion before current sub-node clock must fail");
    assert!(matches!(
        past_completion,
        IoSubNodeError::CompletionBeforeClock {
            current_icount: Icount { retired: 100 },
            delivery_icount: Icount { retired: 0 },
        }
    ));
}

#[test]
fn restore_rejects_structurally_invalid_public_snapshot() {
    let mut original = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    original
        .enqueue_request(request(1, "vm-a", 0, 2, None, b"due"))
        .expect("request should enqueue");
    original
        .advance_to(Icount { retired: 1 })
        .expect("completion should enter outbox");
    let mut snapshot = original.snapshot();
    snapshot.response_outbox[0].sub_node = scheduler_node("other-disk", SchedulingNodeKind::Disk);

    let mut restored = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    let error = restored
        .restore(snapshot)
        .expect_err("forged snapshot completion should fail");

    assert!(
        matches!(error, IoSubNodeError::InvalidSnapshot { message } if message.contains("belongs to other-disk"))
    );
}

#[test]
fn response_outbox_remains_in_deterministic_order_across_advances() {
    let mut subnode = subnode("net", SchedulingNodeKind::Network, 4, 4);
    subnode
        .enqueue_request(request(1, "vm-b", 0, 0, None, b"b"))
        .expect("first request should enqueue");
    subnode
        .advance_to(Icount { retired: 0 })
        .expect("first completion should enter outbox");
    subnode
        .enqueue_request(request(2, "vm-a", 0, 0, None, b"a"))
        .expect("second same-time request should enqueue");
    subnode
        .advance_to(Icount { retired: 0 })
        .expect("second completion should enter outbox");

    let drained = subnode
        .drain_response_outbox()
        .into_iter()
        .map(|completion| (completion.requester.node.name, completion.sequence))
        .collect::<Vec<_>>();

    assert_eq!(
        drained,
        vec![(String::from("vm-a"), 2), (String::from("vm-b"), 1)]
    );
}

#[test]
fn restore_rejects_forged_completion_delivery_icount() {
    let mut original = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    original
        .enqueue_request(request(1, "vm-a", 0, 0, None, b"forged"))
        .expect("request should enqueue");
    let mut snapshot = original.snapshot();
    snapshot.in_flight[0].delivery_icount = Icount { retired: 100 };

    let mut restored = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    let error = restored
        .restore(snapshot)
        .expect_err("forged delivery icount should fail");

    assert!(
        matches!(error, IoSubNodeError::InvalidSnapshot { message } if message.contains("does not match deterministic request+latency"))
    );
}

#[test]
fn enqueue_rejects_non_vm_requester() {
    let mut subnode = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    let mut invalid = request(1, "disk-peer", 0, 1, None, b"invalid");
    invalid.requester = scheduler_node("disk-peer", SchedulingNodeKind::Disk);

    let error = subnode
        .enqueue_request(invalid)
        .expect_err("I/O requester must be a VM scheduler node");

    assert!(matches!(
        error,
        IoSubNodeError::InvalidRequesterKind {
            kind: SchedulingNodeKind::Disk
        }
    ));
}

#[test]
fn constructor_rejects_invalid_shift() {
    let error = DeterministicIoSubNode::new(
        scheduler_node("disk", SchedulingNodeKind::Disk),
        Shift { bits: 64 },
        1,
        1,
    )
    .expect_err("invalid shift should fail at construction");

    assert!(matches!(error, IoSubNodeError::TimeConversion(_)));
}

#[test]
fn restore_rejects_invalid_empty_snapshot_shift() {
    let original = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    let mut snapshot = original.snapshot();
    snapshot.shift = Shift { bits: 64 };

    let mut restored = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    let error = restored
        .restore(snapshot)
        .expect_err("invalid shift should fail even for an empty snapshot");

    assert!(matches!(error, IoSubNodeError::TimeConversion(_)));
}

#[test]
fn vm_nodes_are_rejected_as_io_subnodes() {
    let error = DeterministicIoSubNode::new(
        scheduler_node("vm-a", SchedulingNodeKind::Vm),
        shift(0),
        1,
        1,
    )
    .expect_err("VM node is not an I/O sub-node");

    assert!(matches!(
        error,
        IoSubNodeError::InvalidNodeKind {
            kind: SchedulingNodeKind::Vm
        }
    ));
}

#[test]
fn scheduler_completion_preserves_exact_delivery_icount() {
    let mut subnode = subnode("disk", SchedulingNodeKind::Disk, 4, 4);
    subnode
        .enqueue_request(request(4, "vm-a", 11, 5, None, b"block"))
        .expect("request should enqueue");
    let completion = subnode
        .advance_to(Icount { retired: 14 })
        .expect("completion should drain")
        .remove(0);
    let scheduler_completion = completion.to_scheduler_completion();

    assert_eq!(
        scheduler_completion.sub_node,
        scheduler_node("disk", SchedulingNodeKind::Disk)
    );
    assert_eq!(
        scheduler_completion.target,
        NodeId {
            name: String::from("vm-a")
        }
    );
    assert_eq!(scheduler_completion.delivery_icount, Icount { retired: 14 });
    assert_eq!(scheduler_completion.payload, b"block".to_vec());
}

fn subnode(
    name: &str,
    kind: SchedulingNodeKind,
    request_capacity: usize,
    response_capacity: usize,
) -> DeterministicIoSubNode {
    DeterministicIoSubNode::new(
        scheduler_node(name, kind),
        shift(1),
        request_capacity,
        response_capacity,
    )
    .expect("test sub-node should build")
}

fn request(
    sequence: u64,
    requester: &str,
    request_icount: u64,
    latency_ns: u64,
    rng_draw: Option<u64>,
    payload: &[u8],
) -> IoSubNodeRequest {
    IoSubNodeRequest {
        sequence,
        requester: scheduler_node(requester, SchedulingNodeKind::Vm),
        request_icount: Icount {
            retired: request_icount,
        },
        modeled_latency: SimDuration { nanos: latency_ns },
        rng_draw,
        payload: payload.to_vec(),
    }
}

fn response_payload(payload: &[u8], rng_draw: Option<u64>) -> Vec<u8> {
    let mut response = payload.to_vec();
    if let Some(draw) = rng_draw {
        response.extend_from_slice(&draw.to_le_bytes());
    }
    response
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
