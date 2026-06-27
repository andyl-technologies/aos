//! Checks T-IO-4 deterministic block sub-node completion planning.

#![forbid(unsafe_code)]

use crucible::{
    BlockCompletionError, BlockCompletionRequest, BlockLatencyParameters, BlockSubNodeOperation,
    DeterministicIoSubNode, Icount, IoSubNode, IoSubNodeError, NodeId, SchedulerNodeId,
    SchedulingNodeKind, Shift, SimDuration, sort_block_completion_plans,
};

#[test]
fn completion_icount_uses_request_icount_operation_count_params_and_shift() {
    let plan = request(
        7,
        "disk-a",
        "vm-a",
        BlockSubNodeOperation::Read,
        5,
        3,
        b"read",
    )
    .plan(shift(1), latency_params())
    .expect("completion should plan");

    assert_eq!(plan.modeled_latency, SimDuration { nanos: 15 });
    assert_eq!(plan.delivery_icount, Icount { retired: 11 });
    assert_eq!(plan.payload, b"read".to_vec());
}

#[test]
fn latency_model_differentiates_operation_and_byte_count() {
    let params = latency_params();

    assert_eq!(
        params
            .latency_for(BlockSubNodeOperation::Read, 4)
            .expect("read latency should compute"),
        SimDuration { nanos: 14 }
    );
    assert_eq!(
        params
            .latency_for(BlockSubNodeOperation::Write, 4)
            .expect("write latency should compute"),
        SimDuration { nanos: 24 }
    );
    assert_eq!(
        params
            .latency_for(BlockSubNodeOperation::Flush, 0)
            .expect("flush latency should compute"),
        SimDuration { nanos: 30 }
    );
    assert_eq!(
        params
            .latency_for(BlockSubNodeOperation::GetLength, 0)
            .expect("get-length latency should compute"),
        SimDuration { nanos: 40 }
    );
}

#[test]
fn coincident_completions_sort_by_delivery_subnode_and_sequence() {
    let mut plans = vec![
        request(
            9,
            "disk-b",
            "vm-a",
            BlockSubNodeOperation::Flush,
            0,
            0,
            b"b9",
        )
        .plan(shift(0), zero_latency())
        .expect("completion should plan"),
        request(
            2,
            "disk-a",
            "vm-a",
            BlockSubNodeOperation::Flush,
            0,
            0,
            b"a2",
        )
        .plan(shift(0), zero_latency())
        .expect("completion should plan"),
        request(
            1,
            "disk-a",
            "vm-a",
            BlockSubNodeOperation::Flush,
            0,
            0,
            b"a1",
        )
        .plan(shift(0), zero_latency())
        .expect("completion should plan"),
    ];

    sort_block_completion_plans(&mut plans);

    let order = plans
        .iter()
        .map(|plan| {
            (
                plan.delivery_icount.retired,
                plan.sub_node.node.name.as_str(),
                plan.sequence,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        order,
        vec![(0, "disk-a", 1), (0, "disk-a", 2), (0, "disk-b", 9)]
    );
}

#[test]
fn planned_completion_feeds_uniform_io_subnode_without_recomputing_host_time() {
    let plan = request(
        3,
        "disk-a",
        "vm-a",
        BlockSubNodeOperation::Write,
        4,
        4,
        b"ok",
    )
    .plan(shift(1), latency_params())
    .expect("completion should plan");
    let mut subnode = DeterministicIoSubNode::new(
        scheduler_node("disk-a", SchedulingNodeKind::Disk),
        shift(1),
        4,
        4,
    )
    .expect("subnode should build");

    subnode
        .enqueue_request(plan.into_io_request())
        .expect("planned block completion should enqueue");

    assert_eq!(
        subnode.next_exact_local_event(),
        Some(Icount { retired: 16 })
    );
    let completion = subnode
        .advance_to(Icount { retired: 16 })
        .expect("completion should become due")
        .remove(0);
    assert_eq!(completion.sequence, 3);
    assert_eq!(completion.modeled_latency, SimDuration { nanos: 24 });
    assert_eq!(completion.delivery_icount, Icount { retired: 16 });
    assert_eq!(completion.payload, b"ok".to_vec());
}

#[test]
fn planned_completion_rejects_wrong_uniform_subnode_or_shift() {
    let plan = request(
        3,
        "disk-a",
        "vm-a",
        BlockSubNodeOperation::Write,
        4,
        4,
        b"ok",
    )
    .plan(shift(1), latency_params())
    .expect("completion should plan");

    let mut wrong_subnode = DeterministicIoSubNode::new(
        scheduler_node("disk-b", SchedulingNodeKind::Disk),
        shift(1),
        4,
        4,
    )
    .expect("subnode should build");
    let wrong_subnode_error = wrong_subnode
        .enqueue_request(plan.clone().into_io_request())
        .expect_err("planned completion must not enqueue on the wrong source");
    assert!(matches!(
        wrong_subnode_error,
        IoSubNodeError::ExpectedSubNodeMismatch { expected, actual }
            if expected == scheduler_node("disk-a", SchedulingNodeKind::Disk)
                && actual == scheduler_node("disk-b", SchedulingNodeKind::Disk)
    ));

    let mut wrong_shift = DeterministicIoSubNode::new(
        scheduler_node("disk-a", SchedulingNodeKind::Disk),
        shift(0),
        4,
        4,
    )
    .expect("subnode should build");
    let wrong_shift_error = wrong_shift
        .enqueue_request(plan.into_io_request())
        .expect_err("planned delivery icount must be enforced");
    assert!(matches!(
        wrong_shift_error,
        IoSubNodeError::ExpectedDeliveryMismatch {
            expected: Icount { retired: 16 },
            actual: Icount { retired: 28 },
        }
    ));
}

#[test]
fn planner_rejects_non_disk_subnodes_and_non_vm_requesters() {
    let invalid_subnode = request(
        1,
        "vm-looking",
        "vm-a",
        BlockSubNodeOperation::Read,
        1,
        0,
        b"bad",
    )
    .plan(shift(0), zero_latency());
    assert!(matches!(
        invalid_subnode,
        Err(BlockCompletionError::InvalidNodeKind {
            kind: SchedulingNodeKind::Vm
        })
    ));

    let mut invalid_requester = request(
        1,
        "disk-a",
        "disk-peer",
        BlockSubNodeOperation::Read,
        1,
        0,
        b"bad",
    );
    invalid_requester.requester = scheduler_node("disk-peer", SchedulingNodeKind::Disk);
    assert!(matches!(
        invalid_requester.plan(shift(0), zero_latency()),
        Err(BlockCompletionError::InvalidRequesterKind {
            kind: SchedulingNodeKind::Disk
        })
    ));
}

#[test]
fn latency_and_completion_time_overflow_fail_loudly() {
    let latency = BlockLatencyParameters::new(
        SimDuration { nanos: u64::MAX },
        SimDuration { nanos: 0 },
        SimDuration { nanos: 0 },
        SimDuration { nanos: 0 },
        SimDuration { nanos: 1 },
    );
    assert!(matches!(
        latency.latency_for(BlockSubNodeOperation::Read, 1),
        Err(BlockCompletionError::LatencyOverflow {
            operation: BlockSubNodeOperation::Read,
            count: 1,
        })
    ));

    let completion_overflow = request(
        1,
        "disk-a",
        "vm-a",
        BlockSubNodeOperation::Flush,
        1,
        u64::MAX,
        b"overflow",
    )
    .plan(
        shift(0),
        BlockLatencyParameters::new(
            SimDuration { nanos: 1 },
            SimDuration { nanos: 0 },
            SimDuration { nanos: 1 },
            SimDuration { nanos: 0 },
            SimDuration { nanos: 0 },
        ),
    );
    assert!(matches!(
        completion_overflow,
        Err(BlockCompletionError::CompletionTimeOverflow {
            request_icount: Icount { retired: u64::MAX },
            modeled_latency: SimDuration { nanos: 1 },
        })
    ));
}

#[test]
fn invalid_shift_rejects_completion_planning() {
    let error = request(
        1,
        "disk-a",
        "vm-a",
        BlockSubNodeOperation::Read,
        1,
        0,
        b"bad",
    )
    .plan(Shift { bits: 64 }, zero_latency())
    .expect_err("invalid shift should fail");

    assert!(matches!(error, BlockCompletionError::TimeConversion(_)));
}

fn request(
    sequence: u64,
    sub_node: &str,
    requester: &str,
    operation: BlockSubNodeOperation,
    count: u32,
    request_icount: u64,
    payload: &[u8],
) -> BlockCompletionRequest {
    BlockCompletionRequest {
        sequence,
        sub_node: if sub_node.starts_with("vm") {
            scheduler_node(sub_node, SchedulingNodeKind::Vm)
        } else {
            scheduler_node(sub_node, SchedulingNodeKind::Disk)
        },
        requester: scheduler_node(requester, SchedulingNodeKind::Vm),
        operation,
        request_icount: Icount {
            retired: request_icount,
        },
        count,
        payload: payload.to_vec(),
    }
}

fn latency_params() -> BlockLatencyParameters {
    BlockLatencyParameters::new(
        SimDuration { nanos: 10 },
        SimDuration { nanos: 20 },
        SimDuration { nanos: 30 },
        SimDuration { nanos: 40 },
        SimDuration { nanos: 1 },
    )
}

fn zero_latency() -> BlockLatencyParameters {
    BlockLatencyParameters::default()
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
