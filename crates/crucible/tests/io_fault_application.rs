//! Checks T-FAULT-9 block/9p fault application on I/O sub-nodes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    BlockFault, CombinedFaults, Decision, DeviceId, DeviceSchedulingSubNode, EffectOutcomeDecision,
    Fault, FaultBandwidthBitsPerSecond, FaultDuration, FaultRateBasisPoints, IoFailureMode,
    NinePErrno, NinePFault, SchedulerNodeId, SchedulerState, SchedulingNodeKind, Seed, VirtualTime,
    apply_combined_block_faults_to_subnode, apply_combined_block_faults_to_subnode_and_state,
    apply_combined_ninep_faults_to_subnode, apply_combined_ninep_faults_to_subnode_and_state,
    block_faults_from_combined_block, io_fault_id, ninep_faults_from_combined_ninep,
};
use crucible_device::ninep::codec;
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockResponse, BlockStatus, FsTree, IoCore,
    NinepDevice, NinepLatency, Node,
};

#[test]
fn combined_block_faults_apply_to_subnode_resolve_path() {
    let disk = device("disk0");
    let combined = CombinedFaults::from_faults(&[
        Fault::Block(BlockFault::Latency {
            device: disk.clone(),
            extra: duration(100),
            jitter: duration(0),
        }),
        Fault::Block(BlockFault::Reorder {
            device: disk.clone(),
            window: duration(37),
        }),
        Fault::Block(BlockFault::Duplicate {
            device: disk.clone(),
            rate: rate(10_000),
            gap: duration(11),
        }),
        Fault::Block(BlockFault::Corruption {
            device: disk.clone(),
            rate: rate(10_000),
            bit_flips: 1,
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: disk.clone(),
            limit: bandwidth(8_000_000),
        }),
    ]);
    let faults = combined
        .block
        .get(&disk)
        .unwrap_or_else(|| panic!("combined block faults should include disk"));
    let lowered = block_faults_from_combined_block(faults);
    assert_eq!(lowered.added_latency_ns, 100);
    assert_eq!(lowered.reorder_window_ns, 37);
    assert!(lowered.duplicate.fires(0));
    assert!(lowered.corrupt.fires(0));
    assert_eq!(lowered.bandwidth_bits_per_sec, vec![8_000_000]);

    let mut sub_node = fresh_disk(Seed::from_u64(0xb10c), &disk);
    let installed = apply_combined_block_faults_to_subnode(&mut sub_node, faults);
    assert_eq!(&installed, sub_node.io_faults());

    sub_node
        .submit(0, &BlockRequest::read(42, 0, 4))
        .unwrap_or_else(|error| panic!("block submit should succeed: {error}"));
    let first_delivery = sub_node
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("block completion should be in flight"));
    let delivered = sub_node.deliver_due(u64::MAX);

    assert_eq!(delivered.len(), 2, "duplicate emits a second completion");
    let primary = delivered[0]
        .completion
        .as_ref()
        .unwrap_or_else(|| panic!("primary block completion should be visible"));
    let duplicate = delivered[1]
        .completion
        .as_ref()
        .unwrap_or_else(|| panic!("duplicate block completion should be visible"));
    let expected_unfaulted = BlockResponse::ok(42, vec![0xab; 4])
        .encode()
        .unwrap_or_else(|error| panic!("expected response should encode: {error}"));

    assert_eq!(primary.delivery_icount.retired, first_delivery);
    assert!(
        (17_104..=17_141).contains(&first_delivery),
        "latency + bandwidth shift plus reorder window should bound delivery"
    );
    assert_eq!(duplicate.delivery_icount.retired, first_delivery + 11);
    assert_ne!(
        primary.payload, expected_unfaulted,
        "corruption should mutate the block response bytes"
    );
    assert_eq!(
        duplicate.payload, primary.payload,
        "duplicate repeats the resolved payload"
    );
    assert_fault_fired(&delivered[0].decisions, &disk, "duplicate", true);
    assert_fault_fired(&delivered[0].decisions, &disk, "corrupt", true);
}

#[test]
fn block_failures_encode_error_status_or_drop_without_completion() {
    let disk = device("disk-failure");
    let error_combined = CombinedFaults::from_faults(&[Fault::Block(BlockFault::Failure {
        device: disk.clone(),
        rate: rate(10_000),
        mode: IoFailureMode::ErrorStatus,
    })]);
    let error_faults = error_combined
        .block
        .get(&disk)
        .unwrap_or_else(|| panic!("error block faults should include disk"));
    let mut error_node = fresh_disk(Seed::from_u64(0xe110), &disk);
    let _ = apply_combined_block_faults_to_subnode(&mut error_node, error_faults);
    error_node
        .submit(0, &BlockRequest::read(7, 0, 4))
        .unwrap_or_else(|error| panic!("block submit should succeed: {error}"));
    let error_delivery = error_node
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("error completion should be in flight"));
    let delivered = error_node.deliver_due(error_delivery);
    let completion = delivered[0]
        .completion
        .as_ref()
        .unwrap_or_else(|| panic!("error-status failure should still complete"));
    let response = BlockResponse::decode(&completion.payload)
        .unwrap_or_else(|error| panic!("block error response should decode: {error}"));
    assert_eq!(response.status, BlockStatus::Error);
    assert_eq!(response.request_id, 7);
    assert_fault_fired(&delivered[0].decisions, &disk, "loss", true);

    let drop_combined = CombinedFaults::from_faults(&[Fault::Block(BlockFault::Failure {
        device: disk.clone(),
        rate: rate(10_000),
        mode: IoFailureMode::Drop,
    })]);
    let drop_faults = drop_combined
        .block
        .get(&disk)
        .unwrap_or_else(|| panic!("drop block faults should include disk"));
    let mut drop_node = fresh_disk(Seed::from_u64(0xd00d), &disk);
    let _ = apply_combined_block_faults_to_subnode(&mut drop_node, drop_faults);
    drop_node
        .submit(0, &BlockRequest::read(8, 0, 4))
        .unwrap_or_else(|error| panic!("block submit should succeed: {error}"));
    let drop_delivery = drop_node
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("drop decision should be in flight"));
    let dropped = drop_node.deliver_due(drop_delivery);
    assert_eq!(dropped.len(), 1);
    assert!(
        dropped[0].completion.is_none(),
        "drop mode records decisions without emitting a completion"
    );
    assert_fault_fired(&dropped[0].decisions, &disk, "loss", true);
    assert!(drop_node.next_exact_local_event().is_none());
}

#[test]
fn live_fault_activation_does_not_rewrite_already_resolved_block_work() {
    let disk = device("disk-freeze");
    let mut sub_node = fresh_disk(Seed::from_u64(0xf3e3), &disk);
    sub_node
        .submit(0, &BlockRequest::read(1, 0, 4))
        .unwrap_or_else(|error| panic!("first block submit should succeed: {error}"));
    sub_node
        .submit(100, &BlockRequest::read(2, 0, 4))
        .unwrap_or_else(|error| panic!("second block submit should succeed: {error}"));

    let first_delivery = sub_node
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("first completion should be in flight"));
    let first = sub_node.deliver_due(first_delivery);
    assert_eq!(first.len(), 1);
    assert_eq!(block_response_id(&first[0]), 1);

    let combined = CombinedFaults::from_faults(&[Fault::Block(BlockFault::Duplicate {
        device: disk.clone(),
        rate: rate(10_000),
        gap: duration(11),
    })]);
    let faults = combined
        .block
        .get(&disk)
        .unwrap_or_else(|| panic!("duplicate block faults should include disk"));
    let _ = apply_combined_block_faults_to_subnode(&mut sub_node, faults);

    let old_second = sub_node.deliver_due(u64::MAX);
    assert_eq!(
        old_second.len(),
        1,
        "fault activation after a visible delivery must not duplicate old work"
    );
    assert_eq!(block_response_id(&old_second[0]), 2);

    sub_node
        .submit(2_000, &BlockRequest::read(3, 0, 4))
        .unwrap_or_else(|error| panic!("third block submit should succeed: {error}"));
    let new_after_activation = sub_node.deliver_due(u64::MAX);
    assert_eq!(
        new_after_activation.len(),
        2,
        "new work after activation should use the duplicate fault table"
    );
    assert_eq!(block_response_id(&new_after_activation[0]), 3);
    assert_eq!(block_response_id(&new_after_activation[1]), 3);
}

#[test]
fn combined_9p_faults_apply_to_subnode_resolve_path() {
    let fs = device("fs0");
    let combined = CombinedFaults::from_faults(&[
        Fault::NineP(NinePFault::Latency {
            device: fs.clone(),
            extra: duration(50),
            jitter: duration(0),
        }),
        Fault::NineP(NinePFault::Reorder {
            device: fs.clone(),
            window: duration(23),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: fs.clone(),
            rate: rate(10_000),
            gap: duration(13),
        }),
        Fault::NineP(NinePFault::Corruption {
            device: fs.clone(),
            rate: rate(10_000),
            bit_flips: 1,
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: fs.clone(),
            limit: bandwidth(8_000_000),
        }),
    ]);
    let faults = combined
        .ninep
        .get(&fs)
        .unwrap_or_else(|| panic!("combined 9p faults should include fs"));
    let lowered = ninep_faults_from_combined_ninep(faults);
    assert_eq!(lowered.added_latency_ns, 50);
    assert_eq!(lowered.reorder_window_ns, 23);
    assert!(lowered.duplicate.fires(0));
    assert!(lowered.corrupt.fires(0));
    assert_eq!(lowered.bandwidth_bits_per_sec, vec![8_000_000]);

    let mut sub_node = fresh_ninep(Seed::from_u64(0x9f5), &fs);
    let installed = apply_combined_ninep_faults_to_subnode(&mut sub_node, faults);
    assert_eq!(&installed, sub_node.io_faults());

    sub_node
        .submit_ninep_frame(0, &tversion(7, 4096, codec::PROTOCOL_VERSION))
        .unwrap_or_else(|error| panic!("9p submit should succeed: {error}"));
    let first_delivery = sub_node
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("9p completion should be in flight"));
    let delivered = sub_node.deliver_due(u64::MAX);

    assert_eq!(delivered.len(), 2, "duplicate emits a second 9p reply");
    let primary = delivered[0]
        .completion
        .as_ref()
        .unwrap_or_else(|| panic!("primary 9p completion should be visible"));
    let duplicate = delivered[1]
        .completion
        .as_ref()
        .unwrap_or_else(|| panic!("duplicate 9p completion should be visible"));
    let expected_unfaulted = codec::encode_rversion(7, 4096, codec::PROTOCOL_VERSION)
        .unwrap_or_else(|error| panic!("expected rversion should encode: {error}"));

    assert_eq!(primary.delivery_icount.retired, first_delivery);
    assert!(
        (21_871..=21_894).contains(&first_delivery),
        "latency + bandwidth shift plus reorder window should bound delivery"
    );
    assert_eq!(duplicate.delivery_icount.retired, first_delivery + 13);
    assert_ne!(
        primary.payload, expected_unfaulted,
        "corruption should mutate the 9p response bytes"
    );
    assert_eq!(
        duplicate.payload, primary.payload,
        "duplicate repeats the resolved 9p payload"
    );
    assert_fault_fired(&delivered[0].decisions, &fs, "duplicate", true);
    assert_fault_fired(&delivered[0].decisions, &fs, "corrupt", true);
}

#[test]
fn ninep_failure_encodes_rlerror_with_selected_errno() {
    let fs = device("fs-failure");
    let combined = CombinedFaults::from_faults(&[Fault::NineP(NinePFault::Failure {
        device: fs.clone(),
        rate: rate(10_000),
        errno: errno(13),
    })]);
    let faults = combined
        .ninep
        .get(&fs)
        .unwrap_or_else(|| panic!("9p failure faults should include fs"));
    let lowered = ninep_faults_from_combined_ninep(faults);
    assert!(lowered.loss.fires(0));
    assert_eq!(lowered.failure_errno, Some(13));

    let mut sub_node = fresh_ninep(Seed::from_u64(0xe10), &fs);
    let _ = apply_combined_ninep_faults_to_subnode(&mut sub_node, faults);
    sub_node
        .submit_ninep_frame(0, &tversion(9, 4096, codec::PROTOCOL_VERSION))
        .unwrap_or_else(|error| panic!("9p submit should succeed: {error}"));
    let delivery = sub_node
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("9p error completion should be in flight"));
    let delivered = sub_node.deliver_due(delivery);
    let completion = delivered[0]
        .completion
        .as_ref()
        .unwrap_or_else(|| panic!("9p failure should still complete"));

    assert_eq!(reply_type(&completion.payload), codec::RLERROR);
    assert_eq!(reply_tag(&completion.payload), 9);
    assert_eq!(rlerror_code(&completion.payload), 13);
    assert_fault_fired(&delivered[0].decisions, &fs, "loss", true);
}

#[test]
fn active_block_and_9p_faults_enter_materialized_scheduler_state() {
    let disk = device("materialized-disk");
    let block_combined = CombinedFaults::from_faults(&[
        Fault::Block(BlockFault::Latency {
            device: disk.clone(),
            extra: duration(1),
            jitter: duration(1),
        }),
        Fault::Block(BlockFault::Reorder {
            device: disk.clone(),
            window: duration(1),
        }),
        Fault::Block(BlockFault::Failure {
            device: disk.clone(),
            rate: rate(1),
            mode: IoFailureMode::ErrorStatus,
        }),
        Fault::Block(BlockFault::Duplicate {
            device: disk.clone(),
            rate: rate(1),
            gap: duration(1),
        }),
        Fault::Block(BlockFault::Corruption {
            device: disk.clone(),
            rate: rate(1),
            bit_flips: 1,
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: disk.clone(),
            limit: bandwidth(1_000),
        }),
    ]);
    let block_faults = block_combined
        .block
        .get(&disk)
        .unwrap_or_else(|| panic!("materialized block faults should include disk"));
    let mut block_node = fresh_disk(Seed::from_u64(0xb10c), &disk);
    let (_table, scheduler) = apply_combined_block_faults_to_subnode_and_state(
        SchedulerState::empty(),
        &mut block_node,
        block_faults,
        VirtualTime { ticks: 99 },
    );
    assert_active_kinds(&scheduler, &disk);

    let fs = device("materialized-fs");
    let ninep_combined = CombinedFaults::from_faults(&[
        Fault::NineP(NinePFault::Latency {
            device: fs.clone(),
            extra: duration(1),
            jitter: duration(1),
        }),
        Fault::NineP(NinePFault::Reorder {
            device: fs.clone(),
            window: duration(1),
        }),
        Fault::NineP(NinePFault::Failure {
            device: fs.clone(),
            rate: rate(1),
            errno: errno(5),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: fs.clone(),
            rate: rate(1),
            gap: duration(1),
        }),
        Fault::NineP(NinePFault::Corruption {
            device: fs.clone(),
            rate: rate(1),
            bit_flips: 1,
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: fs.clone(),
            limit: bandwidth(1_000),
        }),
    ]);
    let ninep_faults = ninep_combined
        .ninep
        .get(&fs)
        .unwrap_or_else(|| panic!("materialized 9p faults should include fs"));
    let mut ninep_node = fresh_ninep(Seed::from_u64(0x9f5), &fs);
    let (_table, scheduler) = apply_combined_ninep_faults_to_subnode_and_state(
        SchedulerState::empty(),
        &mut ninep_node,
        ninep_faults,
        VirtualTime { ticks: 99 },
    );
    assert_active_kinds(&scheduler, &fs);
}

fn assert_active_kinds(scheduler: &SchedulerState, device: &DeviceId) {
    for kind in [
        "latency",
        "jitter",
        "reorder",
        "bandwidth",
        "loss",
        "duplicate",
        "corrupt",
    ] {
        assert!(
            scheduler
                .active_faults
                .contains_key(&io_fault_id(device, kind)),
            "active {kind} fault must enter scheduler state"
        );
    }
}

fn fresh_disk(seed: Seed, device_id: &DeviceId) -> DeviceSchedulingSubNode {
    let core = IoCore::new(0, 7, 16, 16)
        .unwrap_or_else(|error| panic!("block io core should construct: {error}"));
    let base = BaseImage::new(vec![0xab; 4096]);
    let device = BlockDevice::new(core, base, BlockLatency::default());
    DeviceSchedulingSubNode::new(
        sub_node_id("disk-sub", SchedulingNodeKind::Disk),
        node("vm-a"),
        device_id.clone(),
        device,
        seed,
    )
}

fn fresh_ninep(seed: Seed, device_id: &DeviceId) -> DeviceSchedulingSubNode {
    let core = IoCore::new(0, 9, 16, 16)
        .unwrap_or_else(|error| panic!("9p io core should construct: {error}"));
    let mut root = BTreeMap::new();
    root.insert(
        "alpha".to_owned(),
        Node::File {
            content: b"alpha".to_vec(),
        },
    );
    let tree = FsTree::try_new(Node::Directory { children: root })
        .expect("test 9p tree components are valid");
    let device = NinepDevice::new(core, tree, NinepLatency::default());
    DeviceSchedulingSubNode::new_ninep(
        sub_node_id("ninep-sub", SchedulingNodeKind::NineP),
        node("vm-a"),
        device_id.clone(),
        device,
        seed,
    )
}

fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
    let mut body = msize.to_le_bytes().to_vec();
    body.extend_from_slice(&string_bytes(version));
    frame(codec::TVERSION, tag, &body)
}

fn frame(msg_type: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let size = (codec::HEADER_LEN + body.len()) as u32;
    let mut frame = Vec::new();
    frame.extend_from_slice(&size.to_le_bytes());
    frame.push(msg_type);
    frame.extend_from_slice(&tag.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

fn string_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

fn assert_fault_fired(decisions: &[Decision], device: &DeviceId, kind: &str, fired: bool) {
    assert!(
        decisions.iter().any(|decision| matches!(
            decision,
            Decision::EffectOutcome(EffectOutcomeDecision { fault, fired: actual, .. })
                if fault == &io_fault_id(device, kind) && *actual == fired
        )),
        "expected {kind} fired={fired} decision"
    );
}

fn block_response_id(delivery: &crucible::DeviceDelivery) -> u32 {
    let completion = delivery
        .completion
        .as_ref()
        .unwrap_or_else(|| panic!("block delivery should emit a completion"));
    BlockResponse::decode(&completion.payload)
        .unwrap_or_else(|error| panic!("block response should decode: {error}"))
        .request_id
}

fn reply_type(frame: &[u8]) -> u8 {
    frame[4]
}

fn reply_tag(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[5], frame[6]])
}

fn rlerror_code(frame: &[u8]) -> u32 {
    u32::from_le_bytes([frame[7], frame[8], frame[9], frame[10]])
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("test rate should be valid: {error}"))
}

fn duration(nanos: u64) -> FaultDuration {
    FaultDuration::from_nanos(nanos)
}

fn bandwidth(bits_per_second: u64) -> FaultBandwidthBitsPerSecond {
    FaultBandwidthBitsPerSecond::new(bits_per_second)
        .unwrap_or_else(|error| panic!("test bandwidth should be valid: {error}"))
}

fn errno(code: i32) -> NinePErrno {
    NinePErrno::from_code(code)
        .unwrap_or_else(|error| panic!("test errno should be valid: {error}"))
}

fn device(name: &str) -> DeviceId {
    DeviceId {
        name: name.to_owned(),
    }
}

fn node(name: &str) -> crucible::NodeId {
    crucible::NodeId {
        name: name.to_owned(),
    }
}

fn sub_node_id(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind,
    }
}
