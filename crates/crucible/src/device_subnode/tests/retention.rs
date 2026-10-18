//! Retirement of delivered completions from the bridge and its device.
//!
//! Delivery retires each completion from the bridge's modeled and pending sets
//! and from the device's in-flight queue. These tests show that the retained
//! state stays bounded by in-flight requests, that checkpoint/restore at any
//! step continues exactly like an uninterrupted run, and that a completion
//! ordered before an already-delivered one is still delivered.

use super::*;

/// One step of a deterministic sub-node script.
#[derive(Clone, Copy)]
enum Step {
    /// Submits a read with this request id at this request icount.
    Submit {
        request_icount: u64,
        request_id: u32,
    },
    /// Delivers every completion due at or before this consumer icount.
    Deliver { consumer_icount: u64 },
}

fn script() -> Vec<Step> {
    vec![
        Step::Submit {
            request_icount: 0,
            request_id: 1,
        },
        Step::Submit {
            request_icount: 100,
            request_id: 2,
        },
        Step::Deliver {
            consumer_icount: u64::MAX / 4,
        },
        Step::Submit {
            request_icount: 200,
            request_id: 3,
        },
        Step::Submit {
            request_icount: 50,
            request_id: 4,
        },
        Step::Deliver {
            consumer_icount: u64::MAX / 2,
        },
        Step::Submit {
            request_icount: 300,
            request_id: 5,
        },
        Step::Deliver {
            consumer_icount: u64::MAX,
        },
    ]
}

/// Applies one step and returns the deliveries it produced.
fn apply(sub_node: &mut DeviceSchedulingSubNode, step: Step) -> Vec<DeviceDelivery> {
    match step {
        Step::Submit {
            request_icount,
            request_id,
        } => {
            sub_node
                .submit_fifo(request_icount, &read_request(request_id, 0, 8))
                .unwrap_or_else(|error| panic!("scripted submit should succeed: {error}"));
            Vec::new()
        }
        Step::Deliver { consumer_icount } => deliver(sub_node, consumer_icount),
    }
}

fn checkpoint_bytes(sub_node: &DeviceSchedulingSubNode) -> Vec<u8> {
    sub_node
        .checkpoint()
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("sub-node checkpoint should encode: {error}"))
}

fn restored_from(sub_node: &DeviceSchedulingSubNode, seed: Seed) -> DeviceSchedulingSubNode {
    let decoded =
        DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(&checkpoint_bytes(sub_node))
            .unwrap_or_else(|error| panic!("sub-node checkpoint should decode: {error}"));
    let mut restored = fresh_disk(seed);
    restored
        .restore_checkpoint(&decoded)
        .unwrap_or_else(|error| panic!("sub-node checkpoint should restore: {error}"));
    restored
}

fn device_inflight_len(sub_node: &DeviceSchedulingSubNode) -> usize {
    sub_node
        .block_device()
        .unwrap_or_else(|| panic!("disk sub-node holds a block device"))
        .core()
        .inflight_len()
}

#[test]
fn delivery_retires_completions_from_bridge_and_device() {
    let mut disk = fresh_disk(Seed::from_u64(0xd15c));
    disk.submit_fifo(0, &read_request(1, 0, 8))
        .unwrap_or_else(|error| panic!("first submit: {error}"));
    disk.submit_fifo(1_000_000, &read_request(2, 0, 8))
        .unwrap_or_else(|error| panic!("second submit: {error}"));
    let first = disk
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("first completion in flight"));

    let delivered = deliver(&mut disk, first);
    assert_eq!(delivered.len(), 1);
    assert_eq!(disk.modeled.len(), 1);
    assert_eq!(disk.resolved.len(), 1);
    assert_eq!(device_inflight_len(&disk), 1);

    // A delivered completion is never offered again.
    assert!(deliver(&mut disk, first).is_empty());
    assert!(deliver(&mut disk, u64::MAX).len() == 1);
    assert!(disk.modeled.is_empty());
    assert!(disk.resolved.is_empty());
    assert_eq!(device_inflight_len(&disk), 0);
    assert_eq!(disk.next_exact_local_event(), None);
}

#[test]
fn retained_completions_stay_bounded_across_a_long_run() {
    let mut disk = fresh_disk(Seed::from_u64(0xd15c));
    disk.submit_fifo(0, &read_request(0, 0, 8))
        .unwrap_or_else(|error| panic!("opening submit: {error}"));
    assert_eq!(deliver(&mut disk, u64::MAX).len(), 1);
    let settled = checkpoint_bytes(&disk).len();

    for request_id in 1..256_u32 {
        disk.submit_fifo(
            u64::from(request_id) * 1_000,
            &read_request(request_id, 0, 8),
        )
        .unwrap_or_else(|error| panic!("submit {request_id}: {error}"));
        assert_eq!(deliver(&mut disk, u64::MAX).len(), 1);
        assert!(disk.modeled.is_empty() && disk.resolved.is_empty());
        assert_eq!(device_inflight_len(&disk), 0);
    }

    // Only fixed-width counters grow; no per-completion record is retained.
    let after = checkpoint_bytes(&disk).len();
    assert!(
        after <= settled + 16,
        "{after} bytes after the run, {settled} before"
    );
}

#[test]
fn restore_at_every_step_continues_like_the_uninterrupted_run() {
    let seed = Seed::from_u64(0xd15c);
    let steps = script();

    let mut uninterrupted = fresh_disk(seed);
    let mut expected_deliveries = Vec::new();
    let mut expected_checkpoints = Vec::new();
    for step in &steps {
        expected_deliveries.push(apply(&mut uninterrupted, *step));
        expected_checkpoints.push(checkpoint_bytes(&uninterrupted));
    }
    assert_eq!(
        expected_deliveries.iter().map(Vec::len).sum::<usize>(),
        5,
        "every submitted completion is delivered exactly once"
    );

    for restore_after in 0..steps.len() {
        let mut prefix = fresh_disk(seed);
        for step in &steps[..=restore_after] {
            apply(&mut prefix, *step);
        }
        let mut resumed = restored_from(&prefix, seed);
        assert_eq!(
            checkpoint_bytes(&resumed),
            expected_checkpoints[restore_after]
        );

        for (index, step) in steps.iter().enumerate().skip(restore_after + 1) {
            assert_eq!(
                apply(&mut resumed, *step),
                expected_deliveries[index],
                "deliveries after restoring at step {restore_after} differ at step {index}"
            );
            assert_eq!(checkpoint_bytes(&resumed), expected_checkpoints[index]);
        }
    }
}

#[test]
fn completion_ordered_before_a_delivered_one_is_still_delivered() {
    let mut disk = fresh_disk(Seed::from_u64(0xd15c));
    disk.submit_fifo(1_000_000, &read_request(1, 0, 8))
        .unwrap_or_else(|error| panic!("late request: {error}"));
    let late = disk
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("late completion in flight"));
    assert_eq!(deliver(&mut disk, late).len(), 1);

    // An earlier request now completes before the delivered one. Retirement
    // keeps no delivery watermark, so it is offered rather than dropped.
    disk.submit_fifo(0, &read_request(2, 0, 8))
        .unwrap_or_else(|error| panic!("earlier request: {error}"));
    let early = disk
        .next_exact_local_event()
        .unwrap_or_else(|| panic!("earlier completion in flight"));
    assert!(early < late);
    let delivered = deliver(&mut disk, late);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].delivery_icount, early);
}

#[test]
fn ninep_delivery_retires_the_device_reply() {
    let mut fs = fresh_ninep(Seed::from_u64(0x9f5));
    fs.submit_ninep_frame(19, &tversion(3, 4096, codec::PROTOCOL_VERSION))
        .unwrap_or_else(|error| panic!("9p submit should succeed: {error}"));
    assert_eq!(deliver(&mut fs, u64::MAX).len(), 1);

    let device = fs
        .ninep_device()
        .unwrap_or_else(|| panic!("9p sub-node holds a 9p device"));
    assert_eq!(device.core().inflight_len(), 0);
    assert!(fs.modeled.is_empty() && fs.resolved.is_empty());
}
