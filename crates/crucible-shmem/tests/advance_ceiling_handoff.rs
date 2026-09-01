//! Checks the per-node advance-ceiling handoff.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use crucible_shmem::{
    FrameEntry, FutexWait, FutexWakeResult, KIND_VM, NODE_SLOT_ALIGN,
    NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET, NODE_SLOT_CURRENT_ICOUNT_OFFSET,
    NODE_SLOT_CURRENT_NS_OFFSET, NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
    NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, NODE_SLOT_KIND_OFFSET, NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
    NODE_SLOT_PUBLISH_GEN_OFFSET, NODE_SLOT_SIZE, NODE_SLOT_STATUS_OFFSET,
    NODE_SLOT_WAKE_SIGNAL_OFFSET, NodeSlot, NodeSlotError, PendingInputPublication,
    RegionAllocation, RegionAllocationAccessError, RegionConfig, RingHeader, SLOT_BLK_IO,
    SLOT_NET_ROUTER, STATUS_IDLE, STATUS_RUNNING, SchedulerWakePublicationError, SpscRingError,
    WakeAction, authorize_advance_ceiling, icount_to_virtual_ns,
};

const SHMEM_SOURCE: &str = concat!(
    include_str!("../src/lib.rs"),
    include_str!("../src/shmem/region.rs"),
    include_str!("../src/shmem/region/allocation_scheduler.rs"),
    include_str!("../src/shmem/ring_coverage.rs"),
    include_str!("../src/shmem/frame_node.rs"),
    include_str!("../src/shmem/frame_node/runtime.rs"),
    include_str!("../src/shmem/delivery_errors.rs"),
);

#[cfg(target_os = "linux")]
use std::{
    fs,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

#[test]
fn node_slot_layout_matches_wire_contract() {
    assert_eq!(NODE_SLOT_SIZE, 128);
    assert_eq!(NODE_SLOT_ALIGN, 128);
    assert_eq!(NODE_SLOT_CURRENT_ICOUNT_OFFSET, 0);
    assert_eq!(NODE_SLOT_CURRENT_NS_OFFSET, 8);
    assert_eq!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, 16);
    assert_eq!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, 24);
    assert_eq!(NODE_SLOT_WAKE_SIGNAL_OFFSET, 32);
    assert_eq!(NODE_SLOT_STATUS_OFFSET, 36);
    assert_eq!(NODE_SLOT_KIND_OFFSET, 37);
    assert_eq!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET, 38);
    assert_eq!(NODE_SLOT_PUBLISH_GEN_OFFSET, 40);
    assert_eq!(NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET, 44);
}

#[test]
fn scheduler_publishes_ceiling_and_node_publishes_reached_icount() {
    let slot = NodeSlot::new(KIND_VM);
    assert_eq!(slot.snapshot().max_advance_icount, 0);

    let ceiling = ceiling(0, 12);
    assert_eq!(
        slot.publish_scheduler_ceiling(ceiling),
        Ok(wake_action(0, 1, 0))
    );
    assert_eq!(slot.load_node_ceiling(), 12);

    slot.mark_running();
    assert_eq!(slot.publish_reached_icount(12, 3), Ok(()));

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 12);
    assert_eq!(snapshot.current_ns, 96);
    assert_eq!(snapshot.max_advance_icount, 12);
    assert_eq!(snapshot.status, STATUS_RUNNING);
    assert_eq!(snapshot.kind, KIND_VM);
    assert_eq!(snapshot.publish_gen % 2, 0);
}

#[test]
fn scheduler_wake_enqueues_pending_inputs_before_ceiling_and_futex_wake() {
    let mut region = region(1, 2);
    let dst_slot = 0;
    let src_slot = SLOT_NET_ROUTER as u32;
    let input = frame(12, src_slot, 1, b"net");
    let pending = [PendingInputPublication::new(src_slot, input.clone())];

    let publication = region
        .publish_scheduler_inputs_and_ceiling(dst_slot, &pending, ceiling(0, 12))
        .expect("scheduler wake publication should succeed");

    assert_eq!(publication.dst_slot, dst_slot);
    assert_eq!(publication.pending_input_count, 1);
    assert_eq!(publication.max_advance_icount, 12);
    assert_eq!(publication.wake, wake_action(0, 1, 0));
    assert_eq!(
        region.peek_directed_frame(src_slot, dst_slot),
        Ok(Some(input.clone()))
    );
    let snapshot = region
        .node_slot(dst_slot)
        .expect("VM slot should exist")
        .snapshot();
    assert_eq!(snapshot.max_advance_icount, 12);
    assert_eq!(snapshot.wake_signal, 1);
    assert_eq!(
        region.dequeue_directed_frame(src_slot, dst_slot),
        Ok(Some(input))
    );
}

#[test]
fn scheduler_wake_batches_pending_inputs_before_single_wake() {
    let mut region = region(1, 2);
    let dst_slot = 0;
    let net_slot = SLOT_NET_ROUTER as u32;
    let blk_slot = SLOT_BLK_IO as u32;
    let net_input = frame(14, net_slot, 1, b"net");
    let blk_input = frame(15, blk_slot, 2, b"blk");
    let pending = [
        PendingInputPublication::new(net_slot, net_input.clone()),
        PendingInputPublication::new(blk_slot, blk_input.clone()),
    ];

    let publication = region
        .publish_scheduler_inputs_and_ceiling(dst_slot, &pending, ceiling(0, 15))
        .expect("batched scheduler wake publication should succeed");

    assert_eq!(publication.pending_input_count, 2);
    assert_eq!(publication.wake, wake_action(0, 1, 0));
    assert_eq!(
        region.peek_directed_frame(net_slot, dst_slot),
        Ok(Some(net_input))
    );
    assert_eq!(
        region.peek_directed_frame(blk_slot, dst_slot),
        Ok(Some(blk_input))
    );
    assert_eq!(
        region
            .node_slot(dst_slot)
            .expect("VM slot should exist")
            .snapshot()
            .wake_signal,
        1
    );
}

#[test]
fn scheduler_wake_node_slot_borrowed_inbox_handoff_orders_input_ceiling_and_wake() {
    let slot = NodeSlot::new(KIND_VM);
    let inbox = RingHeader::new();
    let mut entries = frame_entries(2);
    let dst_slot = 0;
    let src_slot = SLOT_NET_ROUTER as u32;
    let input = frame(12, src_slot, 1, b"net");

    let publication = slot
        .publish_scheduler_inbox_and_ceiling(
            dst_slot,
            src_slot,
            &inbox,
            &mut entries,
            std::slice::from_ref(&input),
            ceiling(0, 12),
        )
        .expect("borrowed inbox handoff should succeed");

    assert_eq!(publication.dst_slot, dst_slot);
    assert_eq!(publication.pending_input_count, 1);
    assert_eq!(publication.max_advance_icount, 12);
    assert_eq!(publication.wake, wake_action(0, 1, 0));
    assert_eq!(inbox.peek(&entries), Ok(Some(input)));
    let snapshot = slot.snapshot();
    assert_eq!(snapshot.max_advance_icount, 12);
    assert_eq!(snapshot.wake_signal, 1);
}

#[test]
fn scheduler_wake_rejects_full_inbox_before_ceiling_or_wake() {
    let mut region = region(1, 1);
    let dst_slot = 0;
    let src_slot = SLOT_NET_ROUTER as u32;
    let existing = frame(5, src_slot, 1, b"old");
    region
        .enqueue_directed_frame(src_slot, dst_slot, &existing)
        .expect("fixture enqueue should fill the inbox");
    let before = region
        .node_slot(dst_slot)
        .expect("VM slot should exist")
        .snapshot();
    let pending = [PendingInputPublication::new(
        src_slot,
        frame(6, src_slot, 2, b"new"),
    )];

    let error = region
        .publish_scheduler_inputs_and_ceiling(dst_slot, &pending, ceiling(0, 6))
        .expect_err("full inbox should reject before ceiling or wake");

    assert_eq!(
        error,
        SchedulerWakePublicationError::RegionAccess {
            source: RegionAllocationAccessError::SpscRing {
                source: SpscRingError::QueueFull { capacity: 1 },
            },
        }
    );
    assert_eq!(
        region.peek_directed_frame(src_slot, dst_slot),
        Ok(Some(existing))
    );
    let after = region
        .node_slot(dst_slot)
        .expect("VM slot should exist")
        .snapshot();
    assert_eq!(after.max_advance_icount, before.max_advance_icount);
    assert_eq!(after.wake_signal, before.wake_signal);
}

#[test]
fn scheduler_wake_rejects_source_mismatch_before_inbox_write_or_wake() {
    let mut region = region(1, 2);
    let dst_slot = 0;
    let src_slot = SLOT_NET_ROUTER as u32;
    let mismatched_frame = frame(6, SLOT_BLK_IO as u32, 2, b"wrong-source");
    let pending = [PendingInputPublication::new(src_slot, mismatched_frame)];

    let error = region
        .publish_scheduler_inputs_and_ceiling(dst_slot, &pending, ceiling(0, 6))
        .expect_err("source mismatch should reject before inbox write or wake");

    assert_eq!(
        error,
        SchedulerWakePublicationError::FrameSourceMismatch {
            input_index: 0,
            expected_src_slot: src_slot,
            frame_src_node: SLOT_BLK_IO as u32,
        }
    );
    assert_eq!(region.peek_directed_frame(src_slot, dst_slot), Ok(None));
    let snapshot = region
        .node_slot(dst_slot)
        .expect("VM slot should exist")
        .snapshot();
    assert_eq!(snapshot.max_advance_icount, 0);
    assert_eq!(snapshot.wake_signal, 0);
}

#[test]
fn scheduler_wake_rejects_stale_ceiling_before_inbox_write_or_wake() {
    let mut region = region(1, 2);
    let dst_slot = 0;
    let src_slot = SLOT_NET_ROUTER as u32;
    {
        let slot = region.node_slot(dst_slot).expect("VM slot should exist");
        slot.publish_scheduler_ceiling(ceiling(0, 10))
            .expect("initial ceiling should publish");
        slot.mark_running();
        slot.publish_reached_icount(5, 0)
            .expect("fixture current icount should publish");
    }
    let before = region
        .node_slot(dst_slot)
        .expect("VM slot should exist")
        .snapshot();
    let pending = [PendingInputPublication::new(
        src_slot,
        frame(6, src_slot, 1, b"late"),
    )];

    let error = region
        .publish_scheduler_inputs_and_ceiling(dst_slot, &pending, ceiling(0, 4))
        .expect_err("stale ceiling should reject before inbox write or wake");

    assert_eq!(
        error,
        SchedulerWakePublicationError::NodeSlot {
            source: NodeSlotError::CeilingBeforePublishedCurrent {
                current_icount: 5,
                max_advance_icount: 4,
            },
        }
    );
    assert_eq!(region.peek_directed_frame(src_slot, dst_slot), Ok(None));
    let after = region
        .node_slot(dst_slot)
        .expect("VM slot should exist")
        .snapshot();
    assert_eq!(after.max_advance_icount, before.max_advance_icount);
    assert_eq!(after.wake_signal, before.wake_signal);
}

#[test]
fn scheduler_wake_publication_source_orders_inbox_before_ceiling_before_wake() {
    let source = function_source("pub fn publish_scheduler_inputs_and_ceiling(");
    assert_source_order(
        source,
        &[
            "self.preflight_scheduler_wake_capacity(&enqueue_plans)?;",
            ".enqueue(&mut self.frame_entries[plan.entry_range], frame)",
            "let wake = self.slots[dst_index].publish_prevalidated_scheduler_ceiling(ceiling)?;",
        ],
        "combined scheduler publication must enqueue inbox frames before the ceiling wake",
    );
    let source = function_source("pub fn publish_scheduler_inbox_and_ceiling(");
    assert_source_order(
        source,
        &[
            "self.validate_scheduler_ceiling(ceiling)?;",
            "crate::region::helpers::preflight_ring_enqueue_capacity(",
            ".enqueue(inbox_entries, frame)",
            "let wake = self.publish_prevalidated_scheduler_ceiling(ceiling)?;",
        ],
        "borrowed scheduler publication must enqueue inbox frames before the ceiling wake",
    );
    let source = function_source("pub fn publish_scheduler_ceiling(");
    assert_source_order(
        source,
        &[
            "self.validate_scheduler_ceiling(ceiling)?;",
            "self.publish_prevalidated_scheduler_ceiling(ceiling)",
        ],
        "node-slot direct publication must validate before the prevalidated publish path",
    );
    let source = function_source("fn publish_prevalidated_scheduler_ceiling(");
    assert_source_order(
        source,
        &[
            ".store(ceiling.max_advance_icount, Ordering::Release);",
            "self.wake_after_signal_increment()",
        ],
        "prevalidated node-slot publication must store the ceiling before waking",
    );
    let source = function_source("fn wake_after_signal_increment(");
    assert_source_order(
        source,
        &[
            "let previous = self.wake_signal.fetch_add(1, Ordering::Release);",
            "let futex = self.futex_wake_nonprivate(1)?;",
        ],
        "wake must release-increment the futex word before issuing FUTEX_WAKE",
    );
}

#[test]
fn mark_running_participates_in_publish_generation() {
    let slot = NodeSlot::new(KIND_VM);
    let before = slot.snapshot().publish_gen;

    slot.mark_running();

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.status, STATUS_RUNNING);
    assert_eq!(snapshot.publish_gen, before + 2);
    assert_eq!(snapshot.publish_gen % 2, 0);
}

#[test]
fn control_boundary_request_release_acknowledges_publication() {
    let slot = NodeSlot::new(KIND_VM);
    slot.publish_idle(0, 10, 0)
        .unwrap_or_else(|error| panic!("future idle deadline should publish: {error}"));
    let before = slot.snapshot();

    let request = slot
        .request_control_boundary()
        .unwrap_or_else(|error| panic!("control boundary request should publish: {error}"));

    let requested = slot.snapshot();
    assert_eq!(before.control_boundary_ack, 1);
    assert_eq!(request, 2);
    assert_eq!(requested.control_boundary_ack, request);
    assert!(slot.control_boundary_is_requested());
    assert_eq!(requested.publish_gen, before.publish_gen);
    assert_eq!(requested.current_icount, before.current_icount);
    assert_eq!(requested.status, before.status);

    slot.publish_control_boundary(0, 0, 0)
        .unwrap_or_else(|error| panic!("control boundary should publish: {error}"));
    assert_eq!(slot.acknowledge_control_boundary(), 3);
    let published = slot.snapshot();
    assert_eq!(published.control_boundary_ack, request + 1);
    assert!(!slot.control_boundary_is_requested());
    assert_eq!(published.status, STATUS_IDLE);
    assert_eq!(published.idle_wake_icount, before.idle_wake_icount);

    slot.publish_scheduler_ceiling(ceiling(0, 1))
        .unwrap_or_else(|error| panic!("running ceiling should publish: {error}"));
    slot.mark_running();
    let running_before = slot.snapshot();
    let running_request = slot
        .request_control_boundary()
        .unwrap_or_else(|error| panic!("running control boundary should publish: {error}"));
    slot.publish_control_boundary(0, 0, 0)
        .unwrap_or_else(|error| panic!("running control boundary should publish: {error}"));
    assert_eq!(slot.acknowledge_control_boundary(), running_request + 1);
    assert_eq!(slot.snapshot().status, running_before.status);

    slot.publish_scheduler_ceiling(ceiling(0, 0))
        .unwrap_or_else(|error| panic!("fenced ceiling should publish: {error}"));
    slot.mark_running();
    let fenced_request = slot
        .request_control_boundary()
        .unwrap_or_else(|error| panic!("fenced control boundary should publish: {error}"));
    slot.publish_control_boundary(0, 0, 0)
        .unwrap_or_else(|error| panic!("fenced control boundary should publish: {error}"));
    assert_eq!(slot.acknowledge_control_boundary(), fenced_request + 1);
    let fenced = slot.snapshot();
    assert_eq!(fenced.status, STATUS_IDLE);
    assert_eq!(fenced.idle_wake_icount, fenced.current_icount);
}

#[test]
fn node_cannot_self_extend_past_published_ceiling() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = ceiling(0, 9);
    assert!(slot.publish_scheduler_ceiling(ceiling).is_ok());

    assert_eq!(slot.check_node_may_advance_to(9), Ok(()));
    assert_eq!(
        slot.check_node_may_advance_to(10),
        Err(NodeSlotError::NodeAdvancePastCeiling {
            next_icount: 10,
            max_advance_icount: 9,
        })
    );
    assert_eq!(
        slot.publish_reached_icount(10, 0),
        Err(NodeSlotError::NodeAdvancePastCeiling {
            next_icount: 10,
            max_advance_icount: 9,
        })
    );
}

#[test]
fn external_restore_ceiling_does_not_wake_or_rewind_the_slot() {
    let slot = NodeSlot::new(KIND_VM);
    assert!(slot.publish_scheduler_ceiling(ceiling(0, 10)).is_ok());
    assert!(slot.publish_reached_icount(10, 0).is_ok());
    let before = slot.snapshot();

    assert_eq!(slot.arm_external_state_restore_ceiling(37), Ok(()));
    let armed = slot.snapshot();
    assert_eq!(armed.current_icount, 10);
    assert_eq!(armed.max_advance_icount, 37);
    assert_eq!(armed.wake_signal, before.wake_signal);
    assert_eq!(armed.publish_gen, before.publish_gen);

    assert_eq!(
        slot.arm_external_state_restore_ceiling(9),
        Err(NodeSlotError::CeilingBeforePublishedCurrent {
            current_icount: 10,
            max_advance_icount: 9,
        })
    );
    assert_eq!(slot.snapshot(), armed);
}

#[test]
fn idle_publish_uses_race_free_futex_wait_and_wake_counter() {
    let slot = NodeSlot::new(KIND_VM);
    let first_ceiling = ceiling(0, 10);
    assert!(slot.publish_scheduler_ceiling(first_ceiling).is_ok());
    slot.mark_running();

    assert_eq!(slot.publish_reached_icount(10, 0), Ok(()));
    assert_eq!(
        slot.publish_idle(10, 20, 0),
        Ok(FutexWait::Wait { expected: 1 })
    );
    let idle = slot.snapshot();
    assert_eq!(idle.status, STATUS_IDLE);
    assert_eq!(idle.idle_wake_icount, 20);

    assert!(slot.futex_wait_still_valid(1));
    assert_eq!(
        slot.publish_scheduler_ceiling(ceiling(10, 20)),
        Ok(wake_action(1, 2, 0))
    );
    assert!(!slot.futex_wait_still_valid(1));
    assert_eq!(slot.prepare_futex_wait(), FutexWait::Runnable);
}

#[test]
fn scheduler_raise_during_idle_publish_race_bumps_wake_counter() {
    let slot = NodeSlot::new(KIND_VM);
    assert!(slot.publish_scheduler_ceiling(ceiling(0, 10)).is_ok());
    slot.mark_running();
    assert_eq!(slot.publish_reached_icount(10, 0), Ok(()));

    assert_eq!(
        slot.publish_scheduler_ceiling(ceiling(10, 20)),
        Ok(wake_action(1, 2, 0))
    );
    assert_eq!(slot.publish_idle(10, 20, 0), Ok(FutexWait::Runnable));
    assert_eq!(slot.snapshot().wake_signal, 2);
}

#[test]
fn node_reports_invalid_idle_and_time_conversion_loudly() {
    let slot = NodeSlot::new(KIND_VM);
    assert!(slot.publish_scheduler_ceiling(ceiling(0, 50)).is_ok());
    slot.mark_running();

    assert_eq!(
        slot.publish_idle(20, 19, 0),
        Err(NodeSlotError::IdleWakeBeforeCurrent {
            current_icount: 20,
            idle_wake_icount: 19,
        })
    );
    assert_eq!(
        icount_to_virtual_ns(1, 64),
        Err(NodeSlotError::InvalidShift { shift_bits: 64 })
    );
    assert_eq!(
        icount_to_virtual_ns(u64::MAX, 1),
        Err(NodeSlotError::VirtualTimeOverflow {
            icount: u64::MAX,
            shift_bits: 1,
        })
    );
}

#[test]
fn frame_delivery_wake_always_bumps_the_futex_word() {
    let slot = NodeSlot::new(KIND_VM);

    assert_eq!(slot.wake_for_frame_delivery(), Ok(wake_action(0, 1, 0)));
    assert_eq!(slot.snapshot().wake_signal, 1);
}

#[test]
#[cfg(target_os = "linux")]
fn linux_non_private_futex_syscalls_are_available() {
    let slot = NodeSlot::new(KIND_VM);

    let wake = match slot.futex_wake_nonprivate(1) {
        Ok(wake) => wake,
        Err(error) => panic!("non-private FUTEX_WAKE should be available: {error}"),
    };
    assert_eq!(wake.waiters_woken, 0);
    assert!(!wake.futex_private);
    const { assert!(!crucible_shmem::FUTEX_PRIVATE) };

    let wait = match slot.futex_wait_word_nonprivate(99) {
        Ok(wait) => wait,
        Err(error) => panic!("non-private FUTEX_WAIT should report value change: {error}"),
    };
    assert_eq!(wait, crucible_shmem::FutexWaitOutcome::ValueChanged);
}

#[test]
#[cfg(target_os = "linux")]
fn linux_scheduler_trigger_wakes_parked_waiter() {
    assert_linux_trigger_wakes_parked_waiter(|slot| slot.publish_scheduler_ceiling(ceiling(0, 1)));
}

#[test]
#[cfg(target_os = "linux")]
fn linux_frame_delivery_trigger_wakes_parked_waiter() {
    assert_linux_trigger_wakes_parked_waiter(NodeSlot::wake_for_frame_delivery);
}

#[test]
#[cfg(not(target_os = "linux"))]
fn off_linux_futex_syscalls_compile_to_noops() {
    let slot = NodeSlot::new(KIND_VM);

    let wake = match slot.futex_wake_nonprivate(1) {
        Ok(wake) => wake,
        Err(error) => panic!("off-Linux FUTEX_WAKE shim should be a no-op: {error}"),
    };
    assert_eq!(wake.waiters_woken, 0);
    assert!(!wake.futex_private);

    let wait = match slot.futex_wait_word_nonprivate(0) {
        Ok(wait) => wait,
        Err(error) => panic!("off-Linux FUTEX_WAIT shim should be a no-op: {error}"),
    };
    assert_eq!(wait, crucible_shmem::FutexWaitOutcome::Noop);
}

#[path = "advance_ceiling_handoff/support.rs"]
mod support;

use support::*;
