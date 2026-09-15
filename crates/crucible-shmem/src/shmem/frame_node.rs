//! Shared-memory frame entries and per-node slot state.

use super::*;

#[path = "frame_node/frame_entry.rs"]
mod frame_entry;
#[path = "frame_node/futex.rs"]
mod futex;
#[path = "frame_node/preemption_mailbox.rs"]
mod preemption_mailbox;

pub use frame_entry::{
    FRAME_DELIVERY_PENDING, FRAME_DELIVERY_RETAINED, FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT,
    FRAME_ENTRY_ALIGN, FRAME_ENTRY_DATA_OFFSET, FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET,
    FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET, FRAME_ENTRY_DELIVERY_STATE_OFFSET,
    FRAME_ENTRY_LAST_DELIVERY_ATTEMPT_ICOUNT_OFFSET, FRAME_ENTRY_LEN_OFFSET,
    FRAME_ENTRY_PAD_OFFSET, FRAME_ENTRY_SEQ_OFFSET, FRAME_ENTRY_SIZE, FRAME_ENTRY_SRC_NODE_OFFSET,
    FrameDeliveryAttemptError, FrameDeliveryState, FrameEntry, MAX_FRAME_DELIVERY_ATTEMPTS,
};
pub use futex::{
    FutexError, FutexWait, FutexWaitOutcome, FutexWakeResult, RegionControlError, WakeAction,
};
pub use preemption_mailbox::{
    PreemptionMailboxError, PublishedPreemptionCommand, SchedulerPreemptionCommand,
    SchedulerPreemptionKind,
};

#[path = "frame_node/layout.rs"]
mod layout;
#[path = "frame_node/runtime.rs"]
mod runtime;
#[path = "frame_node/snapshot.rs"]
mod snapshot;

pub use layout::*;
pub use snapshot::*;

#[cfg(test)]
mod control_boundary_tests {
    use super::*;

    #[test]
    fn repeated_request_and_acknowledgement_are_idempotent() {
        let slot = NodeSlot::new(KIND_VM);
        let request = slot
            .request_control_boundary(0, None)
            .unwrap_or_else(|error| panic!("first request should publish: {error}"));
        let repeated = slot
            .request_control_boundary(0, None)
            .unwrap_or_else(|error| panic!("repeated request should publish: {error}"));

        assert_eq!(request, 2);
        assert_eq!(repeated, request);
        assert_eq!(slot.acknowledge_control_boundary(), 3);
        assert_eq!(slot.acknowledge_control_boundary(), 3);
    }

    #[test]
    fn request_and_acknowledgement_wrap_through_zero() {
        let slot = NodeSlot::new(KIND_VM);
        slot.control_boundary_ack.store(u32::MAX, Ordering::Release);

        let request = slot
            .request_control_boundary(0, None)
            .unwrap_or_else(|error| panic!("wrapped request should publish: {error}"));

        assert_eq!(request, 0);
        assert_eq!(slot.acknowledge_control_boundary(), 1);
    }

    #[test]
    fn outstanding_control_request_rejects_a_changed_frontier_or_capture() {
        let slot = NodeSlot::new(KIND_VM);
        let request = slot
            .request_control_boundary(7, Some(3))
            .unwrap_or_else(|error| panic!("bound request should publish: {error}"));

        assert_eq!(request, 2);
        assert_eq!(slot.control_boundary_fault_command_frontier(), 7);
        assert_eq!(slot.control_boundary_capture_request(), Some(3));
        assert!(matches!(
            slot.request_control_boundary(8, Some(3)),
            Err(NodeSlotError::ControlBoundaryRequestChanged { .. })
        ));
        assert!(matches!(
            slot.request_control_boundary(7, Some(5)),
            Err(NodeSlotError::ControlBoundaryRequestChanged { .. })
        ));
        assert_eq!(slot.snapshot().control_boundary_ack, request);
    }
}

#[cfg(test)]
mod virtual_timer_witness_tests {
    use super::*;

    #[test]
    fn completed_virtual_timer_witness_round_trips_in_one_slot_snapshot() {
        let slot = NodeSlot::new(KIND_VM);
        assert_eq!(slot.snapshot().virtual_timer_witness, None);

        let witness = VirtualTimerFireWitness {
            generation: 7,
            deadline_ns: 500,
            deadline_icount: 63,
            armed_raw_icount: 41,
            fired_expire_ns: 500,
            fired_virtual_ns: 504,
            fired_raw_icount: 41,
            completed: 1,
            reserved: 0,
        };
        slot.publish_virtual_timer_witness(witness);

        let snapshot = slot.snapshot();
        assert_eq!(snapshot.virtual_timer_witness, Some(witness));
        assert!(snapshot.publish_gen.is_multiple_of(2));
    }
}
