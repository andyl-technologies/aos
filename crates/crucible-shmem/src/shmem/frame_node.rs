//! Shared-memory frame entries and per-node slot state.

use super::*;

#[path = "frame_node/frame_entry.rs"]
mod frame_entry;
#[path = "frame_node/futex.rs"]
mod futex;
#[path = "frame_node/preemption_mailbox.rs"]
mod preemption_mailbox;

pub use frame_entry::{
    FRAME_DELIVERY_PENDING, FRAME_DELIVERY_RETAINED, FRAME_ENTRY_ALIGN, FRAME_ENTRY_DATA_OFFSET,
    FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET, FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
    FRAME_ENTRY_DELIVERY_STATE_OFFSET, FRAME_ENTRY_LEN_OFFSET, FRAME_ENTRY_PAD_OFFSET,
    FRAME_ENTRY_SEQ_OFFSET, FRAME_ENTRY_SIZE, FRAME_ENTRY_SRC_NODE_OFFSET,
    FrameDeliveryAttemptError, FrameDeliveryState, FrameEntry,
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
            .request_control_boundary()
            .unwrap_or_else(|error| panic!("first request should publish: {error}"));
        let repeated = slot
            .request_control_boundary()
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
            .request_control_boundary()
            .unwrap_or_else(|error| panic!("wrapped request should publish: {error}"));

        assert_eq!(request, 0);
        assert_eq!(slot.acknowledge_control_boundary(), 1);
    }
}
