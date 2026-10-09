//! Shared-memory frame entries and per-node slot state.

use super::*;

/// Even sequence supplied only inside an original scheduler publication writer.
///
/// This local transaction receipt identifies ordering, not execution permission
/// or a native console phase. It is never stored as a Rust object in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerAdvanceSequence(u64);

impl SchedulerAdvanceSequence {
    /// Returns the exact even sequence released by this publication.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Even request proposed inside its original host publication transaction.
///
/// This local value is not yet visible to the node and confers no control or
/// phase authority. Native fields prepared with it must also match the actual
/// subsequently acquired request and its complete authenticated binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedControlBoundaryRequest(u32);

impl PreparedControlBoundaryRequest {
    /// Returns the exact even successor proposed by this original publisher.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

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

#[path = "frame_node/control_effect.rs"]
mod control_effect;
pub use control_effect::{
    NodeBoundaryPublication, NodeBoundaryPublicationError, SchedulerAdvancePublication,
};

#[path = "frame_node/control_publication.rs"]
mod control_publication;
pub use control_publication::HostControlBoundaryPublication;
#[cfg(feature = "test-support")]
pub use control_publication::ModeledControlBoundaryPublication;

#[path = "frame_node/layout.rs"]
mod layout;
#[path = "frame_node/restore_publication.rs"]
mod restore_publication;
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
            deadline_ps: 500,
            deadline_tick: 63,
            armed_raw_icount: 41,
            fired_expire_ps: 500,
            fired_virtual_ps: 504,
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

#[cfg(test)]
mod advance_publication_tests {
    use super::*;
    use std::sync::Arc;

    fn ceiling(max_advance_icount: u64) -> AdvanceCeiling {
        authorize_advance_ceiling(0, max_advance_icount, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"))
    }

    #[test]
    fn single_attempt_snapshot_requires_both_complete_publications() {
        let slot = NodeSlot::new(KIND_VM);
        slot.publish_scheduler_advance(ceiling(100), AdvanceStopCondition::NextAuthenticatedIdle)
            .unwrap_or_else(|error| panic!("scheduler control should publish: {error}"));
        slot.publish_idle(10, 20)
            .unwrap_or_else(|error| panic!("idle control should publish: {error}"));
        let original = slot.snapshot();
        assert_eq!(slot.try_snapshot(), Some(original));

        // An unfinished writer may already have changed payload fields. Neither
        // seqlock permits a host to accept that partial state.
        slot.publish_gen
            .store(original.publish_gen + 1, Ordering::Release);
        slot.current_icount.store(15, Ordering::Release);
        assert_eq!(slot.try_snapshot(), None);
        slot.advance_publication_sequence
            .store(original.advance_publication_sequence + 1, Ordering::Release);
        slot.publish_gen
            .store(original.publish_gen + 2, Ordering::Release);
        assert_eq!(slot.try_snapshot(), None);
        slot.max_advance_icount.store(80, Ordering::Release);
        slot.advance_publication_sequence
            .store(original.advance_publication_sequence + 2, Ordering::Release);

        let accepted = slot
            .try_snapshot()
            .unwrap_or_else(|| panic!("completed publications must be readable"));
        assert_eq!(accepted.current_icount, 15);
        assert_eq!(accepted.max_advance_icount, 80);
        assert_eq!(
            accepted.advance_stop_condition,
            AdvanceStopCondition::NextAuthenticatedIdle.encode()
        );
        assert_eq!(accepted.publish_gen, original.publish_gen + 2);
        assert_eq!(
            accepted.advance_publication_sequence,
            original.advance_publication_sequence + 2
        );
        assert_eq!(slot.snapshot(), accepted);
    }

    #[test]
    fn full_mode_aba_changes_the_publication_sequence() {
        let slot = NodeSlot::new(KIND_VM);
        let before = slot.snapshot();

        slot.publish_scheduler_advance(ceiling(100), AdvanceStopCondition::NextAuthenticatedIdle)
            .unwrap_or_else(|error| panic!("next-idle publication should succeed: {error}"));
        slot.publish_scheduler_advance(ceiling(7), AdvanceStopCondition::Ceiling)
            .unwrap_or_else(|error| panic!("ceiling publication should succeed: {error}"));

        let after = slot.snapshot();
        assert_eq!(before.advance_stop_condition, after.advance_stop_condition);
        assert_ne!(
            before.advance_publication_sequence,
            after.advance_publication_sequence
        );
        assert_eq!(after.max_advance_icount, 7);
        assert!(after.advance_publication_sequence.is_multiple_of(2));
    }

    #[test]
    fn concurrent_publication_never_exposes_a_mixed_scheduler_tuple() {
        const ITERATIONS: usize = 10_000;

        let slot = Arc::new(NodeSlot::new(KIND_VM));
        let next_idle_slot = Arc::clone(&slot);
        let next_idle_writer = std::thread::spawn(move || {
            for _ in 0..ITERATIONS {
                next_idle_slot
                    .publish_scheduler_advance(
                        ceiling(100),
                        AdvanceStopCondition::NextAuthenticatedIdle,
                    )
                    .unwrap_or_else(|error| panic!("next-idle publication failed: {error}"));
            }
        });
        let ceiling_slot = Arc::clone(&slot);
        let ceiling_writer = std::thread::spawn(move || {
            for _ in 0..ITERATIONS {
                ceiling_slot
                    .publish_scheduler_advance(ceiling(7), AdvanceStopCondition::Ceiling)
                    .unwrap_or_else(|error| panic!("ceiling publication failed: {error}"));
            }
        });

        for _ in 0..ITERATIONS {
            let observed = slot
                .load_scheduler_advance()
                .unwrap_or_else(|error| panic!("published tuple should decode: {error}"));
            assert!(matches!(
                observed,
                (0 | 7, AdvanceStopCondition::Ceiling)
                    | (100, AdvanceStopCondition::NextAuthenticatedIdle)
            ));
        }
        next_idle_writer
            .join()
            .unwrap_or_else(|_| panic!("next-idle publication writer panicked"));
        ceiling_writer
            .join()
            .unwrap_or_else(|_| panic!("ceiling publication writer panicked"));
    }

    #[test]
    fn clone_captures_one_even_coherent_scheduler_tuple() {
        let slot = NodeSlot::new(KIND_VM);
        slot.publish_scheduler_advance(ceiling(100), AdvanceStopCondition::NextAuthenticatedIdle)
            .unwrap_or_else(|error| panic!("next-idle publication should succeed: {error}"));

        let cloned = slot.clone().snapshot();
        assert_eq!(cloned.max_advance_icount, 100);
        assert_eq!(
            cloned.advance_stop_condition,
            AdvanceStopCondition::NextAuthenticatedIdle.encode()
        );
        assert!(cloned.advance_publication_sequence.is_multiple_of(2));
    }

    #[test]
    fn unknown_stop_condition_fails_closed() {
        let slot = NodeSlot::new(KIND_VM);
        slot.advance_stop_condition.store(0xff, Ordering::Release);

        assert_eq!(
            slot.load_scheduler_advance(),
            Err(NodeSlotError::InvalidAdvanceStopCondition { encoded: 0xff })
        );
        assert!(!slot.is_runnable_after_idle_publish());
    }
}

#[cfg(test)]
#[path = "frame_node/advance_effect_tests.rs"]
mod advance_effect_tests;
