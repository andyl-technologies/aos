//! Reserves one nonreusable scheduler publication before inbox effects.
//!
//! The existing odd/even wire sequence excludes concurrent writers. A refused
//! reservation changes no inputs, tuple or wake. An abandoned reservation
//! closes at its fresh even successor without claiming a committed advance;
//! any already enqueued frames remain the caller's publication debt.

use super::*;

/// Retains the exact slot and fresh sequence through a scheduler handoff.
///
/// This physical writer reservation supplies no operation, deadline or execution
/// authority. Its owner must retain those independently before publishing. Drop
/// consumes its fresh generation even when no tuple was committed.
#[must_use]
pub struct SchedulerAdvancePublication<'a> {
    slot: &'a NodeSlot,
    completed_sequence: u64,
    closed: bool,
}

/// Retains one committed scheduler tuple before its once-only wake attempt.
///
/// The producer can publish its actual immutable command and operation borrower
/// after tuple commit and before waking the executor. This receipt corroborates
/// that physical ordering; it grants no permission to execute or renew work.
#[must_use]
pub struct CommittedSchedulerAdvance<'a> {
    slot: &'a NodeSlot,
    sequence: u64,
}

impl NodeSlot {
    /// Reserves one exact generation without waiting for another writer.
    ///
    /// # Errors
    /// Refuses an occupied writer or exhausted generation before mutation.
    pub fn reserve_scheduler_advance(
        &self,
    ) -> Result<SchedulerAdvancePublication<'_>, NodeSlotError> {
        let observed = self.advance_publication_sequence.load(Ordering::Acquire);
        if !observed.is_multiple_of(2) {
            return Err(NodeSlotError::AdvancePublicationOccupied {
                expected: observed,
                observed,
            });
        }
        let completed_sequence = observed
            .checked_add(2)
            .ok_or(NodeSlotError::AdvanceGenerationExhausted { sequence: observed })?;

        self.advance_publication_sequence
            .compare_exchange(observed, observed + 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|actual| NodeSlotError::AdvancePublicationOccupied {
                expected: observed,
                observed: actual,
            })?;

        Ok(SchedulerAdvancePublication {
            slot: self,
            completed_sequence,
            closed: false,
        })
    }
}

impl SchedulerAdvancePublication<'_> {
    /// Returns the actual fresh generation reserved by this writer.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.completed_sequence
    }

    /// Observes whether this reservation belongs to the exact supplied slot.
    #[must_use]
    pub fn belongs_to(&self, slot: &NodeSlot) -> bool {
        std::ptr::eq(self.slot, slot)
    }

    /// Commits the tuple before incrementing and ringing its existing wake.
    pub(crate) fn publish(
        self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
    ) -> Result<WakeAction, NodeSlotError> {
        let slot = self.slot;
        self.publish_without_wake(ceiling.max_advance_icount, stop_condition);
        slot.wake_after_signal_increment()
            .map_err(|source| NodeSlotError::FutexWake { source })
    }

    /// Commits the tuple for an externally restored, still quiesced executor.
    pub(crate) fn publish_without_wake(
        mut self,
        max_advance_icount: u64,
        stop_condition: AdvanceStopCondition,
    ) {
        // Preserve the executor's asymmetric acquire observations: raising a
        // next-idle ceiling first installs its stop mode, while clearing that
        // mode first installs the replacement ceiling.
        match stop_condition {
            AdvanceStopCondition::NextAuthenticatedIdle => {
                self.slot
                    .advance_stop_condition
                    .store(stop_condition.encode(), Ordering::Release);
                self.slot
                    .max_advance_icount
                    .store(max_advance_icount, Ordering::Release);
            }
            AdvanceStopCondition::Ceiling => {
                self.slot
                    .max_advance_icount
                    .store(max_advance_icount, Ordering::Release);
                self.slot
                    .advance_stop_condition
                    .store(stop_condition.encode(), Ordering::Release);
            }
        }
        self.slot
            .advance_publication_sequence
            .store(self.completed_sequence, Ordering::Release);
        self.closed = true;
    }
}

impl<'slot> SchedulerAdvancePublication<'slot> {
    /// Commits the validated tuple while retaining its separate wake attempt.
    ///
    /// A caller can retain its real publisher memberships and immutable command
    /// before this mutation, then publish their offer before consuming the wake
    /// receipt. A refused later operation does not undo this committed tuple.
    ///
    /// # Errors
    /// Refuses a ceiling incompatible with the actual slot. The reservation's
    /// fresh generation is still consumed, without changing the tuple or wake.
    pub fn commit(
        self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
    ) -> Result<CommittedSchedulerAdvance<'slot>, NodeSlotError> {
        self.slot.validate_scheduler_ceiling(ceiling)?;
        let committed = CommittedSchedulerAdvance {
            slot: self.slot,
            sequence: self.completed_sequence,
        };
        self.publish_without_wake(ceiling.max_advance_icount, stop_condition);

        Ok(committed)
    }
}

impl CommittedSchedulerAdvance<'_> {
    /// Returns the actual committed generation, independently of any wake.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.sequence
    }

    /// Observes whether this commit belongs to the exact supplied slot.
    #[must_use]
    pub fn belongs_to(&self, slot: &NodeSlot) -> bool {
        std::ptr::eq(self.slot, slot)
    }

    /// Attempts this committed tuple's wake once, consuming its receipt.
    ///
    /// # Errors
    /// Refuses a replaced publication before changing the wake word. A futex
    /// failure preserves its typed cause after the signal increment; it does
    /// not permit another attempt through this consumed receipt.
    /// A wake remains advisory: another writer can replace the tuple after
    /// this observation. Consumers must authenticate their retained command.
    pub fn wake(self) -> Result<WakeAction, NodeSlotError> {
        let observed = self
            .slot
            .advance_publication_sequence
            .load(Ordering::Acquire);
        if observed != self.sequence {
            return Err(NodeSlotError::AdvancePublicationOccupied {
                expected: self.sequence,
                observed,
            });
        }

        self.slot
            .wake_after_signal_increment()
            .map_err(|source| NodeSlotError::FutexWake { source })
    }
}

impl Drop for SchedulerAdvancePublication<'_> {
    fn drop(&mut self) {
        if !self.closed {
            // All fallible work precedes tuple stores. Abandonment preserves
            // the previous tuple and consumes this sequence without a wake.
            // Reusing the old even value would conceal the attempted handoff.
            self.slot
                .advance_publication_sequence
                .store(self.completed_sequence, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceiling() -> AdvanceCeiling {
        authorize_advance_ceiling(0, 12, None).unwrap()
    }

    #[test]
    fn committed_tuple_retains_a_separate_once_wake_receipt() {
        let slot = NodeSlot::new(KIND_VM);
        let foreign = NodeSlot::new(KIND_VM);
        let reservation = slot.reserve_scheduler_advance().unwrap();
        assert_eq!(reservation.generation(), 2);
        assert!(reservation.belongs_to(&slot));
        assert!(!reservation.belongs_to(&foreign));

        let committed = reservation
            .commit(ceiling(), AdvanceStopCondition::NextAuthenticatedIdle)
            .unwrap();

        assert_eq!(committed.generation(), 2);
        assert!(committed.belongs_to(&slot));
        assert!(!committed.belongs_to(&foreign));
        let before_wake = slot.snapshot();
        assert_eq!(before_wake.advance_publication_sequence, 2);
        assert_eq!(before_wake.max_advance_icount, 12);
        assert_eq!(before_wake.wake_signal, 0);

        committed.wake().unwrap();

        assert_eq!(slot.snapshot().wake_signal, 1);
    }

    #[test]
    fn replaced_commit_refuses_before_an_extra_wake() {
        let slot = NodeSlot::new(KIND_VM);
        let committed = slot
            .reserve_scheduler_advance()
            .unwrap()
            .commit(ceiling(), AdvanceStopCondition::Ceiling)
            .unwrap();
        slot.publish_scheduler_advance(ceiling(), AdvanceStopCondition::NextAuthenticatedIdle)
            .unwrap();
        let before = slot.snapshot();

        assert_eq!(
            committed.wake(),
            Err(NodeSlotError::AdvancePublicationOccupied {
                expected: 2,
                observed: 4,
            })
        );
        assert_eq!(slot.snapshot(), before);
    }

    #[test]
    fn refused_commit_consumes_only_its_fresh_generation() {
        let slot = NodeSlot::new(KIND_VM);
        slot.current_icount.store(13, Ordering::Release);
        let before = slot.snapshot();
        let reservation = slot.reserve_scheduler_advance().unwrap();

        assert!(matches!(
            reservation.commit(ceiling(), AdvanceStopCondition::Ceiling),
            Err(NodeSlotError::CeilingBeforePublishedCurrent {
                current_icount: 13,
                max_advance_icount: 12,
            })
        ));

        let after = slot.snapshot();
        assert_eq!(after.advance_publication_sequence, 2);
        assert_eq!(after.max_advance_icount, before.max_advance_icount);
        assert_eq!(after.advance_stop_condition, before.advance_stop_condition);
        assert_eq!(after.wake_signal, before.wake_signal);
    }

    #[test]
    fn discarded_commit_does_not_ring_or_reuse_its_generation() {
        let slot = NodeSlot::new(KIND_VM);
        {
            let committed = slot
                .reserve_scheduler_advance()
                .unwrap()
                .commit(ceiling(), AdvanceStopCondition::Ceiling)
                .unwrap();
            assert_eq!(committed.generation(), 2);
        }

        assert_eq!(slot.snapshot().wake_signal, 0);
        let next = slot.reserve_scheduler_advance().unwrap();
        assert_eq!(next.generation(), 4);
    }

    #[test]
    fn bounded_snapshot_refuses_the_actual_held_writer_without_waiting() {
        let slot = NodeSlot::new(KIND_VM);
        let before = slot.snapshot();
        let reservation = slot.reserve_scheduler_advance().unwrap();

        assert_eq!(
            slot.try_snapshot(),
            Err(NodeSlotError::AdvancePublicationOccupied {
                expected: 1,
                observed: 1,
            })
        );
        assert_eq!(slot.wake_signal.load(Ordering::Acquire), before.wake_signal);
        assert_eq!(slot.max_advance_icount.load(Ordering::Acquire), 0);
        assert_eq!(reservation.generation(), 2);

        drop(reservation);
        assert_eq!(slot.try_snapshot(), Ok(slot.snapshot()));
    }

    #[test]
    fn bounded_snapshot_refuses_an_incomplete_node_report_without_mutation() {
        let slot = NodeSlot::new(KIND_VM);
        slot.publish_gen.store(3, Ordering::Release);

        assert_eq!(
            slot.try_snapshot(),
            Err(NodeSlotError::NodeReportChanged {
                expected: 3,
                observed: 3,
            })
        );

        assert_eq!(slot.publish_gen.load(Ordering::Acquire), 3);
        assert_eq!(slot.advance_publication_sequence.load(Ordering::Acquire), 0);
        assert_eq!(slot.wake_signal.load(Ordering::Acquire), 0);
    }

    #[test]
    fn final_even_publication_refuses_reuse_without_tuple_or_wake_changes() {
        let slot = NodeSlot::new(KIND_VM);
        slot.advance_publication_sequence
            .store(u64::MAX - 3, Ordering::Release);
        slot.publish_scheduler_advance(ceiling(), AdvanceStopCondition::NextAuthenticatedIdle)
            .unwrap();
        let before = slot.snapshot();
        assert_eq!(before.advance_publication_sequence, u64::MAX - 1);

        let result = slot.publish_scheduler_advance(ceiling(), AdvanceStopCondition::Ceiling);

        assert_eq!(
            result,
            Err(NodeSlotError::AdvanceGenerationExhausted {
                sequence: u64::MAX - 1,
            })
        );
        assert_eq!(slot.snapshot(), before);
        assert_eq!(
            slot.arm_external_state_restore_ceiling(12),
            Err(NodeSlotError::AdvanceGenerationExhausted {
                sequence: u64::MAX - 1,
            })
        );
        assert_eq!(slot.snapshot(), before);
    }

    #[test]
    fn occupied_writer_refuses_without_waiting_or_changing_the_actual_slot() {
        let slot = NodeSlot::new(KIND_VM);
        let reservation = slot.reserve_scheduler_advance().unwrap();

        assert_eq!(
            slot.publish_scheduler_advance(ceiling(), AdvanceStopCondition::Ceiling),
            Err(NodeSlotError::AdvancePublicationOccupied {
                expected: 1,
                observed: 1,
            })
        );
        assert_eq!(slot.advance_publication_sequence.load(Ordering::Acquire), 1);
        assert_eq!(slot.max_advance_icount.load(Ordering::Acquire), 0);
        assert_eq!(slot.wake_signal.load(Ordering::Acquire), 0);

        reservation
            .publish(ceiling(), AdvanceStopCondition::Ceiling)
            .unwrap();
        assert_eq!(slot.snapshot().advance_publication_sequence, 2);
        assert_eq!(slot.snapshot().wake_signal, 1);
    }

    #[test]
    fn abandoned_reservation_consumes_its_epoch_without_a_tuple_or_wake() {
        let slot = NodeSlot::new(KIND_VM);
        let before = slot.snapshot();
        let unwind = std::panic::catch_unwind(|| {
            let _reservation = slot.reserve_scheduler_advance().unwrap();
            panic!("abandon the actual reserved writer before tuple stores");
        });
        assert!(unwind.is_err());

        let after = slot.snapshot();
        assert_eq!(after.advance_publication_sequence, 2);
        assert_eq!(after.max_advance_icount, before.max_advance_icount);
        assert_eq!(after.advance_stop_condition, before.advance_stop_condition);
        assert_eq!(after.wake_signal, before.wake_signal);

        slot.publish_scheduler_advance(ceiling(), AdvanceStopCondition::Ceiling)
            .unwrap();
        assert_eq!(slot.snapshot().advance_publication_sequence, 4);
    }

    #[test]
    fn borrowed_inbox_refuses_occupied_and_exhausted_writers_before_enqueue() {
        for sequence in [1, u64::MAX - 1] {
            let slot = NodeSlot::new(KIND_VM);
            slot.advance_publication_sequence
                .store(sequence, Ordering::Release);
            let inbox = RingHeader::new();
            let mut entries = core::array::from_fn::<_, 2, _>(|_| FrameEntry::default());
            let input = FrameEntry::new(12, SLOT_NET_ROUTER as u32, 1, b"net").unwrap();

            let error = slot
                .publish_scheduler_inbox_and_advance(
                    0,
                    SLOT_NET_ROUTER as u32,
                    &inbox,
                    &mut entries,
                    &[input],
                    ceiling(),
                    AdvanceStopCondition::Ceiling,
                )
                .unwrap_err();

            assert!(matches!(
                error,
                SchedulerWakePublicationError::NodeSlot { .. }
            ));
            assert_eq!(inbox.read_index(), 0);
            assert_eq!(inbox.write_index(), 0);
            assert_eq!(inbox.peek(&entries), Ok(None));
            assert_eq!(
                slot.advance_publication_sequence.load(Ordering::Acquire),
                sequence
            );
            assert_eq!(slot.max_advance_icount.load(Ordering::Acquire), 0);
            assert_eq!(slot.wake_signal.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn allocated_inbox_refuses_occupied_and_exhausted_writers_before_enqueue() {
        for sequence in [1, u64::MAX - 1] {
            let mut region = RegionAllocation::new_model(RegionConfig::new(1, 2)).unwrap();
            region
                .node_slot(0)
                .unwrap()
                .advance_publication_sequence
                .store(sequence, Ordering::Release);
            let input = FrameEntry::new(12, SLOT_NET_ROUTER as u32, 1, b"net").unwrap();

            let error = region
                .publish_scheduler_inputs_and_advance(
                    0,
                    &[PendingInputPublication::new(SLOT_NET_ROUTER as u32, input)],
                    ceiling(),
                    AdvanceStopCondition::Ceiling,
                )
                .unwrap_err();

            assert!(matches!(
                error,
                SchedulerWakePublicationError::NodeSlot { .. }
            ));
            assert_eq!(
                region.peek_directed_frame(SLOT_NET_ROUTER as u32, 0),
                Ok(None)
            );
            let slot = region.node_slot(0).unwrap();
            assert_eq!(
                slot.advance_publication_sequence.load(Ordering::Acquire),
                sequence
            );
            assert_eq!(slot.max_advance_icount.load(Ordering::Acquire), 0);
            assert_eq!(slot.wake_signal.load(Ordering::Acquire), 0);
        }
    }
}
