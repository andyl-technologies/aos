//! Couples an actual bounded node observation to its scheduler writer.
//!
//! These move-only physical receipts retain the exact slot and observed report.
//! They supply no operation, Source, borrower, deadline or execution permission.
//! Report-generation and scheduler-sequence checks do not replace independent
//! control/restore protocol validation or the producer's actual lender joins.

use super::*;

/// Retains an actual node report before reserving its observed scheduler generation.
///
/// Dropping this receipt changes no shared word. Its snapshot corroborates only
/// the bounded observation that created it, independently of semantic custody.
#[must_use]
pub struct ObservedSchedulerAdvance<'slot> {
    slot: &'slot NodeSlot,
    snapshot: NodeSlotSnapshot,
}

/// Holds the writer reserved from the same actual bounded node observation.
///
/// Abandonment consumes the fresh scheduler generation without changing the
/// previous tuple or wake. Already published inputs remain the caller's debt.
#[must_use]
pub struct PreparedSchedulerAdvance<'slot> {
    observation: ObservedSchedulerAdvance<'slot>,
    publication: SchedulerAdvancePublication<'slot>,
}

impl NodeSlot {
    /// Observes command coordinates once without reserving or waiting.
    ///
    /// # Errors
    /// Refuses an occupied or changed node report or scheduler publication.
    pub fn observe_scheduler_advance(&self) -> Result<ObservedSchedulerAdvance<'_>, NodeSlotError> {
        Ok(ObservedSchedulerAdvance {
            slot: self,
            snapshot: self.try_snapshot()?,
        })
    }
}

impl<'slot> ObservedSchedulerAdvance<'slot> {
    /// Returns the exact bounded observation retained by this receipt.
    #[must_use]
    pub const fn snapshot(&self) -> NodeSlotSnapshot {
        self.snapshot
    }

    fn check_report(&self) -> Result<(), NodeSlotError> {
        let observed = self.slot.publish_gen.load(Ordering::Acquire);
        if observed != self.snapshot.publish_gen {
            return Err(NodeSlotError::NodeReportChanged {
                expected: self.snapshot.publish_gen,
                observed,
            });
        }
        Ok(())
    }

    /// Reserves only the scheduler generation in this actual observation.
    ///
    /// The report is checked before and after the single writer CAS. A failed
    /// postcheck consumes a born reservation without committing inputs or wake.
    ///
    /// # Errors
    /// Refuses a changed report, replaced or occupied scheduler generation, or
    /// generation exhaustion. It never waits or acquires another generation.
    pub fn reserve(self) -> Result<PreparedSchedulerAdvance<'slot>, NodeSlotError> {
        self.check_report()?;
        let publication = self
            .slot
            .reserve_scheduler_advance_at(self.snapshot.advance_publication_sequence)?;
        self.check_report()?;
        Ok(PreparedSchedulerAdvance {
            observation: self,
            publication,
        })
    }
}

impl<'slot> PreparedSchedulerAdvance<'slot> {
    /// Returns the actual initial report retained before writer acquisition.
    #[must_use]
    pub const fn snapshot(&self) -> NodeSlotSnapshot {
        self.observation.snapshot
    }

    /// Returns the fresh generation owned by this exact writer reservation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.publication.generation()
    }

    /// Observes whether this writer belongs to the exact supplied node slot.
    #[must_use]
    pub fn belongs_to(&self, slot: &NodeSlot) -> bool {
        self.publication.belongs_to(slot)
    }

    /// Commits under the same report while retaining a separate once-only wake.
    ///
    /// # Errors
    /// Refuses a changed report or invalid ceiling, consuming the reservation
    /// without changing the tuple or wake. Independent operation custody is
    /// required before this physical commit and its later wake.
    pub fn commit(
        self,
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
    ) -> Result<CommittedSchedulerAdvance<'slot>, NodeSlotError> {
        self.observation.check_report()?;
        self.publication.commit(ceiling, stop_condition)
    }

    /// Publishes a checked inbox batch, then this reserved tuple and its wake.
    ///
    /// The complete ring batch is checked before effects. A changed report
    /// after inbox publication leaves those actual inputs as retained debt;
    /// neither the tuple nor wake is committed by that refused request.
    ///
    /// # Errors
    /// Refuses a changed report, invalid ceiling or input source, insufficient
    /// ring capacity, an enqueue failure, or the once-only futex wake failure.
    // crucible-lint: allow rust-allow -- the borrowed adapter binds every independent ring and scheduler-advance input explicitly.
    #[allow(
        clippy::too_many_arguments,
        reason = "the borrowed adapter binds one directed ring and one typed scheduler advance"
    )]
    pub fn publish_inbox_and_advance(
        self,
        dst_slot: u32,
        src_slot: u32,
        inbox: &RingHeader,
        inbox_entries: &mut [FrameEntry],
        pending_inputs: &[FrameEntry],
        ceiling: AdvanceCeiling,
        stop_condition: AdvanceStopCondition,
    ) -> Result<SchedulerWakePublication, SchedulerWakePublicationError> {
        self.observation.check_report()?;
        self.observation.slot.validate_scheduler_ceiling(ceiling)?;
        for (input_index, frame) in pending_inputs.iter().enumerate() {
            crate::region::helpers::validate_pending_input_source(input_index, src_slot, frame)?;
        }
        crate::region::helpers::preflight_ring_enqueue_capacity(
            inbox,
            inbox_entries,
            pending_inputs.len(),
        )
        .map_err(RegionAllocationAccessError::from)?;
        self.observation.check_report()?;

        for frame in pending_inputs {
            inbox
                .enqueue(inbox_entries, frame)
                .map_err(RegionAllocationAccessError::from)?;
        }
        let wake = self.commit(ceiling, stop_condition)?.wake()?;
        Ok(SchedulerWakePublication {
            dst_slot,
            pending_input_count: pending_inputs.len(),
            max_advance_icount: ceiling.max_advance_icount(),
            wake,
        })
    }
}

#[cfg(test)]
#[path = "scheduler_observation/tests.rs"]
mod tests;
