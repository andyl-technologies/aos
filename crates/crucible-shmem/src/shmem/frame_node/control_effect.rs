//! Local effects ordered by the original node and control-request publishers.
//!
//! These values describe publication custody. They do not authenticate native
//! execution, a console phase, or permission to retire an authorization.

use super::*;

/// One complete original scheduler-advance observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerAdvancePublication {
    pub(super) ceiling: u64,
    pub(super) stop: AdvanceStopCondition,
    pub(super) sequence: u64,
}

impl SchedulerAdvancePublication {
    /// Returns the checked scheduler ceiling.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        self.ceiling
    }

    /// Returns the original completion condition.
    #[must_use]
    pub const fn stop(self) -> AdvanceStopCondition {
        self.stop
    }

    /// Returns the stable even original advance sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Original boundary fields supplied within their node publication interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeBoundaryPublication {
    pub(super) logical: u64,
    pub(super) raw: u64,
    pub(super) advance: Option<SchedulerAdvancePublication>,
    pub(super) closed_generation: u32,
}

impl NodeBoundaryPublication {
    /// Returns the exact logical coordinate stored by the original writer.
    #[must_use]
    pub const fn logical(self) -> u64 {
        self.logical
    }

    /// Returns the exact raw retirement stored by the original writer.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.raw
    }

    /// Returns the even generation closed by this same original writer.
    ///
    /// The writer's entry operation retains this value before its fields are
    /// stored. It describes storage framing after normal return, refusal or
    /// unwind; it does not authenticate a native stop or any phase. Wrapping
    /// follows the original publication counter without extending its lifetime.
    #[must_use]
    pub const fn closed_generation(self) -> u32 {
        self.closed_generation
    }

    /// Returns the ordinary writer's original checked advance observation.
    ///
    /// The pause writer deliberately performs no scheduler-advance read. Its
    /// caller must retain its own validated original callback tuple separately.
    #[must_use]
    pub const fn advance(self) -> Option<SchedulerAdvancePublication> {
        self.advance
    }
}

/// A refusal before accepted local effects or an original publication failure.
#[derive(Debug, thiserror::Error)]
pub enum NodeBoundaryPublicationError<E> {
    /// Original slot validation failed before opening the writer.
    #[error("node boundary publication failed: {0}")]
    Slot(NodeSlotError),
    /// The prepared effect refused without mutating its accepted state.
    #[error("node boundary effect refused: {0}")]
    Effect(E),
}

impl NodeBoundaryPublicationError<std::convert::Infallible> {
    pub(super) fn into_slot(self) -> NodeSlotError {
        match self {
            Self::Slot(error) => error,
            Self::Effect(never) => match never {},
        }
    }
}

/// Closes the original publication on normal return, refusal and unwind.
pub(super) struct BoundaryWriter<'a> {
    generation: &'a AtomicU32,
    closed_generation: u32,
}

impl<'a> BoundaryWriter<'a> {
    pub(super) fn enter(generation: &'a AtomicU32) -> Self {
        let previous = generation.fetch_add(1, Ordering::AcqRel);
        Self {
            generation,
            closed_generation: previous.wrapping_add(2),
        }
    }

    pub(super) const fn closed_generation(&self) -> u32 {
        self.closed_generation
    }
}

impl Drop for BoundaryWriter<'_> {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::convert::Infallible;

    use super::*;

    #[test]
    fn original_boundary_writers_supply_their_actual_closing_generation() {
        let slot = NodeSlot::new(0);
        let seen = Cell::new(0);
        let pause = slot.publish_pause_quiesced_with_effect(0, 0, |publication| {
            assert_eq!(slot.publish_gen.load(Ordering::Acquire), 1);
            assert!(slot.try_snapshot().is_none());
            assert!(publication.advance().is_none());
            seen.set(publication.closed_generation());
            Ok::<_, Infallible>(())
        });
        assert!(pause.is_ok());
        assert_eq!(seen.get(), 2);
        assert_eq!(slot.publish_gen.load(Ordering::Acquire), seen.get());

        let ordinary = slot.publish_control_boundary_with_effect(0, 0, |publication| {
            assert_eq!(slot.publish_gen.load(Ordering::Acquire), 3);
            assert!(publication.advance().is_some());
            seen.set(publication.closed_generation());
            Ok::<_, Infallible>(())
        });
        assert!(ordinary.is_ok());
        assert_eq!(seen.get(), 4);
        assert_eq!(slot.publish_gen.load(Ordering::Acquire), seen.get());
        assert_eq!(slot.control_boundary_ack.load(Ordering::Acquire), 1);
    }

    #[test]
    fn original_writer_generation_wrap_and_refusal_keep_the_same_close() {
        let slot = NodeSlot::new(0);
        slot.publish_gen.store(u32::MAX - 1, Ordering::Release);
        let seen = Cell::new(u32::MAX);

        let refused = slot.publish_pause_quiesced_with_effect(0, 0, |publication| {
            assert_eq!(slot.publish_gen.load(Ordering::Acquire), u32::MAX);
            seen.set(publication.closed_generation());
            Err::<(), _>("refused before any stop-table effect")
        });
        assert!(matches!(
            refused,
            Err(NodeBoundaryPublicationError::Effect(_))
        ));
        assert_eq!(seen.get(), 0);
        assert_eq!(slot.publish_gen.load(Ordering::Acquire), 0);
        assert!(slot.try_snapshot().is_some());
        assert_eq!(slot.control_boundary_ack.load(Ordering::Acquire), 1);
    }
}
