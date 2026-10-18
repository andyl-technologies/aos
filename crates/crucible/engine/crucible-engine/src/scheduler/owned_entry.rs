//! Independently admitted scheduler-entry copies and shared final-borrower custody.

use super::*;
use crate::owned_decode::{self, DecodeCustody};

/// Owns one structural event-log copy and its original resource credits.
///
/// Shared borrowers use an admitted [`Arc`] body. The entry is destroyed before
/// its credits, including when a subscriber outlives the originating log.
#[derive(Debug)]
pub struct AdmittedSchedulerEventLogEntry {
    entry: SchedulerEventLogEntry,
    custody: DecodeCustody,
}

impl std::ops::Deref for AdmittedSchedulerEventLogEntry {
    type Target = SchedulerEventLogEntry;

    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

impl PartialEq for AdmittedSchedulerEventLogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.entry == other.entry
    }
}

impl Eq for AdmittedSchedulerEventLogEntry {}

impl AdmittedSchedulerEventLogEntry {
    /// Transfers the entry and its credits together to another owning container.
    #[must_use]
    pub fn into_parts(self) -> (SchedulerEventLogEntry, DecodeCustody) {
        (self.entry, self.custody)
    }

    /// Shares the admitted entry after reserving its concrete reference-count header.
    ///
    /// # Errors
    /// Refuses missing or failed original authority, layout overflow or exhausted credit.
    pub fn into_shared(self) -> Result<Arc<Self>, crate::EngineError> {
        let _scope = self
            .custody
            .enter()
            .ok_or_else(|| admission(owned_decode::DecodeAdmissionError::new(std::fmt::Error)))?;
        // The pinned standard-library ArcInner is repr(C): two AtomicUsize
        // counters followed by its owning body, including alignment padding.
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<Self>())
            .map_err(|source| admission(owned_decode::DecodeAdmissionError::new(source)))?;
        owned_decode::charge_bytes(layout.pad_to_align().size() as u64).map_err(admission)?;
        Ok(Arc::new(self))
    }
}

impl SchedulerEventLogEntry {
    /// Copies concrete owned fields under a fresh child of the current original authority.
    ///
    /// # Errors
    /// Refuses missing authority, exhausted credit or allocation failure before
    /// publishing any partially copied entry.
    pub fn try_clone_admitted(&self) -> Result<AdmittedSchedulerEventLogEntry, crate::EngineError> {
        let budget = owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = budget.enter();
        let entry = copy_entry_admitted(self)?;
        budget.check().map_err(admission)?;
        Ok(AdmittedSchedulerEventLogEntry {
            entry,
            custody: budget.custody(),
        })
    }
}

fn admission(source: owned_decode::DecodeAdmissionError) -> crate::EngineError {
    crate::EngineError::ArtifactDecodeAdmission { source }
}
