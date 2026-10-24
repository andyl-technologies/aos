//! Counts original born adjacency separately from early factory-cache banks.
//!
//! These requested-layout values come from concrete original producers after
//! owning preflight. They enter the actual named whole peak before the ticket
//! is issued. The same bounds are rechecked before post-Capture row copies.

use super::{NativeArchiveLimits, StateError, refused};

/// Reports distinct future dependency owners for an original complete capture.
///
/// These values are inert data. The actual Core caller binds the same original
/// runtime, source and factory and admits their sum alongside all other owning
/// rows before issuing a capture ticket. They do not replace early cache demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteOriginalCaptureDependencyStorage {
    /// Bounds additional backing retained by concrete Source born-object rows.
    pub source_born_growth_bytes: usize,
    /// Bounds separately retained adjacency Vec slots and reference clones.
    pub returned_row_growth_bytes: usize,
    /// Bounds one returned row coexisting with its temporary verification hash.
    pub maximum_lookup_scratch_bytes: usize,
}

impl CompleteOriginalCaptureDependencyStorage {
    /// Returns the conservative simultaneous requested-layout sum.
    ///
    /// # Errors
    /// Refuses arithmetic overflow without allocating or issuing authority.
    pub fn peak(&self) -> Result<usize, StateError> {
        self.source_born_growth_bytes
            .checked_add(self.returned_row_growth_bytes)
            .and_then(|bytes| bytes.checked_add(self.maximum_lookup_scratch_bytes))
            .ok_or_else(|| refused("complete dependency storage peak overflow"))
    }

    pub(super) fn validate(&self, limits: NativeArchiveLimits) -> Result<(), StateError> {
        let peak = self.peak()?;
        if peak > limits.state.maximum_total_content_bytes
            || peak > limits.native.maximum_total_record_bytes
        {
            return Err(refused(
                "complete dependency storage exceeds finite capture credit",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticate_bound(&self, observed: &Self) -> Result<(), StateError> {
        if observed.source_born_growth_bytes > self.source_born_growth_bytes
            || observed.returned_row_growth_bytes > self.returned_row_growth_bytes
            || observed.maximum_lookup_scratch_bytes > self.maximum_lookup_scratch_bytes
        {
            return Err(refused(
                "complete dependency storage widened after original admission",
            ));
        }
        Ok(())
    }
}
