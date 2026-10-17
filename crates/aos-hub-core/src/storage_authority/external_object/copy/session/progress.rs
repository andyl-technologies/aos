//! Closed metadata projection from actual retained private copy state.

use anyhow::Result;

use super::{CopyPhase, CopySession};
use crate::storage_authority::{external_object::copy::control::CopyProgress, lease::LeaseInteger};

impl CopySession {
    /// Projects compact progress without returning the private hash continuation.
    ///
    /// # Errors
    /// Returns an error for invalid durable state or an overflowing byte count.
    pub fn progress(&self) -> Result<CopyProgress> {
        self.validate(&self.original)?;
        let value = CopyProgress {
            phase: self.phase,
            completed_parts: self.next_part - 1,
            copied_bytes: LeaseInteger::new(i64::try_from(self.source_state.total_bytes)?)?,
            pending: self.pending.is_some(),
            destination: self.destination.clone(),
            sha256: if self.phase == CopyPhase::Closed {
                Some(self.source_hash()?)
            } else {
                None
            },
        };
        value.validate(&self.original)?;
        Ok(value)
    }
}
