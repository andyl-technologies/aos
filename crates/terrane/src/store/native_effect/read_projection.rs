//! Checks complete retained physical read inputs without performing a mutation.
//!
//! The private publication factory supplies actual exclusion duplicates, named
//! fences and original whole-value recipes. The worker owns those inputs until
//! every physical check finishes, even when its asynchronous waiter is dropped.

use super::{ExactRead, NamedFence, NativeExclusion};
use std::io;
use std::sync::Arc;

/// Owns the fixed physical inputs of one read-only closing observation.
pub(in crate::store) struct NativeReadProjection {
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    preimages: Vec<ExactRead>,
}

impl NativeReadProjection {
    /// Retains actual inputs packaged by the native publication descendant.
    pub(in crate::store::native_effect) fn new(
        exclusions: Arc<[NativeExclusion]>,
        names: Vec<NamedFence>,
        preimages: Vec<ExactRead>,
    ) -> Self {
        Self {
            exclusions,
            names,
            preimages,
        }
    }

    /// Checks all named fences around the complete original body observations.
    ///
    /// # Errors
    /// Refuses changed ancestors, names, descriptors, protection, whole bodies
    /// or absence observations, and unavailable actual filesystem reads.
    pub(in crate::store) fn check(self) -> io::Result<()> {
        for name in &self.names {
            name.check(&self.exclusions)?;
        }

        for preimage in &self.preimages {
            preimage.check()?;
        }

        for name in &self.names {
            name.check(&self.exclusions)?;
        }

        Ok(())
    }
}
