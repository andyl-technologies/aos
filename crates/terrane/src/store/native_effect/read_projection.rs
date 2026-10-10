//! Checks complete retained physical read inputs without performing a mutation.
//!
//! The private publication factory supplies actual exclusion duplicates, named
//! fences and original whole-value recipes. The worker owns those inputs until
//! every physical check finishes, even when its asynchronous waiter is dropped.

use super::payload_ranges::RetainedPayloadRanges;
use super::{ExactRead, NamedFence, NativeExclusion};
use std::io;
use std::sync::Arc;

/// Owns the fixed physical inputs of one read-only closing observation.
pub(in crate::store) struct NativeReadProjection {
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    preimages: Vec<ExactRead>,
    ordinary: Vec<Arc<RetainedPayloadRanges>>,
    current: Option<crate::guard::PendingCurrentReadCheck>,
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
            ordinary: Vec::new(),
            current: None,
        }
    }

    /// Retains ordinary original DATA recipes and a token-only current check.
    ///
    /// This constructor creates a read projection, never a publication effect
    /// or an ACL decision. Protected inputs keep their separate strict recipes.
    pub(in crate::store::native_effect) fn new_current(
        exclusions: Arc<[NativeExclusion]>,
        names: Vec<NamedFence>,
        preimages: Vec<ExactRead>,
        ordinary: Vec<Arc<RetainedPayloadRanges>>,
        current: crate::guard::PendingCurrentReadCheck,
    ) -> Self {
        Self {
            exclusions,
            names,
            preimages,
            ordinary,
            current: Some(current),
        }
    }

    /// Checks all named fences around the complete original body observations.
    ///
    /// # Errors
    /// Refuses changed ancestors, names, descriptors, protection, whole bodies
    /// or absence observations, and unavailable actual filesystem reads.
    pub(in crate::store) fn check(self) -> io::Result<()> {
        if let Some(current) = &self.current {
            current.recheck().map_err(io::Error::other)?;
        }

        for name in &self.names {
            name.check(&self.exclusions)?;
        }

        for preimage in &self.preimages {
            preimage.check()?;
        }

        for ordinary in &self.ordinary {
            ordinary.check_ranges()?;
        }

        for name in &self.names {
            name.check(&self.exclusions)?;
        }

        if let Some(current) = &self.current {
            current.recheck().map_err(io::Error::other)?;
        }

        Ok(())
    }
}
