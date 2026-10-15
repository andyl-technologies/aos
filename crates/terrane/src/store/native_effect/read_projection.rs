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
    direct: Option<crate::guard::direct_history::DirectReadCheck>,
    overlay: Option<crate::guard::overlay_history::OverlayReadCheck>,
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
            direct: None,
            overlay: None,
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
            direct: None,
            overlay: None,
        }
    }

    /// Retains ordinary original DATA recipes and a grantless direct inventory check.
    ///
    /// This constructor creates a read projection, never a publication effect
    /// or an ACL decision. Protected inputs keep their separate strict recipes.
    pub(in crate::store::native_effect) fn new_direct(
        exclusions: Arc<[NativeExclusion]>,
        names: Vec<NamedFence>,
        preimages: Vec<ExactRead>,
        ordinary: Vec<Arc<RetainedPayloadRanges>>,
        direct: crate::guard::direct_history::DirectReadCheck,
    ) -> Self {
        Self {
            exclusions,
            names,
            preimages,
            ordinary,
            current: None,
            direct: Some(direct),
            overlay: None,
        }
    }

    /// Retains ordinary original DATA recipes and a grantless overlay inventory check.
    ///
    /// This constructor creates a read projection, never a publication effect
    /// or an ACL decision. Protected inputs keep their separate strict recipes.
    pub(in crate::store::native_effect) fn new_overlay(
        exclusions: Arc<[NativeExclusion]>,
        names: Vec<NamedFence>,
        preimages: Vec<ExactRead>,
        ordinary: Vec<Arc<RetainedPayloadRanges>>,
        overlay: crate::guard::overlay_history::OverlayReadCheck,
    ) -> Self {
        Self {
            exclusions,
            names,
            preimages,
            ordinary,
            current: None,
            direct: None,
            overlay: Some(overlay),
        }
    }

    /// Checks all named fences around the complete original body observations.
    ///
    /// # Errors
    /// Refuses changed ancestors, names, descriptors, protection, whole bodies
    /// or absence observations, and unavailable actual filesystem reads.
    pub(in crate::store) fn check(self) -> io::Result<()> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::ReadProjection);
        {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            let mut component =
                crate::diagnostic_clock::span(crate::diagnostic_clock::Group::ReadCurrent);
            if let Some(overlay) = &self.overlay {
                overlay.recheck().map_err(io::Error::other)?;
            }
            if let Some(direct) = &self.direct {
                direct.recheck().map_err(io::Error::other)?;
            }
            if let Some(current) = &self.current {
                current.recheck().map_err(io::Error::other)?;
            }
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            component.complete();
        }

        {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            let mut component =
                crate::diagnostic_clock::span(crate::diagnostic_clock::Group::ReadNamesBefore);
            // Inventory describes the whole batch, including a refused suffix.
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            crate::diagnostic_clock::count(
                crate::diagnostic_clock::Group::ReadNamesBefore,
                self.names.len(),
            );
            for name in &self.names {
                name.check(&self.exclusions)?;
            }
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            component.complete();
        }

        {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            let mut component =
                crate::diagnostic_clock::span(crate::diagnostic_clock::Group::ReadPreimages);
            // Inventory describes the whole batch, including a refused suffix.
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            crate::diagnostic_clock::count(
                crate::diagnostic_clock::Group::ReadPreimages,
                self.preimages.len(),
            );
            for preimage in &self.preimages {
                preimage.check()?;
            }
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            component.complete();
        }

        {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            let mut component =
                crate::diagnostic_clock::span(crate::diagnostic_clock::Group::ReadRanges);
            // Inventory describes the whole batch, including a refused suffix.
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            crate::diagnostic_clock::count(
                crate::diagnostic_clock::Group::ReadRanges,
                self.ordinary.len(),
            );
            for ordinary in &self.ordinary {
                ordinary.check_ranges()?;
            }
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            component.complete();
        }

        {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            let mut component =
                crate::diagnostic_clock::span(crate::diagnostic_clock::Group::ReadNamesAfter);
            // Inventory describes the whole batch, including a refused suffix.
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            crate::diagnostic_clock::count(
                crate::diagnostic_clock::Group::ReadNamesAfter,
                self.names.len(),
            );
            for name in &self.names {
                name.check(&self.exclusions)?;
            }
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            component.complete();
        }

        {
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            let mut component =
                crate::diagnostic_clock::span(crate::diagnostic_clock::Group::ReadCurrentAfter);
            if let Some(overlay) = &self.overlay {
                overlay.recheck().map_err(io::Error::other)?;
            }
            if let Some(direct) = &self.direct {
                direct.recheck().map_err(io::Error::other)?;
            }
            if let Some(current) = &self.current {
                current.recheck().map_err(io::Error::other)?;
            }
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            component.complete();
        }

        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.complete();
        Ok(())
    }
}
