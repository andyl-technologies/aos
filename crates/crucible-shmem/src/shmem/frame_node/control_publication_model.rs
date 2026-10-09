//! Explicitly modeled CAS writer for public-protocol interleaving controls.
//!
//! This test-support fixture never authenticates a stopped callback, phase or
//! native owner. Production hosts acquire their separate typed host lease.

use super::*;
use core::num::NonZeroU32;

/// A modeled competing writer minted by an actual zero-to-value claim CAS.
///
/// The fixture retains the real shared word until its exact release. It exposes
/// no owned snapshots, paired fields, request commits or execution permission.
/// It is absent unless the explicit `test-support` feature is selected.
pub struct ModeledControlBoundaryPublication<'a> {
    word: &'a AtomicU32,
    value: NonZeroU32,
}

impl NodeSlot {
    /// Claims an explicitly modeled competitor for a protocol interleaving test.
    ///
    /// Value `2` models the stopped-output writer's protocol reservation only;
    /// other nonzero values exercise host or unknown-claim refusal. No native
    /// callback, lexical scope or execution authority is supplied by this CAS.
    ///
    /// # Errors
    ///
    /// Refuses an already-held claim without modifying any shared field.
    pub fn try_claim_control_boundary_publication_for_test(
        &self,
        value: NonZeroU32,
    ) -> Result<ModeledControlBoundaryPublication<'_>, NodeSlotError> {
        self.control_boundary_publication_claim
            .compare_exchange(0, value.get(), Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NodeSlotError::ControlBoundaryPublicationBusy)?;
        Ok(ModeledControlBoundaryPublication {
            word: &self.control_boundary_publication_claim,
            value,
        })
    }
}

impl ModeledControlBoundaryPublication<'_> {
    /// Returns the currently observed protocol word without granting ownership.
    #[must_use]
    pub fn observed_claim(&self) -> u32 {
        self.word.load(Ordering::Acquire)
    }
}

impl Drop for ModeledControlBoundaryPublication<'_> {
    fn drop(&mut self) {
        // A substituted claim is never ours to clear, even in a fault fixture.
        let _ =
            self.word
                .compare_exchange(self.value.get(), 0, Ordering::Release, Ordering::Relaxed);
    }
}
