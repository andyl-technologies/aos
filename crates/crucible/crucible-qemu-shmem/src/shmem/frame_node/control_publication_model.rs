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

/// A modeled node-state writer holding the publication seqlock odd.
///
/// Bounded host reads observe an unfinished plugin publication until the
/// fixture is dropped, which completes the generation without changing any
/// published field. It is absent unless the `test-support` feature is selected.
pub struct ModeledNodeStatePublication<'a> {
    generation: &'a AtomicU32,
}

impl NodeSlot {
    /// Begins a modeled node-state publication for a contention test.
    ///
    /// # Panics
    ///
    /// Panics if another writer already left the generation odd, because the
    /// fixture would otherwise complete a publication it does not own.
    #[must_use]
    pub fn begin_node_state_publication_for_test(&self) -> ModeledNodeStatePublication<'_> {
        let previous = self.publish_gen.fetch_add(1, Ordering::AcqRel);
        assert!(
            previous.is_multiple_of(2),
            "node state publication already in progress"
        );
        ModeledNodeStatePublication {
            generation: &self.publish_gen,
        }
    }
}

impl Drop for ModeledNodeStatePublication<'_> {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
}
