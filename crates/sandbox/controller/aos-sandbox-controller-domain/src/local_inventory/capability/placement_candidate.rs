//! Sealed capability observations retained as non-authorizing placement input.
//!
//! The protected store constructs these values after validating its current
//! capability projection. Remote placement consumes the same observations and
//! immutable receipt times without owning their construction or lease clocks.

use super::{CarrierValidatedCapabilityObservationV1, NodeCapabilitySnapshotV1};

/// Couples one node snapshot to its authenticated controller receipt time.
///
/// Receipt time is placement freshness evidence and is deliberately outside
/// the node snapshot's sequence identity. It is not an ownership lease clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementCandidateV1 {
    observation: CarrierValidatedCapabilityObservationV1,
}

impl PlacementCandidateV1 {
    /// Constructs one candidate after authenticated snapshot receipt.
    #[must_use]
    pub(in crate::local_inventory) fn from_authenticated_observation(
        observation: CarrierValidatedCapabilityObservationV1,
    ) -> Self {
        Self { observation }
    }

    /// Returns the complete node capability snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &NodeCapabilitySnapshotV1 {
        self.observation.snapshot()
    }

    /// Returns the opaque carrier-validated observation.
    #[must_use]
    pub const fn observation(&self) -> &CarrierValidatedCapabilityObservationV1 {
        &self.observation
    }

    /// Returns the controller-recorded authenticated receipt time.
    #[must_use]
    pub const fn received_at_unix_seconds(&self) -> u64 {
        self.observation.authenticated_at_unix_seconds()
    }
}
