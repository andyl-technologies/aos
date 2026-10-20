//! Node capability snapshots and carrier-authenticated scheduling observations.
//!
//! A snapshot is a bounded observation made by one node boot. It is scheduling
//! input only: accepting a snapshot cannot create an assignment, reserve
//! controller capacity, or grant ownership. Authentication and freshness at
//! the carrier boundary remain responsibilities of the coordinator-to-node
//! protocol implementation.
//!
//! Explicitly selected placement candidates retain these sealed observations
//! here so protected inventory does not depend on the placement implementation.

#[cfg(feature = "multi-node")]
mod placement_candidate;

#[cfg(feature = "multi-node")]
pub use placement_candidate::PlacementCandidateV1;

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{NodeId, ObjectDigest, ObservationSequence};

use super::carrier_authority::AuthenticatedFrameSealV1;
use super::evidence::AuthenticatedEvidenceContextV1;

use aos_sandbox_core::{InvalidNodeCapability, NodeCapabilitySnapshotV1};

/// Marks a capability snapshot whose exact carrier frame was authenticated.
///
/// Construction is crate-private so scheduling cannot consume a raw decoded
/// snapshot. The marker remains observation evidence and grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarrierValidatedCapabilityObservationV1 {
    snapshot: NodeCapabilitySnapshotV1,
    audience_node: NodeId,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    replay_fence: ObjectDigest,
}

impl CarrierValidatedCapabilityObservationV1 {
    /// Marks one snapshot after exact carrier authentication and canonical decoding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability::InvalidProbeEvidence`] if either
    /// carrier or canonical observation commitment is zero.
    pub(super) fn from_authenticated_carrier(
        snapshot: NodeCapabilitySnapshotV1,
        context: AuthenticatedEvidenceContextV1,
        frame_seal: &AuthenticatedFrameSealV1,
        canonical_body_digest: ObjectDigest,
    ) -> Result<Self, InvalidNodeCapability> {
        let audience_node = context.node();
        let audience_digest = context.audience_digest();
        let disclosure_domain_digest = context.disclosure_domain_digest();
        let carrier_binding_digest = context.carrier_binding_digest();
        let canonical_frame_digest = context.canonical_frame_digest();
        let canonical_frame_bytes = context.canonical_frame_bytes();
        let coordinator_epoch = context.coordinator_epoch();
        let authenticated_at_unix_seconds = context.verified_at_unix_seconds();
        let valid_until_unix_seconds = context.valid_until_unix_seconds();
        let replay_fence = context.replay_fence();
        if snapshot.node() != audience_node
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || carrier_binding_digest.as_bytes() == &[0; 32]
            || canonical_frame_digest.as_bytes() == &[0; 32]
            || canonical_frame_bytes == 0
            || coordinator_epoch == 0
            || replay_fence.as_bytes() == &[0; 32]
            || valid_until_unix_seconds <= authenticated_at_unix_seconds
            || context.lineage() != snapshot.lineage()
            || !(frame_seal.matches(
                aos_sandbox_core::CanonicalNodeFrameKindV1::GetCapabilitiesResponse,
                canonical_body_digest,
                context,
            ) || frame_seal.matches(
                aos_sandbox_core::CanonicalNodeFrameKindV1::WatchResponse,
                canonical_body_digest,
                context,
            ))
        {
            return Err(InvalidNodeCapability::InvalidProbeEvidence);
        }
        Ok(Self {
            snapshot,
            audience_node,
            audience_digest,
            disclosure_domain_digest,
            carrier_binding_digest,
            canonical_frame_digest,
            canonical_frame_bytes,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            replay_fence,
        })
    }

    /// Returns the validated capability semantics.
    #[must_use]
    pub const fn snapshot(&self) -> &NodeCapabilitySnapshotV1 {
        &self.snapshot
    }

    /// Returns the authenticated carrier binding commitment.
    #[must_use]
    pub const fn carrier_binding_digest(&self) -> ObjectDigest {
        self.carrier_binding_digest
    }

    /// Returns the exact authenticated node audience.
    #[must_use]
    pub const fn audience_node(&self) -> NodeId {
        self.audience_node
    }

    /// Returns the authenticated disclosure/audience commitment.
    #[must_use]
    pub const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the authenticated disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the digest of exact canonical carrier bytes.
    #[must_use]
    pub const fn canonical_observation_digest(&self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Returns the exact bounded canonical carrier length.
    #[must_use]
    pub const fn canonical_frame_bytes(&self) -> u32 {
        self.canonical_frame_bytes
    }

    /// Returns the coordinator epoch that authenticated this observation.
    #[must_use]
    pub const fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }

    /// Returns the authenticated carrier receipt time.
    #[must_use]
    pub const fn authenticated_at_unix_seconds(&self) -> u64 {
        self.authenticated_at_unix_seconds
    }

    /// Returns the fail-closed currentness deadline.
    #[must_use]
    pub const fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }

    /// Returns the protected carrier verifier replay-fence commitment.
    #[must_use]
    pub const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }

    /// Reports whether carrier currentness holds at an exact coordinator time.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        coordinator_unix_seconds >= self.authenticated_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    /// Returns a commitment to the complete placement observation identity and currentness.
    ///
    /// This binds the semantic snapshot, durable boot lineage, exact carrier,
    /// audience, disclosure domain, coordinator epoch, and verifier interval.
    /// Assignment acceptance records use it to prevent a current assignment
    /// from being paired with a different or expired placement observation.
    #[must_use]
    pub fn evidence_binding_digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.node-capability.evidence-binding.v1\0");
        hasher.update(self.snapshot.node().as_bytes());
        hasher.update(self.snapshot.boot().as_bytes());
        hasher.update(self.snapshot.boot_generation().to_be_bytes());
        hasher.update(self.snapshot.lineage().digest().as_bytes());
        hasher.update(self.snapshot.sequence().get().to_be_bytes());
        hasher.update(self.audience_node.as_bytes());
        hasher.update(self.audience_digest.as_bytes());
        hasher.update(self.disclosure_domain_digest.as_bytes());
        hasher.update(self.carrier_binding_digest.as_bytes());
        hasher.update(self.canonical_frame_digest.as_bytes());
        hasher.update(self.canonical_frame_bytes.to_be_bytes());
        hasher.update(self.coordinator_epoch.to_be_bytes());
        hasher.update(self.authenticated_at_unix_seconds.to_be_bytes());
        hasher.update(self.valid_until_unix_seconds.to_be_bytes());
        hasher.update(self.replay_fence.as_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}
