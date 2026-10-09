//! Opaque authenticated evidence contexts shared by multi-node reducers.
//!
//! Contexts commit exact carrier bytes, audience, boot lineage, and a bounded
//! verifier-currentness interval. Construction consumes a singular capability
//! whose fields are private to the protocol verifier, so neither public nor
//! sibling reducer code can mint authenticated observations from scalars.

use aos_sandbox_core::{NodeId, ObjectDigest};

use super::capability::NodeBootLineageV1;
use super::carrier_authority::CarrierEvidenceGrantV1;

/// Reports malformed authenticated observation context.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidEvidenceContext {
    /// A required digest, epoch, length, or currentness interval is invalid.
    #[error("authenticated evidence context is unspecified or not current")]
    Invalid,
}

/// Binds an opaque verifier result to exact carrier and audience facts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthenticatedEvidenceContextV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    verified_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    replay_fence: ObjectDigest,
}

impl AuthenticatedEvidenceContextV1 {
    /// Constructs a context by consuming the protocol verifier's singular capability.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEvidenceContext`] for zero commitments, lengths, or
    /// epochs, a node mismatch, or a nonpositive currentness interval.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authority_grant(
        grant: CarrierEvidenceGrantV1,
    ) -> Result<Self, InvalidEvidenceContext> {
        let node = grant.node();
        let lineage = grant.lineage();
        let audience_digest = grant.audience_digest();
        let disclosure_domain_digest = grant.disclosure_domain_digest();
        let carrier_binding_digest = grant.carrier_binding_digest();
        let canonical_frame_digest = grant.canonical_bytes_digest();
        let canonical_frame_bytes = grant.canonical_bytes();
        let coordinator_epoch = grant.coordinator_epoch();
        let verified_at_unix_seconds = grant.verified_at_unix_seconds();
        let valid_until_unix_seconds = grant.valid_until_unix_seconds();
        let replay_fence = grant.replay_fence();
        if node.as_bytes() == &[0; 16]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || carrier_binding_digest.as_bytes() == &[0; 32]
            || canonical_frame_digest.as_bytes() == &[0; 32]
            || canonical_frame_bytes == 0
            || coordinator_epoch == 0
            || replay_fence.as_bytes() == &[0; 32]
            || valid_until_unix_seconds <= verified_at_unix_seconds
        {
            return Err(InvalidEvidenceContext::Invalid);
        }
        Ok(Self {
            node,
            lineage,
            audience_digest,
            disclosure_domain_digest,
            carrier_binding_digest,
            canonical_frame_digest,
            canonical_frame_bytes,
            coordinator_epoch,
            verified_at_unix_seconds,
            valid_until_unix_seconds,
            replay_fence,
        })
    }

    /// Returns the authenticated node audience.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the exact durable node boot lineage.
    #[must_use]
    pub const fn lineage(self) -> NodeBootLineageV1 {
        self.lineage
    }

    /// Returns the authenticated audience commitment.
    #[must_use]
    pub const fn audience_digest(self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the authenticated disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the authenticated channel-binding commitment.
    #[must_use]
    pub const fn carrier_binding_digest(self) -> ObjectDigest {
        self.carrier_binding_digest
    }

    /// Returns the digest of exact canonical carrier bytes.
    #[must_use]
    pub const fn canonical_frame_digest(self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Returns the exact bounded carrier-frame length.
    #[must_use]
    pub const fn canonical_frame_bytes(self) -> u32 {
        self.canonical_frame_bytes
    }

    /// Returns the durable coordinator epoch.
    #[must_use]
    pub const fn coordinator_epoch(self) -> u64 {
        self.coordinator_epoch
    }

    /// Returns the verifier observation time bound to this context.
    #[must_use]
    pub const fn verified_at_unix_seconds(self) -> u64 {
        self.verified_at_unix_seconds
    }

    /// Returns the fail-closed currentness deadline bound to this context.
    #[must_use]
    pub const fn valid_until_unix_seconds(self) -> u64 {
        self.valid_until_unix_seconds
    }

    /// Returns the protected carrier verifier replay-fence commitment.
    #[must_use]
    pub const fn replay_fence(self) -> ObjectDigest {
        self.replay_fence
    }

    /// Reports whether this exact verifier observation remains current.
    #[must_use]
    pub fn is_current_at(self, coordinator_unix_seconds: u64) -> bool {
        coordinator_unix_seconds >= self.verified_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }
}
