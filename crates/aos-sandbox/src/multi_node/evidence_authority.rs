//! Private verifier authority for non-carrier multi-node evidence.
//!
//! Ownership, Guardian, storage, publication, drain, dependency, and liveness
//! integrations live below this module. Ordinary sibling modules only consume
//! singular grants and therefore cannot manufacture verifier outcomes from a
//! collection of otherwise plausible scalar fields.

use aos_sandbox_core::ObjectDigest;

use super::evidence::AuthenticatedEvidenceContextV1;

mod sealed {
    pub trait Sealed {}
}

/// Owns one authenticated verifier connection and its monotonic replay fence.
///
/// The constructor and issuance method are private so a future integration
/// must be a child of this authority module. The session is intentionally
/// neither `Clone` nor `Copy`.
struct EvidenceVerifierSessionV1 {
    verifier_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    next_issuance_sequence: u64,
    context: AuthenticatedEvidenceContextV1,
}

impl sealed::Sealed for EvidenceVerifierSessionV1 {}

/// Marks the private, non-implementable evidence-verifier authority.
trait EvidenceAuthorityV1: sealed::Sealed {
    fn verifier_domain_digest(&self) -> ObjectDigest;
    fn replay_fence(&self) -> ObjectDigest;
    fn context(&self) -> AuthenticatedEvidenceContextV1;
}

impl EvidenceAuthorityV1 for EvidenceVerifierSessionV1 {
    fn verifier_domain_digest(&self) -> ObjectDigest {
        self.verifier_domain_digest
    }
    fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }
    fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

impl EvidenceVerifierSessionV1 {
    fn from_verified_channel(
        verifier_domain_digest: ObjectDigest,
        replay_fence: ObjectDigest,
        next_issuance_sequence: u64,
        context: AuthenticatedEvidenceContextV1,
    ) -> Option<Self> {
        (verifier_domain_digest.as_bytes() != &[0; 32]
            && replay_fence.as_bytes() != &[0; 32]
            && next_issuance_sequence != 0)
            .then_some(Self {
                verifier_domain_digest,
                replay_fence,
                next_issuance_sequence,
                context,
            })
    }

    /// Issues a consumed grant after the child integration verifies `value`.
    fn issue_once<T>(&mut self, value: T) -> Option<VerifierEvidenceGrantV1<T>> {
        let issuance_sequence = self.next_issuance_sequence;
        self.next_issuance_sequence = self.next_issuance_sequence.checked_add(1)?;
        Some(VerifierEvidenceGrantV1 {
            value,
            verifier_domain_digest: EvidenceAuthorityV1::verifier_domain_digest(self),
            replay_fence: EvidenceAuthorityV1::replay_fence(self),
            issuance_sequence,
            context: EvidenceAuthorityV1::context(self),
        })
    }
}

/// Carries one opaque, singular verifier result into a model constructor.
///
/// It has no constructor outside this authority and intentionally implements
/// neither `Clone` nor `Copy`.
pub(super) struct VerifierEvidenceGrantV1<T> {
    value: T,
    verifier_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    issuance_sequence: u64,
    context: AuthenticatedEvidenceContextV1,
}

impl<T> VerifierEvidenceGrantV1<T> {
    pub(super) fn into_parts(
        self,
    ) -> (
        T,
        ObjectDigest,
        ObjectDigest,
        u64,
        AuthenticatedEvidenceContextV1,
    ) {
        (
            self.value,
            self.verifier_domain_digest,
            self.replay_fence,
            self.issuance_sequence,
            self.context,
        )
    }
}
