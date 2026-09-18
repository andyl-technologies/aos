//! Private verifier authority for non-carrier multi-node evidence.
//!
//! Ownership, Guardian, storage, publication, drain, dependency, and liveness
//! integrations live below this module. Ordinary sibling modules only consume
//! singular grants and therefore cannot manufacture verifier outcomes from a
//! collection of otherwise plausible scalar fields.

use aos_sandbox_core::ObjectDigest;

use super::evidence::AuthenticatedEvidenceContextV1;
use super::journal::{InvalidMultiNodeJournal, ProtectedJournalRecordV1};

mod sealed {
    pub trait Sealed {}
}

/// Owns one authenticated verifier connection and its monotonic replay fence.
///
/// The constructor and issuance method are private so its integration must be
/// a child of this authority module. The session is intentionally
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
            && replay_fence == context.replay_fence()
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

/// Owns one protected evidence receipt and its monotonic verifier session.
///
/// Construction consumes the protected row, so the same receipt cannot be
/// reused through this integration object to recreate an issuance sequence.
pub(super) struct ProtectedEvidenceIntegrationV1 {
    protected_record: ProtectedJournalRecordV1,
    session: EvidenceVerifierSessionV1,
}

impl ProtectedEvidenceIntegrationV1 {
    /// Opens the dormant verifier bridge from one authenticated protected row.
    pub(super) fn from_protected_record(
        protected_record: ProtectedJournalRecordV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let context = protected_record.context();
        let next_issuance_sequence = protected_record
            .durability_generation()
            .checked_add(1)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        if protected_record.storage_domain_digest().as_bytes() == &[0; 32]
            || protected_record.replay_fence() != context.replay_fence()
            || !context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let session = EvidenceVerifierSessionV1::from_verified_channel(
            protected_record.storage_domain_digest(),
            protected_record.replay_fence(),
            next_issuance_sequence,
            context,
        )
        .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        Ok(Self {
            protected_record,
            session,
        })
    }

    pub(super) fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.protected_record.context()
    }

    /// Issues one semantic value under the exact retained protected context.
    pub(super) fn issue_once<T>(
        &mut self,
        value: T,
        expected_context: AuthenticatedEvidenceContextV1,
        verified_at_unix_seconds: u64,
    ) -> Result<VerifierEvidenceGrantV1<T>, InvalidMultiNodeJournal> {
        if self.protected_record.context() != expected_context
            || self.protected_record.replay_fence() != expected_context.replay_fence()
            || !expected_context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        self.session
            .issue_once(value)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)
    }
}
