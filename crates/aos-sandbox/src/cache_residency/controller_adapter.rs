//! Dormant controller-result conversion for cache residency.
//!
//! Conversion consumes the exact-readback result. It does not dispatch an
//! effect or publish a catalog; callers must explicitly consume the returned
//! one-shot capability in a future activated controller path.

use super::{
    AppliedCacheResidencyTransactionV1, CacheAtomicObjectPayloadV1, CacheAuthorityError,
    CacheAuthorityPurposeV1, CacheResidencyPostcommitCapabilityV1,
    CacheResidencyProtectedRecordKindV1, CacheResidencyTransactionKindV1,
};

/// Selects one exact protected authority record for an owner-scoped operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheResidencyAuthorityRequestV1 {
    purpose: CacheAuthorityPurposeV1,
    record_key: Vec<u8>,
}

impl CacheResidencyAuthorityRequestV1 {
    /// Selects a bounded protected record without exposing its capability.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAuthorityError::InvalidScope`] for an empty or oversized key.
    pub fn new(
        purpose: CacheAuthorityPurposeV1,
        record_key: Vec<u8>,
    ) -> Result<Self, CacheAuthorityError> {
        if record_key.is_empty() || record_key.len() > 1024 {
            return Err(CacheAuthorityError::InvalidScope);
        }
        Ok(Self {
            purpose,
            record_key,
        })
    }

    pub(crate) const fn purpose(&self) -> CacheAuthorityPurposeV1 {
        self.purpose
    }

    pub(crate) fn record_key(&self) -> &[u8] {
        &self.record_key
    }
}

/// Carries one authority-branded typed reducer record.
///
/// Only the fixed owner's session sealer can construct this value. Its brand
/// prevents a record from escaping the authority claim that authenticated it.
pub struct CacheResidencyControllerRecordV1<'session> {
    kind: CacheResidencyProtectedRecordKindV1,
    payload: CacheAtomicObjectPayloadV1,
    authority_record: aos_sandbox_core::ObjectDigest,
    session: std::marker::PhantomData<&'session ()>,
}

impl<'session> CacheResidencyControllerRecordV1<'session> {
    pub(super) fn from_authority(
        kind: CacheResidencyProtectedRecordKindV1,
        payload: CacheAtomicObjectPayloadV1,
        authority_record: aos_sandbox_core::ObjectDigest,
    ) -> Self {
        Self {
            kind,
            payload,
            authority_record,
            session: std::marker::PhantomData,
        }
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        CacheResidencyProtectedRecordKindV1,
        CacheAtomicObjectPayloadV1,
        aos_sandbox_core::ObjectDigest,
    ) {
        (self.kind, self.payload, self.authority_record)
    }
}

/// Carries the closed controller-visible result of one durable cache transaction.
#[must_use = "cache controller authority must be consumed or deliberately discarded"]
pub struct CacheResidencyControllerCommitV1 {
    kind: CacheResidencyTransactionKindV1,
    postcommit: Option<CacheResidencyPostcommitCapabilityV1>,
}

impl CacheResidencyControllerCommitV1 {
    /// Returns the semantic transition committed by the adapter.
    #[must_use]
    pub const fn kind(&self) -> CacheResidencyTransactionKindV1 {
        self.kind
    }

    /// Takes the composite capability for one exact journal revalidation.
    #[must_use]
    pub fn take_postcommit(&mut self) -> Option<CacheResidencyPostcommitCapabilityV1> {
        self.postcommit.take()
    }
}

/// Converts exact journal readback into dormant controller capabilities.
#[must_use]
pub fn cache_residency_controller_commit_v1(
    mut applied: AppliedCacheResidencyTransactionV1,
) -> CacheResidencyControllerCommitV1 {
    CacheResidencyControllerCommitV1 {
        kind: applied.kind(),
        postcommit: applied.take_postcommit(),
    }
}
