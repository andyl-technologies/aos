//! Protected Cache record selection and session-branded reducer inputs.
//!
//! Requests select bounded authority keys; records remain tied to the
//! session that authenticated them. Construction stays with the Cache owner.

use super::{
    CacheAtomicObjectPayloadV1, CacheAuthorityError, CacheAuthorityPurposeV1,
    CacheResidencyProtectedRecordKindV1,
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
    authority_record: aos_sandbox_model::ObjectDigest,
    session: std::marker::PhantomData<&'session ()>,
}

impl<'session> CacheResidencyControllerRecordV1<'session> {
    pub(super) fn from_authority(
        kind: CacheResidencyProtectedRecordKindV1,
        payload: CacheAtomicObjectPayloadV1,
        authority_record: aos_sandbox_model::ObjectDigest,
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
        aos_sandbox_model::ObjectDigest,
    ) {
        (self.kind, self.payload, self.authority_record)
    }
}
