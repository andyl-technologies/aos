//! Challenge-bound publication request semantics and their canonical commitment.
//!
//! The request preimage carries the capability handle, logical cache resource,
//! publisher challenge, and every proposed plan field except the resulting
//! request commitment. It contains no signature. Construction hashes that
//! non-self-referential preimage and produces the exact inert plan it commits.
//! The controller must independently resolve authority and authenticate the
//! holder, and durably consume the challenge; this model does none of those.

#[cfg(test)]
mod tests;

use super::{
    InvalidPublisherDomainPlan, PublisherAuthorityBindings, PublisherDomainPlan,
    PublisherDomainPlanDraft, PublisherRequest, PublisherRequestCommitment, PublisherTarget,
};
use crate::{
    CapabilityId, ChannelBinding, FeatureRef, ObjectDescriptor, ObjectDigest, OperationId,
    PrincipalId, ProtocolVersion, PublicationReservationId, ResourceId,
};

/// Caps one canonical publisher admission request before decoding allocations.
///
/// The fixed v1 fields and at most 64 bounded feature references fit within
/// this ceiling. Carriers may impose a smaller bound but must not enlarge it.
pub const MAXIMUM_PUBLISHER_ADMISSION_REQUEST_BYTES: usize = 32 * 1024;

/// Carries a publisher-generated unpredictable challenge without proving freshness.
///
/// The live publisher must generate these 32 bytes from a cryptographic random
/// source. Parsing merely rejects the reserved all-zero sentinel. The authority
/// must durably bind each challenge to one publisher instance and exact request;
/// neither this type nor a signature prevents replay on its own.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublisherChallengeV1([u8; 32]);

impl PublisherChallengeV1 {
    /// Validates one challenge's exact bytes without authenticating its issuer.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero challenge.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidPublisherAdmissionRequest> {
        if bytes == [0; 32] {
            return Err(InvalidPublisherAdmissionRequest::UnspecifiedChallenge);
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact bytes in the canonical request preimage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Supplies the proposed object and holder bindings before request hashing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherAdmissionClaimV1 {
    /// Claimed holder, which the controller must authenticate independently.
    pub holder: PrincipalId,
    /// Claimed authenticated channel; never sufficient as its own proof.
    pub channel: ChannelBinding,
    /// Exact operation identity for durable replay and receipt matching.
    pub operation: OperationId,
    /// Reservation identity to resolve or allocate in the controller ledger.
    pub reservation: PublicationReservationId,
    /// Complete raw-content descriptor to materialize.
    pub content: ObjectDescriptor,
    /// Commitment identifying the controller-owned source-authorization record.
    pub source_authorization: ObjectDigest,
    /// Proposed payload-byte ceiling, not proof that capacity was reserved.
    pub maximum_bytes: u64,
}

/// Supplies untrusted proposed fields for one challenge-bound admission request.
///
/// Authority generations and validity are exact preconditions, not values the
/// caller can install. The controller must compare them with protected current
/// state and its trusted clock, constrain the interval to the capability and
/// policy interval, and retain the resulting decision before asking a signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherAdmissionRequestDraftV1 {
    /// Handle of the capability that the controller must look up, not a bearer grant.
    pub capability: CapabilityId,
    /// Logical resource identity whose project/cache mapping the controller resolves.
    pub cache_resource: ResourceId,
    /// Fresh publisher challenge to bind and consume durably at admission.
    pub challenge: PublisherChallengeV1,
    /// Proposed independently versioned publisher protocol.
    pub protocol_version: ProtocolVersion,
    /// Proposed exact receiving service execution and project disclosure domain.
    pub target: PublisherTarget,
    /// Object, holder, source, operation, and reservation preconditions.
    pub claim: PublisherAdmissionClaimV1,
    /// Expected authority configuration, which must be independently resolved.
    pub authority: PublisherAuthorityBindings,
    /// Inclusive proposed plan start as a Unix second.
    pub issued_seconds: i64,
    /// Exclusive proposed plan expiry as a Unix second.
    pub expires_seconds: i64,
    /// Strictly ordered required semantics, at most 64 supported features.
    pub required_features: Vec<FeatureRef>,
}

/// Binds a canonical admission preimage to the exact inert plan it describes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherAdmissionRequestV1 {
    capability: CapabilityId,
    cache_resource: ResourceId,
    challenge: PublisherChallengeV1,
    plan: PublisherDomainPlan,
}

impl PublisherAdmissionRequestV1 {
    /// Validates the proposed request and reconstructs its complete commitment.
    ///
    /// No input commitment is accepted. The resulting plan hashes every
    /// proposed field, capability handle, resource identity, and challenge using
    /// the canonical v1 request preimage. This proves consistency, not authority.
    ///
    /// # Errors
    ///
    /// Rejects zero capability/resource handles or any invalid publisher-plan
    /// field, including unknown semantics, malformed validity, and byte ceilings.
    pub fn new(
        draft: PublisherAdmissionRequestDraftV1,
    ) -> Result<Self, InvalidPublisherAdmissionRequest> {
        if draft.capability.as_bytes() == &[0; 16] {
            return Err(InvalidPublisherAdmissionRequest::UnspecifiedCapability);
        }
        if draft.cache_resource.as_bytes() == &[0; 16] {
            return Err(InvalidPublisherAdmissionRequest::UnspecifiedCacheResource);
        }
        // All other dynamic values have bounded validated element types. Check
        // collection cardinality before allocating the temporary hash preimage.
        if draft.required_features.len() > 64 {
            return Err(InvalidPublisherDomainPlan::InvalidFeatures.into());
        }
        let canonical = crate::format::encode_publisher_admission_draft_v1(&draft);
        if canonical.len() > MAXIMUM_PUBLISHER_ADMISSION_REQUEST_BYTES {
            return Err(InvalidPublisherAdmissionRequest::RequestTooLarge);
        }
        let commitment = PublisherRequestCommitment::for_canonical_bytes(&canonical);
        let claim = draft.claim;
        let plan = PublisherDomainPlan::new(PublisherDomainPlanDraft {
            protocol_version: draft.protocol_version,
            target: draft.target,
            request: PublisherRequest {
                holder: claim.holder,
                channel: claim.channel,
                operation: claim.operation,
                reservation: claim.reservation,
                content: claim.content,
                source_authorization: claim.source_authorization,
                commitment,
                maximum_bytes: claim.maximum_bytes,
            },
            authority: draft.authority,
            issued_seconds: draft.issued_seconds,
            expires_seconds: draft.expires_seconds,
            required_features: draft.required_features,
        })?;
        Ok(Self {
            capability: draft.capability,
            cache_resource: draft.cache_resource,
            challenge: draft.challenge,
            plan,
        })
    }

    /// Returns the capability handle that must be resolved by the controller.
    #[must_use]
    pub const fn capability(&self) -> CapabilityId {
        self.capability
    }

    /// Returns the logical cache resource, without asserting its domain mapping.
    #[must_use]
    pub const fn cache_resource(&self) -> ResourceId {
        self.cache_resource
    }

    /// Returns the challenge that must be bound to the live publisher instance.
    #[must_use]
    pub const fn challenge(&self) -> PublisherChallengeV1 {
        self.challenge
    }

    /// Returns the exact proposed plan with its reconstructed request commitment.
    #[must_use]
    pub const fn plan(&self) -> &PublisherDomainPlan {
        &self.plan
    }

    /// Checks that a separate plan commits this complete admission request.
    ///
    /// # Errors
    ///
    /// Rejects any plan field or commitment mismatch. Success neither
    /// authenticates the plan nor proves that its request was admitted.
    pub fn validate_plan_binding(
        &self,
        plan: &PublisherDomainPlan,
    ) -> Result<(), InvalidPublisherAdmissionRequest> {
        if plan != &self.plan {
            return Err(InvalidPublisherAdmissionRequest::PlanMismatch);
        }
        Ok(())
    }
}

/// Reports a malformed or inconsistent challenge-bound admission request.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidPublisherAdmissionRequest {
    /// The canonical preimage exceeds the fixed protocol packet ceiling.
    #[error("publisher admission request exceeds 32 KiB")]
    RequestTooLarge,
    /// The request omitted its capability lookup handle.
    #[error("publisher admission capability handle is unspecified")]
    UnspecifiedCapability,
    /// The request omitted its logical cache-resource lookup handle.
    #[error("publisher admission cache resource is unspecified")]
    UnspecifiedCacheResource,
    /// The publisher challenge uses the reserved all-zero sentinel.
    #[error("publisher admission challenge is unspecified")]
    UnspecifiedChallenge,
    /// The proposed plan violates the closed project publisher schema.
    #[error("publisher admission plan is invalid: {0}")]
    Plan(#[from] InvalidPublisherDomainPlan),
    /// A separately supplied plan does not commit the exact request.
    #[error("publisher admission plan binding differs")]
    PlanMismatch,
}
