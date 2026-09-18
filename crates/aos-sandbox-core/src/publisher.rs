//! Project-domain publication plans independent of sandbox assignments.
//!
//! A plan commits one request and its expected authority configuration. Decoding
//! or authenticating it does not authorize filesystem effects. Online admission
//! must resolve current controller state; final naming additionally requires a
//! durably retained completion permit. In particular, checking these generation
//! numbers against caller-supplied numbers is not revocation validation.
//!
//! The v1 publisher accepts raw content within one project domain. Publishing
//! publicly, building a tree, and reading cached data are different authorities.

mod request;
mod verification;

#[cfg(test)]
mod tests;

pub use request::{
    InvalidPublisherAdmissionRequest, MAXIMUM_PUBLISHER_ADMISSION_REQUEST_BYTES,
    PublisherAdmissionClaimV1, PublisherAdmissionRequestDraftV1, PublisherAdmissionRequestV1,
    PublisherChallengeV1,
};
pub use verification::{
    PublisherPlanExpectation, PublisherPlanTrustAnchor, PublisherPlanVerificationError,
    VerifiedPublisherDomainPlan, verify_publisher_domain_plan,
};

use crate::model::{CacheDomain, CacheDomainKind};
use crate::{
    ChannelBinding, FeatureRef, NodeId, ObjectDescriptor, ObjectDigest, OperationId,
    PortableMediaType, PrincipalId, ProjectId, ProtocolId, ProtocolVersion,
    PublicationReservationId, PublisherInstanceId, RegistryError, RevocationScopeId,
};

/// Binds one publisher execution to its configured project disclosure domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherTarget {
    /// Service principal independently authenticated by the controller.
    pub principal: PrincipalId,
    /// Fresh identity for this publisher execution, not a sandbox incarnation.
    pub instance: PublisherInstanceId,
    /// Node hosting the publisher execution.
    pub node: NodeId,
    /// Project whose publication authority is being exercised.
    pub project: ProjectId,
    /// Exact project cache domain; directories alone do not establish isolation.
    pub cache_domain: CacheDomain,
    /// Commitment to the configured backing and timing isolation policy revision.
    pub isolation_policy: ObjectDigest,
}

/// Commits one bounded raw-content request without retaining producer bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherRequest {
    /// Capability holder authenticated independently of its claimed request.
    pub holder: PrincipalId,
    /// Authenticated transport channel binding for this holder.
    pub channel: ChannelBinding,
    /// Exact operation used for controller-owned idempotency and receipts.
    pub operation: OperationId,
    /// Retained reservation charged through uncertain effects and residency.
    pub reservation: PublicationReservationId,
    /// Complete descriptor, including media type and exact encoded byte count.
    pub content: ObjectDescriptor,
    /// Commitment to controller-resolved authorization for the source bytes.
    pub source_authorization: ObjectDigest,
    /// Domain-separated commitment to the full canonical request semantics.
    pub commitment: PublisherRequestCommitment,
    /// Maximum materialized payload bytes; filesystem overhead is charged separately.
    pub maximum_bytes: u64,
}

/// Records exact authority generations expected by a publication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherAuthorityBindings {
    /// Commitment to the effective publication policy.
    pub policy: ObjectDigest,
    /// Monotonic generation of that policy.
    pub policy_generation: u64,
    /// Monotonic controller-authority generation, independent of signing keys.
    pub controller_generation: u64,
    /// Controller-managed revocation domain.
    pub revocation_scope: RevocationScopeId,
    /// Expected revocation generation; static equality is not online freshness.
    pub revocation_generation: u64,
    /// Trusted root-registry generation selecting the publication root.
    pub root_registry_generation: u64,
}

/// Supplies unvalidated fields for one immutable publisher-domain plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherDomainPlanDraft {
    /// Independently negotiated publisher-authority protocol version.
    pub protocol_version: ProtocolVersion,
    /// Exact receiving service execution and project domain.
    pub target: PublisherTarget,
    /// Exact holder, operation, object, source authority, and reservation.
    pub request: PublisherRequest,
    /// Expected controller configuration, not proof that it is current.
    pub authority: PublisherAuthorityBindings,
    /// Inclusive Unix-second start of the static plan validity interval.
    pub issued_seconds: i64,
    /// Exclusive Unix-second end; this does not cancel retained completion permits.
    pub expires_seconds: i64,
    /// Strictly increasing supported feature references, at most 64.
    pub required_features: Vec<FeatureRef>,
}

/// Stores a structurally validated, inert publication request commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherDomainPlan(PublisherDomainPlanDraft);

impl PublisherDomainPlan {
    /// Validates and seals the fields of a project-only raw-content plan.
    ///
    /// # Errors
    ///
    /// Rejects zero authority identities, generations or commitments, another
    /// disclosure class or content media type, an unrepresentable file size,
    /// insufficient byte ceiling, unsupported protocol/features, noncanonical
    /// feature order, and empty or inverted validity intervals.
    pub fn new(draft: PublisherDomainPlanDraft) -> Result<Self, InvalidPublisherDomainPlan> {
        let target = &draft.target;
        let request = &draft.request;
        let authority = &draft.authority;
        for (field, bytes) in [
            ("publisher principal", target.principal.as_bytes()),
            ("publisher instance", target.instance.as_bytes()),
            ("node", target.node.as_bytes()),
            ("project", target.project.as_bytes()),
            ("cache domain", target.cache_domain.domain_id().as_bytes()),
            ("holder", request.holder.as_bytes()),
            ("operation", request.operation.as_bytes()),
            ("reservation", request.reservation.as_bytes()),
            ("revocation scope", authority.revocation_scope.as_bytes()),
        ] {
            if bytes == &[0; 16] {
                return Err(InvalidPublisherDomainPlan::Unspecified { field });
            }
        }
        for (field, digest) in [
            ("isolation policy", target.isolation_policy),
            ("source authorization", request.source_authorization),
            ("policy", authority.policy),
        ] {
            if digest.as_bytes() == &[0; 32] {
                return Err(InvalidPublisherDomainPlan::Unspecified { field });
            }
        }
        if request.channel.as_bytes() == &[0; 32] {
            return Err(InvalidPublisherDomainPlan::Unspecified { field: "channel" });
        }
        for (field, generation) in [
            ("policy generation", authority.policy_generation),
            ("controller generation", authority.controller_generation),
            ("revocation generation", authority.revocation_generation),
            (
                "root registry generation",
                authority.root_registry_generation,
            ),
        ] {
            if generation == 0 {
                return Err(InvalidPublisherDomainPlan::Unspecified { field });
            }
        }

        if target.cache_domain.kind() != CacheDomainKind::Project {
            return Err(InvalidPublisherDomainPlan::NotProjectDomain);
        }
        if request.content.media_type().as_str() != PortableMediaType::Content.as_str() {
            return Err(InvalidPublisherDomainPlan::NotRawContent);
        }
        // File offsets must remain representable by the materializer, including
        // on an otherwise valid wire carrying the full unsigned CBOR range.
        if request.maximum_bytes > i64::MAX as u64
            || request.content.encoded_size() > request.maximum_bytes
        {
            return Err(InvalidPublisherDomainPlan::InvalidByteCeiling);
        }
        crate::negotiate_protocol(ProtocolId::PublisherAuthority, draft.protocol_version)?;
        if draft.issued_seconds >= draft.expires_seconds {
            return Err(InvalidPublisherDomainPlan::InvalidValidity);
        }
        if draft.required_features.len() > 64
            || draft
                .required_features
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(InvalidPublisherDomainPlan::InvalidFeatures);
        }
        crate::validate_required_features(&draft.required_features)?;
        Ok(Self(draft))
    }

    /// Borrows all validated fields without allowing mutation of the plan.
    #[must_use]
    pub const fn fields(&self) -> &PublisherDomainPlanDraft {
        &self.0
    }
}

/// Commits canonical publication semantics in a dedicated hash domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublisherRequestCommitment(ObjectDigest);

impl PublisherRequestCommitment {
    /// Hashes a separately encoded canonical request preimage in its own domain.
    ///
    /// The preimage excludes this commitment and detached signatures; it is not
    /// the complete publisher plan encoding. This helper does not validate the
    /// preimage schema or establish source authorization. The typed
    /// [`PublisherAdmissionRequestV1`] constructor reconstructs the v1 preimage;
    /// online admission must independently authorize all of its claims.
    #[must_use]
    pub fn for_canonical_bytes(bytes: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};

        let mut hash = Sha256::new();
        hash.update(b"aos-sandbox-publisher-request-v1\0");
        hash.update(bytes);
        Self(ObjectDigest::from_bytes(hash.finalize().into()))
    }

    /// Validates a decoded commitment without authenticating its source.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero commitment.
    pub fn from_digest(digest: ObjectDigest) -> Result<Self, InvalidPublisherDomainPlan> {
        if digest.as_bytes() == &[0; 32] {
            return Err(InvalidPublisherDomainPlan::Unspecified {
                field: "request commitment",
            });
        }
        Ok(Self(digest))
    }

    /// Returns the committed digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Reports a malformed or unsupported publisher-domain plan.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidPublisherDomainPlan {
    /// A mandatory authority identity, commitment, or generation is zero.
    #[error("publisher plan has unspecified {field}")]
    Unspecified {
        /// Semantic field containing the reserved sentinel.
        field: &'static str,
    },
    /// The first publisher protocol does not authorize other disclosure classes.
    #[error("publisher plan requires an explicit project cache domain")]
    NotProjectDomain,
    /// A tree, provenance record, or another object cannot substitute for content.
    #[error("publisher plan requires the registered raw content media type")]
    NotRawContent,
    /// The object exceeds its signed or representable materialization ceiling.
    #[error("publisher plan byte ceiling is invalid")]
    InvalidByteCeiling,
    /// The static validity interval is empty or inverted.
    #[error("publisher plan validity interval is empty or inverted")]
    InvalidValidity,
    /// The feature list exceeds its ceiling or is not strictly ordered.
    #[error("publisher plan feature list is not canonical or exceeds 64 entries")]
    InvalidFeatures,
    /// A required feature or protocol version is unsupported.
    #[error("publisher plan registry validation failed: {0}")]
    Registry(#[from] RegistryError),
}
