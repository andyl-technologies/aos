//! Nonforgeable authenticated provenance for resolved requests and audit reads.

use std::fmt;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::requests::ResolvedPublicMutationV1;
use crate::controller_query::model::{
    AuthorizationRevisionDigestV1, ObservationSchemaDigestV1, QueryPrincipalDigestV1,
};

/// Maximum canonical request bytes admitted to authenticated provenance.
pub const MAXIMUM_CANONICAL_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Reports invalid authenticated request provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidRequestProvenance {
    /// Canonical bytes are empty or exceed their fixed ceiling.
    #[error("canonical request bytes are invalid")]
    InvalidCanonicalRequest,
    /// The resolved action does not carry its exact required fence kind.
    #[error("resolved mutation fence does not match its action")]
    InvalidMutationFence,
}

/// Commits bounded canonical request bytes inside the authenticated adapter.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalRequestDigestV1(ObjectDigest);

impl CanonicalRequestDigestV1 {
    /// Commits bytes only after the authenticated adapter has canonicalized them.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRequestProvenance`] for empty or oversized bytes.
    pub(crate) fn from_authenticated_canonical(
        bytes: &[u8],
    ) -> Result<Self, InvalidRequestProvenance> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_CANONICAL_REQUEST_BYTES {
            return Err(InvalidRequestProvenance::InvalidCanonicalRequest);
        }
        Ok(Self(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.cli.canonical-request.v1\0")
                .chain_update((bytes.len() as u64).to_be_bytes())
                .chain_update(bytes)
                .finalize()
                .into(),
        )))
    }

    /// Returns the authenticated canonical request commitment.
    #[must_use]
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Commits the closed typed meaning decoded from authenticated request bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthenticatedRequestSemanticsDigestV1(ObjectDigest);

impl AuthenticatedRequestSemanticsDigestV1 {
    /// Constructs a semantic commitment inside the closed request decoder.
    #[must_use]
    pub(crate) const fn from_decoded(digest: ObjectDigest) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for AuthenticatedRequestSemanticsDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedRequestSemanticsDigestV1(<redacted>)")
    }
}

impl fmt::Debug for CanonicalRequestDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalRequestDigestV1(<redacted>)")
    }
}

/// Binds a resolved request to authentication, authorization, schema, and bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RequestProvenanceV1 {
    principal: QueryPrincipalDigestV1,
    authorization: AuthorizationRevisionDigestV1,
    schema: ObservationSchemaDigestV1,
    normalized_request: CanonicalRequestDigestV1,
    semantics: AuthenticatedRequestSemanticsDigestV1,
}

impl RequestProvenanceV1 {
    /// Constructs provenance only inside the authenticated request adapter.
    pub(crate) const fn from_authenticated(
        principal: QueryPrincipalDigestV1,
        authorization: AuthorizationRevisionDigestV1,
        schema: ObservationSchemaDigestV1,
        normalized_request: CanonicalRequestDigestV1,
        semantics: AuthenticatedRequestSemanticsDigestV1,
    ) -> Self {
        Self {
            principal,
            authorization,
            schema,
            normalized_request,
            semantics,
        }
    }

    /// Returns all authenticated commitments to an internal transport adapter.
    #[must_use]
    pub(crate) const fn commitments(
        self,
    ) -> (
        QueryPrincipalDigestV1,
        AuthorizationRevisionDigestV1,
        ObservationSchemaDigestV1,
        CanonicalRequestDigestV1,
        AuthenticatedRequestSemanticsDigestV1,
    ) {
        (
            self.principal,
            self.authorization,
            self.schema,
            self.normalized_request,
            self.semantics,
        )
    }
}

impl fmt::Debug for RequestProvenanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestProvenanceV1(<redacted>)")
    }
}

/// Stores a resolved mutation that cannot exist without authenticated provenance.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedResolvedMutationV1 {
    mutation: ResolvedPublicMutationV1,
    provenance: RequestProvenanceV1,
}

impl AuthorizedResolvedMutationV1 {
    /// Couples a request to provenance inside the authenticated adapter.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRequestProvenance::InvalidMutationFence`] when an
    /// incarnation or plan fence is missing, forbidden, or mismatched.
    pub(crate) fn from_authenticated(
        mutation: ResolvedPublicMutationV1,
        provenance: RequestProvenanceV1,
    ) -> Result<Self, InvalidRequestProvenance> {
        if !mutation.has_action_specific_fences() {
            return Err(InvalidRequestProvenance::InvalidMutationFence);
        }
        Ok(Self {
            mutation,
            provenance,
        })
    }

    /// Returns the lossless resolved mutation.
    #[must_use]
    pub const fn mutation(&self) -> &ResolvedPublicMutationV1 {
        &self.mutation
    }

    /// Returns authenticated request provenance to an internal request adapter.
    #[must_use]
    pub(crate) const fn provenance(&self) -> RequestProvenanceV1 {
        self.provenance
    }
}

/// Proves audit-read authorization without exposing a public constructor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuditAuthorizationV1(RequestProvenanceV1);

impl AuditAuthorizationV1 {
    /// Derives audit authorization inside the authenticated request adapter.
    pub(crate) const fn from_authorized(provenance: RequestProvenanceV1) -> Self {
        Self(provenance)
    }

    /// Returns authenticated provenance to the internal audit transport.
    #[must_use]
    pub(crate) const fn provenance(self) -> RequestProvenanceV1 {
        self.0
    }
}

impl fmt::Debug for AuditAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditAuthorizationV1(<redacted>)")
    }
}
