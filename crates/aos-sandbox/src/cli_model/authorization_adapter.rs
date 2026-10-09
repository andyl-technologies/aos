//! Dormant authenticated request and authorization binding for CLI integration.
//!
//! This module is crate-visible so a future controller transport can hand its
//! independently authenticated observations to one common binding path. It
//! registers no command, route, service, or effect. Its evidence constructors
//! are not public API: untrusted request fields and caller-supplied digests are
//! not authentication evidence.

use std::collections::BTreeMap;

use aos_sandbox_core::{
    AuthorizationContext, CLOCK_PAIR_TOLERANCE_NANOSECONDS, CapabilityId, ChannelBinding,
    ObjectDigest, Operation, PrincipalId, ProjectId, RawPairedClockSample, ResourceKind, Selector,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::provenance::{
    AuditAuthorizationV1, AuthenticatedRequestSemanticsDigestV1, AuthorizedResolvedMutationV1,
    CanonicalRequestDigestV1, InvalidRequestProvenance, RequestProvenanceV1,
};
use super::requests::ResolvedPublicMutationV1;
use aos_sandbox_protocol::public_api::model::{
    AuthorizationRevisionDigestV1,
    ObservationSchemaDigestV1,
    QueryPrincipalDigestV1,
};
use crate::publisher_authority::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const MAXIMUM_AUTHENTICATED_EVIDENCE_BYTES: usize = 64 * 1024;
const IDENTITY_EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.cli.authenticated-identity.v1\0";
const SESSION_EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.cli.authenticated-session.v1\0";
const CHANNEL_EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.cli.authenticated-channel.v1\0";
const REQUEST_SEMANTICS_DOMAIN: &[u8] = b"aos.sandbox.cli.request-semantics.v1\0";
const CANONICAL_AUTHORIZATION_REQUEST_VERSION_V1: u16 = 1;
const CANONICAL_AUTHORIZATION_REQUEST_VERSION_V2: u16 = 2;
const TIME_FLOOR_REVISION_MAGIC: &[u8; 8] = b"AOSCTFR1";
const TIME_FLOOR_HEAD_MAGIC: &[u8; 8] = b"AOSCTFH1";
const TIME_FLOOR_CURRENT_KEY: &[u8] = b"cli-authorization-time/current";
const TIME_FLOOR_REVISION_PREFIX: &[u8] = b"cli-authorization-time/revision/";
const TIME_FLOOR_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.cli.authorization-time-floor.v1\0";
const TIME_FLOOR_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.cli.authorization-time-floor-transaction.v1\0";

#[cfg(test)]
#[path = "authorization_adapter/decision_tests.rs"]
mod decision_tests;

/// Selects the single authority surface admitted by protected authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CliAuthorizedSurfaceV1 {
    /// Permits construction of one resolved mutation authority.
    Mutation,
    /// Permits construction of one audit-read authority.
    AuditRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CliAuthorizedSurfaceWireV1 {
    Mutation,
    AuditRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum OperationWireV1 {
    Discover,
    MetadataRead,
    ContentRead,
    Execute,
    Create,
    ContentWrite,
    Remove,
    Rename,
    Link,
    MetadataWrite,
    Attach,
    LifecycleControl,
    Delegate,
    Publish,
    LiveKernelCoupledRead,
}

impl From<OperationWireV1> for Operation {
    fn from(value: OperationWireV1) -> Self {
        match value {
            OperationWireV1::Discover => Self::Discover,
            OperationWireV1::MetadataRead => Self::MetadataRead,
            OperationWireV1::ContentRead => Self::ContentRead,
            OperationWireV1::Execute => Self::Execute,
            OperationWireV1::Create => Self::Create,
            OperationWireV1::ContentWrite => Self::ContentWrite,
            OperationWireV1::Remove => Self::Remove,
            OperationWireV1::Rename => Self::Rename,
            OperationWireV1::Link => Self::Link,
            OperationWireV1::MetadataWrite => Self::MetadataWrite,
            OperationWireV1::Attach => Self::Attach,
            OperationWireV1::LifecycleControl => Self::LifecycleControl,
            OperationWireV1::Delegate => Self::Delegate,
            OperationWireV1::Publish => Self::Publish,
            OperationWireV1::LiveKernelCoupledRead => Self::LiveKernelCoupledRead,
        }
    }
}

impl From<Operation> for OperationWireV1 {
    fn from(value: Operation) -> Self {
        match value {
            Operation::Discover => Self::Discover,
            Operation::MetadataRead => Self::MetadataRead,
            Operation::ContentRead => Self::ContentRead,
            Operation::Execute => Self::Execute,
            Operation::Create => Self::Create,
            Operation::ContentWrite => Self::ContentWrite,
            Operation::Remove => Self::Remove,
            Operation::Rename => Self::Rename,
            Operation::Link => Self::Link,
            Operation::MetadataWrite => Self::MetadataWrite,
            Operation::Attach => Self::Attach,
            Operation::LifecycleControl => Self::LifecycleControl,
            Operation::Delegate => Self::Delegate,
            Operation::Publish => Self::Publish,
            Operation::LiveKernelCoupledRead => Self::LiveKernelCoupledRead,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCliAuthorizationRequestWireV1 {
    version: u16,
    surface: CliAuthorizedSurfaceWireV1,
    resource_kind: ResourceKind,
    operation: OperationWireV1,
    selector: Selector,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutation_identity_fence: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_rpc: Option<CanonicalPublicRpcBindingWireV1>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPublicRpcBindingWireV1 {
    method: PublicApiAuditMethodV1,
    body_sha256: [u8; 32],
}

pub use aos_sandbox_protocol::public_api::method::PublicApiAuditMethodV1;

/// Constructs a canonical mutation authorization envelope for one exact public RPC.
///
/// The mutation fence is a purpose-separated commitment to the method and exact
/// protobuf body. Endpoint compilers must still decode the body, validate every
/// typed concurrency field, and derive broker-specific requests.
///
/// # Errors
///
/// Returns [`CliAuthorizationAdapterError`] for empty or oversized bodies or
/// canonical serialization failure.
pub(crate) fn canonical_public_mutation_request_v2(
    method: PublicApiAuditMethodV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: Selector,
    protobuf_body: &[u8],
) -> Result<(Vec<u8>, ObjectDigest), CliAuthorizationAdapterError> {
    let protobuf_body = checked_authenticated_bytes(protobuf_body)?;
    let mutation_fence =
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.public-mutation-fence.v1\0")
                .chain_update(serde_json::to_vec(&method).map_err(|_| {
                    CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest
                })?)
                .chain_update(Sha256::digest(protobuf_body))
                .finalize()
                .into(),
        );
    let canonical = serde_json::to_vec(&CanonicalCliAuthorizationRequestWireV1 {
        version: CANONICAL_AUTHORIZATION_REQUEST_VERSION_V2,
        surface: CliAuthorizedSurfaceWireV1::Mutation,
        resource_kind,
        operation: operation.into(),
        selector,
        mutation_identity_fence: Some(*mutation_fence.as_bytes()),
        public_rpc: Some(CanonicalPublicRpcBindingWireV1 {
            method,
            body_sha256: Sha256::digest(protobuf_body).into(),
        }),
    })
    .map_err(|_| CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest)?;

    Ok((canonical, mutation_fence))
}

/// Constructs a canonical authorization envelope bound to one exact public RPC.
///
/// # Errors
///
/// Returns [`CliAuthorizationAdapterError`] when the protobuf body is empty or
/// exceeds the authenticated-evidence bound, or canonical encoding fails.
pub(crate) fn canonical_public_audit_request_v2(
    method: PublicApiAuditMethodV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: Selector,
    protobuf_body: &[u8],
) -> Result<Vec<u8>, CliAuthorizationAdapterError> {
    let protobuf_body = checked_authenticated_bytes(protobuf_body)?;
    serde_json::to_vec(&CanonicalCliAuthorizationRequestWireV1 {
        version: CANONICAL_AUTHORIZATION_REQUEST_VERSION_V2,
        surface: CliAuthorizedSurfaceWireV1::AuditRead,
        resource_kind,
        operation: operation.into(),
        selector,
        mutation_identity_fence: None,
        public_rpc: Some(CanonicalPublicRpcBindingWireV1 {
            method,
            body_sha256: Sha256::digest(protobuf_body).into(),
        }),
    })
    .map_err(|_| CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest)
}

/// Carries the only typed authorization meaning admitted from an authenticated payload.
///
/// No public constructor exists. The exact authenticated bytes must decode and
/// re-encode identically under the closed V1 schema before this value exists.
pub(crate) struct DecodedAuthenticatedCliRequestV1 {
    canonical_request: Vec<u8>,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: Selector,
    surface: CliAuthorizedSurfaceV1,
    mutation_identity_fence: Option<ObjectDigest>,
    semantics: AuthenticatedRequestSemanticsDigestV1,
}

impl DecodedAuthenticatedCliRequestV1 {
    /// Decodes and exact-verifies one authenticated canonical request envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest`]
    /// for malformed, noncanonical, unknown-version, or surface-inconsistent input.
    pub(crate) fn decode_authenticated(
        authenticated_payload: &[u8],
    ) -> Result<Self, CliAuthorizationAdapterError> {
        CanonicalRequestDigestV1::from_authenticated_canonical(authenticated_payload)?;
        let wire: CanonicalCliAuthorizationRequestWireV1 =
            serde_json::from_slice(authenticated_payload)
                .map_err(|_| CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest)?;
        let canonical = serde_json::to_vec(&wire)
            .map_err(|_| CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest)?;
        let version_matches = match wire.version {
            CANONICAL_AUTHORIZATION_REQUEST_VERSION_V1 => wire.public_rpc.is_none(),
            CANONICAL_AUTHORIZATION_REQUEST_VERSION_V2 => {
                wire.public_rpc.is_some()
                    && match (wire.surface, wire.mutation_identity_fence) {
                        (CliAuthorizedSurfaceWireV1::AuditRead, None) => true,
                        (CliAuthorizedSurfaceWireV1::Mutation, Some(fence)) => fence != [0; 32],
                        _ => false,
                    }
            }
            _ => false,
        };
        if !version_matches || canonical != authenticated_payload {
            return Err(CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest);
        }

        let (surface, mutation_identity_fence) = match (
            wire.surface,
            wire.mutation_identity_fence.map(ObjectDigest::from_bytes),
        ) {
            (CliAuthorizedSurfaceWireV1::Mutation, Some(binding))
                if binding.as_bytes() != &[0; 32] =>
            {
                (CliAuthorizedSurfaceV1::Mutation, Some(binding))
            }
            (CliAuthorizedSurfaceWireV1::AuditRead, None) => {
                (CliAuthorizedSurfaceV1::AuditRead, None)
            }
            _ => return Err(CliAuthorizationAdapterError::InvalidCanonicalAuthorizationRequest),
        };
        let semantics =
            AuthenticatedRequestSemanticsDigestV1::from_decoded(ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(REQUEST_SEMANTICS_DOMAIN)
                    .chain_update((canonical.len() as u64).to_be_bytes())
                    .chain_update(&canonical)
                    .finalize()
                    .into(),
            ));

        Ok(Self {
            canonical_request: canonical,
            resource_kind: wire.resource_kind,
            operation: wire.operation.into(),
            selector: wire.selector,
            surface,
            mutation_identity_fence,
            semantics,
        })
    }

    /// Returns the exact typed selector to the dormant resolver.
    #[must_use]
    pub(crate) const fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Returns the exact closed resource kind to the dormant resolver.
    #[must_use]
    pub(crate) const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Returns the exact closed operation to the dormant resolver.
    #[must_use]
    pub(crate) const fn operation(&self) -> Operation {
        self.operation
    }
}

/// Reports invalid or inconsistently bound authenticated CLI evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CliAuthorizationAdapterError {
    /// An authenticated identity, session, or channel value is absent or oversized.
    #[error("authenticated CLI evidence is invalid")]
    InvalidAuthenticatedEvidence,
    /// Authenticated bytes do not encode the exact closed canonical V1 request schema.
    #[error("authenticated CLI authorization request is invalid or noncanonical")]
    InvalidCanonicalAuthorizationRequest,
    /// Current protected lookup or authorization rejected the requested operation.
    #[error("current protected CLI authorization was rejected")]
    ProtectedAuthorizationRejected,
    /// The authenticated session names a different identity.
    #[error("authenticated CLI identity and session evidence do not match")]
    IdentitySessionMismatch,
    /// The authenticated channel names a different identity or session.
    #[error("authenticated CLI session and channel evidence do not match")]
    SessionChannelMismatch,
    /// Current protected authorization names a different identity, session, or channel.
    #[error("authenticated CLI evidence does not match current protected authorization")]
    ProtectedBindingMismatch,
    /// Authenticated or protected evidence covers different canonical request bytes.
    #[error("canonical CLI request does not match authenticated authorization evidence")]
    RequestBindingMismatch,
    /// Protected authorization covers another authority surface.
    #[error("protected CLI authorization does not cover the requested authority surface")]
    AuthoritySurfaceMismatch,
    /// The resolved mutation differs from the authenticated identity and fence commitment.
    #[error("resolved CLI mutation does not match authenticated identity and fences")]
    MutationBindingMismatch,
    /// Canonical request or resolved-mutation provenance is invalid.
    #[error(transparent)]
    Provenance(#[from] InvalidRequestProvenance),
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct EvidenceCommitmentV1(ObjectDigest);

impl EvidenceCommitmentV1 {
    fn from_exact_bytes(
        domain: &[u8],
        bytes: &[u8],
        invalid: CliAuthorizationAdapterError,
    ) -> Result<Self, CliAuthorizationAdapterError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_AUTHENTICATED_EVIDENCE_BYTES {
            return Err(invalid);
        }

        Ok(Self(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(domain)
                .chain_update((bytes.len() as u64).to_be_bytes())
                .chain_update(bytes)
                .finalize()
                .into(),
        )))
    }

    const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Retains an identity established by an authenticated transport.
///
/// The input is the transport verifier's canonical semantic identity, not a
/// principal field copied from the CLI request.
pub(crate) struct AuthenticatedCliIdentityEvidenceV1 {
    principal: PrincipalId,
    identity: EvidenceCommitmentV1,
}

impl AuthenticatedCliIdentityEvidenceV1 {
    /// Commits one independently authenticated transport identity.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError::InvalidAuthenticatedEvidence`]
    /// when the verifier's canonical identity is empty or exceeds its ceiling.
    pub(crate) fn from_verified_transport_identity(
        principal: PrincipalId,
    ) -> Result<Self, CliAuthorizationAdapterError> {
        Ok(Self {
            principal,
            identity: authenticated_identity_commitment(principal)?,
        })
    }
}

/// Retains an authenticated application session and its independently observed identity.
pub(crate) struct AuthenticatedCliSessionEvidenceV1 {
    identity: EvidenceCommitmentV1,
    session: EvidenceCommitmentV1,
}

impl AuthenticatedCliSessionEvidenceV1 {
    /// Commits the identity and session emitted by an authenticated session verifier.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError::InvalidAuthenticatedEvidence`]
    /// when either canonical value is empty or exceeds its ceiling.
    pub(crate) fn from_verified_session(
        principal: PrincipalId,
        canonical_session: &[u8],
    ) -> Result<Self, CliAuthorizationAdapterError> {
        Ok(Self {
            identity: authenticated_identity_commitment(principal)?,
            session: EvidenceCommitmentV1::from_exact_bytes(
                SESSION_EVIDENCE_DOMAIN,
                canonical_session,
                CliAuthorizationAdapterError::InvalidAuthenticatedEvidence,
            )?,
        })
    }
}

/// Retains a channel-authenticated request and the session bindings it observed.
pub(crate) struct AuthenticatedCliChannelEvidenceV1 {
    identity: EvidenceCommitmentV1,
    session: EvidenceCommitmentV1,
    channel_binding: ChannelBinding,
    channel: EvidenceCommitmentV1,
    request: ObjectDigest,
    schema: ObservationSchemaDigestV1,
}

impl AuthenticatedCliChannelEvidenceV1 {
    /// Commits exact evidence emitted by an authenticated channel verifier.
    ///
    /// `authenticated_canonical_request` must be the exact message bytes whose
    /// authentication was verified, not a reparsed or caller-reconstructed form.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError`] when a binding is empty or
    /// oversized, or when the authenticated request bytes violate their bound.
    pub(crate) fn from_verified_channel(
        principal: PrincipalId,
        canonical_session: &[u8],
        channel_binding: ChannelBinding,
        authenticated_canonical_request: &[u8],
        canonical_observation_schema: &[u8],
    ) -> Result<Self, CliAuthorizationAdapterError> {
        let canonical_observation_schema =
            checked_authenticated_bytes(canonical_observation_schema)?;

        Ok(Self {
            identity: authenticated_identity_commitment(principal)?,
            session: EvidenceCommitmentV1::from_exact_bytes(
                SESSION_EVIDENCE_DOMAIN,
                canonical_session,
                CliAuthorizationAdapterError::InvalidAuthenticatedEvidence,
            )?,
            channel_binding,
            channel: authenticated_channel_commitment(channel_binding)?,
            request: canonical_request_commitment(authenticated_canonical_request)?,
            schema: ObservationSchemaDigestV1::commit(canonical_observation_schema),
        })
    }
}

/// Retains one current protected authorization decision with all checked bindings.
///
/// A protected authority implementation creates this only after current policy,
/// revocation, expiry, audience, scope, and requested operation checks succeed.
/// The adapter rechecks its exact identity/session/channel/request cross-links;
/// this type does not turn a capability handle or caller-selected IDs into proof.
pub(crate) struct CurrentProtectedCliAuthorizationV1 {
    identity: EvidenceCommitmentV1,
    session: EvidenceCommitmentV1,
    channel: EvidenceCommitmentV1,
    request: ObjectDigest,
    revision: AuthorizationRevisionDigestV1,
    schema: ObservationSchemaDigestV1,
    surface: CliAuthorizedSurfaceV1,
    authorized_wall_seconds: i64,
    policy_generation: u64,
    original_coordinates: super::provenance::OriginalPublicMutationCoordinatesV2,
}

impl CurrentProtectedCliAuthorizationV1 {
    /// Resolves and authorizes one exact operation from protected controller stores.
    ///
    /// The immutable capability, controller audience, project policy, and
    /// revocation head are independently loaded from protected state. The
    /// method constructs dynamic authorization context from those values plus
    /// authenticated identity and channel evidence. The closed decoded request
    /// is the sole source of resource kind, operation, selector, surface, and
    /// canonical request bytes.
    /// The authenticated transport's project must independently match the
    /// capability's project; a holder cannot cross a registered session boundary
    /// by selecting a capability issued for another project.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError::ProtectedAuthorizationRejected`]
    /// when protected lookup, currentness checks, or grant evaluation fails.
    pub(crate) fn from_current_protected_capability(
        journal: &mut Journal,
        capability_limits: PublisherAuthorityLimits,
        policy_limits: PublisherPolicyLimits,
        capability_id: CapabilityId,
        authenticated_project: ProjectId,
        protected_clock: &mut crate::controller::ControllerProtectedClockV1,
        decoded: &DecodedAuthenticatedCliRequestV1,
        identity: &AuthenticatedCliIdentityEvidenceV1,
        channel: &AuthenticatedCliChannelEvidenceV1,
    ) -> Result<Self, CliAuthorizationAdapterError> {
        Self::from_current_protected_capability_with_decision(
            journal,
            capability_limits,
            policy_limits,
            capability_id,
            authenticated_project,
            protected_clock,
            decoded,
            identity,
            channel,
        )
        .map(|(authorization, _)| authorization)
    }

    /// Retains the same checked inputs beside the exact authorization evidence.
    ///
    /// The evaluator and protected time-floor advancement run exactly once.
    /// The projection is historical provenance, not a transferable live grant.
    ///
    /// # Errors
    /// Rejects the same protected authorization or authenticated-evidence
    /// failures as `from_current_protected_capability`.
    pub(crate) fn from_current_protected_capability_with_decision(
        journal: &mut Journal,
        capability_limits: PublisherAuthorityLimits,
        policy_limits: PublisherPolicyLimits,
        capability_id: CapabilityId,
        authenticated_project: ProjectId,
        protected_clock: &mut crate::controller::ControllerProtectedClockV1,
        decoded: &DecodedAuthenticatedCliRequestV1,
        identity: &AuthenticatedCliIdentityEvidenceV1,
        channel: &AuthenticatedCliChannelEvidenceV1,
    ) -> Result<(Self, CurrentCapabilityDecisionV1), CliAuthorizationAdapterError> {
        let decision = evaluate_current_protected_capability(
            journal,
            capability_limits,
            policy_limits,
            capability_id,
            authenticated_project,
            identity.principal,
            channel.channel_binding,
            protected_clock,
            decoded.resource_kind,
            decoded.operation,
            &decoded.selector,
        )?;
        let revision = decision.revision();
        let authorization = Self {
            identity: authenticated_identity_commitment(identity.principal)?,
            session: channel.session,
            channel: authenticated_channel_commitment(channel.channel_binding)?,
            request: canonical_request_commitment(&decoded.canonical_request)?,
            revision,
            schema: channel.schema,
            surface: decoded.surface,
            authorized_wall_seconds: decision.authorized_wall_seconds(),
            policy_generation: decision.policy().generation(),
            original_coordinates: decision.original_coordinates(*channel.session.0.as_bytes()),
        };
        Ok((authorization, decision))
    }
}

/// Retains the actual protected inputs for the common current grant checks.
///
/// There is no scalar constructor. Callers must still establish the identity
/// and exact request semantics in their own owner boundary; this projection
/// does not reconstruct a TLS peer or mint public mutation authorization.
/// Selected preparation parks these inputs privately before the floor effect;
/// only the later scope check can move them into the completed decision slot.
pub(crate) struct CurrentCapabilityDecisionV1 {
    capability: aos_sandbox_core::CapabilityRecord,
    policy: crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
    controller: crate::publisher_policy::PublisherControllerHeadV1,
    revocation: crate::publisher_policy::PublisherRevocationHeadV1,
    time_floor: ProtectedTimeFloorRevisionV1,
    authorized_wall_seconds: i64,
}

impl CurrentCapabilityDecisionV1 {
    /// Borrows the actual immutable capability that passed current grant checks.
    pub(crate) fn capability(&self) -> &aos_sandbox_core::CapabilityRecord {
        &self.capability
    }

    /// Borrows the actual currently selected protected project policy.
    pub(crate) fn policy(&self) -> &crate::publisher_policy::PreparedPublisherPolicyRevisionV1 {
        &self.policy
    }

    /// Returns the protected wall time used for this decision.
    pub(crate) const fn authorized_wall_seconds(&self) -> i64 {
        self.authorized_wall_seconds
    }

    /// Returns the same paired sample committed into the protected time floor.
    pub(crate) const fn clock(&self) -> RawPairedClockSample {
        self.time_floor.clock
    }

    fn revision(&self) -> AuthorizationRevisionDigestV1 {
        protected_authorization_revision(
            &self.capability,
            self.controller.generation,
            self.policy.generation(),
            self.time_floor,
        )
    }

    /// Projects checked coordinates without reviving the historical TLS session.
    pub(crate) fn original_coordinates(
        &self,
        historical_session: [u8; 32],
    ) -> super::provenance::OriginalPublicMutationCoordinatesV2 {
        let claims = self.capability.claims();
        super::provenance::OriginalPublicMutationCoordinatesV2::from_historical_parts((
            *claims.id.as_bytes(),
            *claims.revocation_scope.as_bytes(),
            claims.revocation_generation.get(),
            *claims.policy_digest.as_bytes(),
            self.policy.generation(),
            *self.controller.principal.as_bytes(),
            self.controller.generation,
            claims.not_before,
            claims.expires_at,
            self.policy.not_before(),
            self.policy.expires_at(),
            *claims.channel_binding.as_bytes(),
            historical_session,
            *self.revision().digest().as_bytes(),
        ))
    }
}

/// Evaluates the same protected capability policy for live and original custody.
///
/// # Errors
/// Rejects unavailable protected time/state, changed controller or revocation
/// heads, invalid policy lifetime, holder/key/project mismatch, or denied scope.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_current_protected_capability(
    journal: &mut Journal,
    capability_limits: PublisherAuthorityLimits,
    policy_limits: PublisherPolicyLimits,
    capability_id: CapabilityId,
    authenticated_project: ProjectId,
    holder: PrincipalId,
    channel_binding: ChannelBinding,
    protected_clock: &mut crate::controller::ControllerProtectedClockV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: &Selector,
) -> Result<CurrentCapabilityDecisionV1, CliAuthorizationAdapterError> {
    evaluate_current_protected_capability_inner(
        journal, capability_limits, policy_limits, capability_id,
        authenticated_project, holder, channel_binding, protected_clock,
        resource_kind, operation, selector, None,
    )
}

// The closed retained inspection shares every policy/grant check with the
// ordinary path, but owns its actual time-floor crossing before readback.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_current_protected_capability_retained(
    journal: &mut Journal,
    capability_limits: PublisherAuthorityLimits,
    policy_limits: PublisherPolicyLimits,
    capability_id: CapabilityId,
    authenticated_project: ProjectId,
    holder: PrincipalId,
    channel_binding: ChannelBinding,
    protected_clock: &mut crate::controller::ControllerProtectedClockV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: &Selector,
    crossing: &mut RetainedAuthorizationTimeFloorV1,
) -> Result<CurrentCapabilityDecisionV1, CliAuthorizationAdapterError> {
    evaluate_current_protected_capability_inner(
        journal, capability_limits, policy_limits, capability_id,
        authenticated_project, holder, channel_binding, protected_clock,
        resource_kind, operation, selector, Some(crossing),
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_current_protected_capability_inner(
    journal: &mut Journal,
    capability_limits: PublisherAuthorityLimits,
    policy_limits: PublisherPolicyLimits,
    capability_id: CapabilityId,
    authenticated_project: ProjectId,
    holder: PrincipalId,
    channel_binding: ChannelBinding,
    protected_clock: &mut crate::controller::ControllerProtectedClockV1,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: &Selector,
    crossing: Option<&mut RetainedAuthorizationTimeFloorV1>,
) -> Result<CurrentCapabilityDecisionV1, CliAuthorizationAdapterError> {
    let clock = protected_clock
        .sample()
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    let time_floor = advance_protected_time_floor_inner(journal, clock, crossing)?;
    evaluate_at_protected_time_floor(
        journal, capability_limits, policy_limits, capability_id,
        authenticated_project, holder, channel_binding, resource_kind,
        operation, selector, clock, time_floor,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_at_protected_time_floor(
    journal: &mut Journal,
    capability_limits: PublisherAuthorityLimits,
    policy_limits: PublisherPolicyLimits,
    capability_id: CapabilityId,
    authenticated_project: ProjectId,
    holder: PrincipalId,
    channel_binding: ChannelBinding,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: &Selector,
    clock: RawPairedClockSample,
    time_floor: ProtectedTimeFloorRevisionV1,
) -> Result<CurrentCapabilityDecisionV1, CliAuthorizationAdapterError> {
    prepare_capability_at_protected_time_floor(
        journal, capability_limits, policy_limits, capability_id, authenticated_project,
        holder, channel_binding, resource_kind, operation, selector, clock, time_floor,
        CapabilityCheckV1::Scope,
    )
}

enum CapabilityCheckV1 {
    Scope,
    // Preserve scope-denied negative DATA after the ordinary floor crossing;
    // Denied is distinct from the real context, validity or revocation errors.
    RetainedLifetime,
}

#[allow(clippy::too_many_arguments)]
fn prepare_capability_at_protected_time_floor(
    journal: &mut Journal,
    capability_limits: PublisherAuthorityLimits,
    policy_limits: PublisherPolicyLimits,
    capability_id: CapabilityId,
    authenticated_project: ProjectId,
    holder: PrincipalId,
    channel_binding: ChannelBinding,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: &Selector,
    clock: RawPairedClockSample,
    time_floor: ProtectedTimeFloorRevisionV1,
    check: CapabilityCheckV1,
) -> Result<CurrentCapabilityDecisionV1, CliAuthorizationAdapterError> {
    let trusted_now = clock.wall_seconds();
    let capability = {
        let registry = PublisherCapabilityRegistry::load(journal, capability_limits)
            .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        registry
            .resolve_current(capability_id)
            .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?
    };
    let claims = capability.claims();
    require_authenticated_project(authenticated_project, claims.project)?;
    let (controller, revocation, policy) = {
        let store = PublisherPolicyStore::load(journal, policy_limits)
            .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        let controller = store
            .controller_head()
            .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        let revocation = store
            .revocation_head(claims.revocation_scope)
            .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        let policy = store
            .current_policy(claims.project)
            .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        (controller, revocation, policy)
    };

    validate_current_capability_inputs(
        &capability, &policy, &controller, &revocation, holder, channel_binding,
        resource_kind, operation, selector, trusted_now, check,
    )?;

    Ok(CurrentCapabilityDecisionV1 {
        capability,
        policy,
        controller,
        revocation,
        time_floor,
        authorized_wall_seconds: trusted_now,
    })
}

// The ordinary evaluator and selected crossings borrow the same grant and
// lifetime paragraph. This helper neither advances a floor nor prepares DATA.
#[allow(clippy::too_many_arguments)]
fn validate_current_capability_inputs(
    capability: &aos_sandbox_core::CapabilityRecord,
    policy: &crate::publisher_policy::PreparedPublisherPolicyRevisionV1,
    controller: &crate::publisher_policy::PublisherControllerHeadV1,
    revocation: &crate::publisher_policy::PublisherRevocationHeadV1,
    holder: PrincipalId,
    channel_binding: ChannelBinding,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: &Selector,
    trusted_now: i64,
    check: CapabilityCheckV1,
) -> Result<(), CliAuthorizationAdapterError> {
    let claims = capability.claims();
    if controller.principal != claims.audience
        || revocation.scope != claims.revocation_scope
        || revocation.generation != claims.revocation_generation.get()
        || policy.project() != claims.project
        || policy.descriptor().digest() != claims.policy_digest
        || trusted_now < policy.not_before()
        || trusted_now >= policy.expires_at()
    {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }

    let context = AuthorizationContext {
        now: trusted_now,
        audience: controller.principal,
        holder,
        channel_binding,
        project: claims.project,
        sandbox: claims.sandbox,
        incarnation: claims.incarnation,
        assignment_epoch: claims.assignment_epoch,
        revocation_generation: claims.revocation_generation,
    };
    match capability.authorize(&context, resource_kind, operation, selector) {
        Ok(()) => {}
        Err(aos_sandbox_core::AuthorizationError::Denied)
            if matches!(check, CapabilityCheckV1::RetainedLifetime) => {}
        Err(_) => return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected),
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn compare_retained_git_read_at_clock_v1(
    decision: &CurrentCapabilityDecisionV1,
    facts: crate::git::delegated_read::ReadFactsV1,
    clock: RawPairedClockSample,
) -> Result<(), CliAuthorizationAdapterError> {
    require_authenticated_project(facts.project, decision.capability.claims().project)?;
    validate_current_capability_inputs(
        &decision.capability, &decision.policy, &decision.controller, &decision.revocation,
        facts.principal, facts.binding, ResourceKind::GitObjectDatabase,
        Operation::ContentRead, &Selector::Resource { resource: facts.resource },
        clock.wall_seconds(), CapabilityCheckV1::RetainedLifetime,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn compare_retained_git_entitlement_at_clock_v1(
    owner: &mut crate::public_capability_issuance::RetainedGitEntitlementReadV1,
    decision: &CurrentCapabilityDecisionV1,
    clock: RawPairedClockSample,
) -> Result<(), CliAuthorizationAdapterError> {
    owner.check_current_inputs(
        &decision.capability, &decision.policy, &decision.controller, &decision.revocation,
        clock.wall_seconds(),
    ).map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)
}

fn require_authenticated_project(
    authenticated_project: ProjectId,
    capability_project: ProjectId,
) -> Result<(), CliAuthorizationAdapterError> {
    if authenticated_project.as_bytes() == &[0; 16] || authenticated_project != capability_project {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    Ok(())
}

/// Lends one genuine selected request to the fixed same-writer crossing.
///
/// This opaque mechanical argument has no public constructor, clock, owner,
/// quantity or authority projection. Its originals stay in their caller slots.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub struct GitCoverageReadMetadataOperationV1<'original, 'profile> {
    input: GitCoverageReadInputV1<'original>,
    account: &'original mut crate::policy_compiler::GitCoverageAccountAttemptV1<'profile>,
}

#[cfg(target_os = "linux")]
enum GitCoverageReadInputV1<'original> {
    Inspect {
        original: &'original mut crate::git::delegated_read::GitReadRequestOwnerV1,
        acceptor: &'original crate::public_api_session::PublicApiSessionAcceptor,
        prepared: Option<(CapabilityId, crate::git::delegated_read::ReadFactsV1)>,
    },
    Bootstrap(&'original mut crate::public_capability_issuance::RetainedGitInitialIssuanceV1),
}

#[cfg(target_os = "linux")]
impl<'original, 'profile> GitCoverageReadMetadataOperationV1<'original, 'profile> {
    pub(crate) fn inspect(
        original: &'original mut crate::git::delegated_read::GitReadRequestOwnerV1,
        acceptor: &'original crate::public_api_session::PublicApiSessionAcceptor,
        account: &'original mut crate::policy_compiler::GitCoverageAccountAttemptV1<'profile>,
    ) -> Self {
        Self {
            input: GitCoverageReadInputV1::Inspect {
                original,
                acceptor,
                prepared: None,
            },
            account,
        }
    }

    pub(crate) fn bootstrap(
        original: &'original mut crate::public_capability_issuance::RetainedGitInitialIssuanceV1,
        account: &'original mut crate::policy_compiler::GitCoverageAccountAttemptV1<'profile>,
    ) -> Self {
        Self {
            input: GitCoverageReadInputV1::Bootstrap(original),
            account,
        }
    }

    pub(crate) fn compare_source(
        &mut self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
    ) -> Result<(), ()> {
        self.account.compare_completed_original_source_cut(source, inputs)
    }

    pub(crate) fn refuse(&mut self, cause: CliAuthorizationAdapterError) {
        match &mut self.input {
            GitCoverageReadInputV1::Inspect { original, .. } => {
                original.decision.get_or_insert(Err(cause));
            }
            GitCoverageReadInputV1::Bootstrap(original) => original.refuse(),
        }
    }

    pub(crate) fn prepare(
        &mut self,
        journal: &mut Journal,
        catalog: &aos_sandbox_core::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<Option<RawPairedClockSample>, CliAuthorizationAdapterError> {
        let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
        let (original, acceptor, prepared_slot) = match &mut self.input {
            GitCoverageReadInputV1::Inspect { original, acceptor, prepared } => {
                (original, acceptor, prepared)
            }
            GitCoverageReadInputV1::Bootstrap(original) => {
                return original.prepare(journal, catalog).map(Some);
            }
        };
        if prepared_slot.is_some() || original.coverage_sample.is_some() {
            return Err(refused());
        }
        let Some(prepared) = crate::controller::prepare_original_gateway_git_read_v1(
            journal, original, acceptor,
        ) else {
            if original.handle_rejected() {
                // The SAME registry has parked an ordinary negative handle
                // result. No time-floor or Cache effect follows this 401.
                return Ok(None);
            }
            return Err(refused());
        };
        *prepared_slot = Some(prepared);
        let sampled = {
            let (clock, _, _) = original.borrow_git_coverage_evaluation_v1()?;
            clock.sample()
        };
        original.coverage_sample = Some(sampled);
        let sample = *original.coverage_sample.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;

        original.coverage_entitlements = Some(
            crate::public_capability_issuance::RetainedGitEntitlementReadV1::new(),
        );
        original.coverage_entitlements.as_mut().ok_or_else(refused)?
            .capture_and_compare(journal, prepared.1.project).map_err(|_| refused())?;

        original.coverage_prefix = Some((|| {
            let mut loan = journal.controller_git_coverage_native_prefix_v1(catalog)?;
            let has_floor = loan.existing_controller_read_floor_v1()
                .map_err(|first| crate::journal::GitCoverageNativeHistoryErrorV1::from_first(first))?;
            loan.recheck()
                .map_err(|first| crate::journal::GitCoverageNativeHistoryErrorV1::from_first(first))?;
            Ok(has_floor)
        })());
        original.coverage_prefix.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?;
        original.crossing.prepare_existing_git_read(journal, sample)?;
        let revision = original.crossing.prepared_revision.ok_or_else(refused)?;
        original.coverage_prepared = Some(prepare_capability_at_protected_time_floor(
            journal, PublisherAuthorityLimits::default(), PublisherPolicyLimits::default(),
            prepared.0, prepared.1.project, prepared.1.principal, prepared.1.binding,
            ResourceKind::GitObjectDatabase, Operation::ContentRead,
            &Selector::Resource { resource: prepared.1.resource }, sample, revision,
            CapabilityCheckV1::RetainedLifetime,
        ));
        original.coverage_prepared.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?;
        Ok(Some(sample))
    }

    // Checks the real request after slow preparation, before the next effect.
    // No returned sample is a permit; every later crossing samples again.
    pub(crate) fn check_original_crossing(&mut self) -> Result<(), CliAuthorizationAdapterError> {
        match &mut self.input {
            GitCoverageReadInputV1::Inspect { original, prepared, .. } => {
                let (_, facts) = (*prepared)
                    .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
                original.check_git_coverage_crossing_v1(facts)
            }
            GitCoverageReadInputV1::Bootstrap(original) => original.check_original_crossing(),
        }
    }

    pub(crate) fn commit_and_evaluate(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), CliAuthorizationAdapterError> {
        let (original, prepared) = match &mut self.input {
            GitCoverageReadInputV1::Inspect { original, prepared, .. } => (original, prepared),
            GitCoverageReadInputV1::Bootstrap(original) => {
                return original.commit_and_issue(journal);
            }
        };
        let (_, facts) = (*prepared)
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        original.crossing.preflight_existing_git_read(journal)?;
        original.check_git_coverage_crossing_v1(facts)?;
        let revision = original.crossing.commit_prepared_existing_git_read(journal)?;
        let decision = original.coverage_prepared.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        decision.time_floor = revision;
        let scope = validate_current_capability_inputs(
            &decision.capability, &decision.policy, &decision.controller, &decision.revocation,
            facts.principal, facts.binding, ResourceKind::GitObjectDatabase,
            Operation::ContentRead, &Selector::Resource { resource: facts.resource },
            decision.authorized_wall_seconds, CapabilityCheckV1::Scope,
        );
        original.decision = Some(match scope {
            Ok(()) => original.coverage_prepared.take()
                .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?,
            Err(cause) => Err(cause),
        });
        // A denied scope after an exact floor crossing remains negative DATA;
        // it does not poison the shared owner or create effect permission.
        Ok(())
    }

    pub(crate) fn postcheck(&mut self) -> Result<(), ()> {
        match &mut self.input {
            GitCoverageReadInputV1::Inspect { original, .. } => {
                original.postcheck_git_coverage_evaluation_v1();
                if original.terminal_failure_observed() {
                    Err(())
                } else {
                    Ok(())
                }
            }
            GitCoverageReadInputV1::Bootstrap(original) => original.postcheck(),
        }
    }
}

#[cfg(test)]
mod project_binding_tests {
    use super::*;
    use aos_sandbox_core::ResourceId;

    #[test]
    fn accepts_only_the_nonzero_authenticated_project() {
        let capability = crate::publisher_authority::tests::capability(CapabilityId::new(), 200);
        let project = capability.claims().project;

        assert!(require_authenticated_project(project, project).is_ok());
        assert!(require_authenticated_project(ProjectId::from_bytes([99; 16]), project).is_err());
        assert!(require_authenticated_project(ProjectId::from_bytes([0; 16]), project).is_err());
        assert!(
            require_authenticated_project(
                ProjectId::from_bytes([0; 16]),
                ProjectId::from_bytes([0; 16]),
            )
            .is_err()
        );
    }

    #[test]
    fn public_audit_envelope_binds_method_and_exact_protobuf_body() {
        let selector = Selector::Resource {
            resource: ResourceId::from_bytes([42; 16]),
        };
        let first = canonical_public_audit_request_v2(
            PublicApiAuditMethodV1::GetOperation,
            ResourceKind::Sandbox,
            Operation::MetadataRead,
            selector.clone(),
            &[0x0a, 0x10, 0x42],
        )
        .unwrap();
        let second = canonical_public_audit_request_v2(
            PublicApiAuditMethodV1::GetOperation,
            ResourceKind::Sandbox,
            Operation::MetadataRead,
            selector,
            &[0x0a, 0x10, 0x43],
        )
        .unwrap();

        assert_ne!(first, second);
        let decoded = DecodedAuthenticatedCliRequestV1::decode_authenticated(&first).unwrap();
        assert_eq!(decoded.resource_kind, ResourceKind::Sandbox);
        assert_eq!(decoded.operation, Operation::MetadataRead);
        assert_eq!(decoded.surface, CliAuthorizedSurfaceV1::AuditRead);

        let mut downgraded: CanonicalCliAuthorizationRequestWireV1 =
            serde_json::from_slice(&first).unwrap();
        downgraded.version = CANONICAL_AUTHORIZATION_REQUEST_VERSION_V1;
        let downgraded = serde_json::to_vec(&downgraded).unwrap();
        assert!(DecodedAuthenticatedCliRequestV1::decode_authenticated(&downgraded).is_err());
    }
}

/// Carries one exact authenticated and currently authorized request binding.
///
/// The value is deliberately non-cloneable and crate-private. A future
/// resolver may borrow its mutation provenance to construct action-specific
/// fences, then must consume the same value to mint mutation authority.
#[must_use = "authenticated CLI authority must be consumed or deliberately discarded"]
pub(crate) struct DormantAuthenticatedCliRequestV1 {
    provenance: RequestProvenanceV1,
    decoded: DecodedAuthenticatedCliRequestV1,
    authorized_wall_seconds: i64,
    policy_generation: u64,
    original_coordinates: super::provenance::OriginalPublicMutationCoordinatesV2,
}

impl DormantAuthenticatedCliRequestV1 {
    /// Exact-verifies and binds transport and current protected evidence.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError`] when any identity, session,
    /// channel, request, or protected-authorization cross-link differs, or the
    /// supplied canonical request is empty or oversized.
    pub(crate) fn bind(
        decoded: DecodedAuthenticatedCliRequestV1,
        identity: AuthenticatedCliIdentityEvidenceV1,
        session: AuthenticatedCliSessionEvidenceV1,
        channel: AuthenticatedCliChannelEvidenceV1,
        authorization: CurrentProtectedCliAuthorizationV1,
    ) -> Result<Self, CliAuthorizationAdapterError> {
        if identity.identity != session.identity {
            return Err(CliAuthorizationAdapterError::IdentitySessionMismatch);
        }
        if identity.identity != channel.identity || session.session != channel.session {
            return Err(CliAuthorizationAdapterError::SessionChannelMismatch);
        }
        if identity.identity != authorization.identity
            || session.session != authorization.session
            || channel.channel != authorization.channel
        {
            return Err(CliAuthorizationAdapterError::ProtectedBindingMismatch);
        }

        let canonical_request =
            CanonicalRequestDigestV1::from_authenticated_canonical(&decoded.canonical_request)?;
        if canonical_request.digest() != channel.request
            || canonical_request.digest() != authorization.request
        {
            return Err(CliAuthorizationAdapterError::RequestBindingMismatch);
        }

        let principal = principal_commitment(identity.identity, session.session, channel.channel);
        let provenance = RequestProvenanceV1::from_authenticated(
            principal,
            authorization.revision,
            authorization.schema,
            canonical_request,
            decoded.semantics,
        );

        Ok(Self {
            provenance,
            decoded,
            authorized_wall_seconds: authorization.authorized_wall_seconds,
            policy_generation: authorization.policy_generation,
            original_coordinates: authorization.original_coordinates,
        })
    }

    /// Borrows the exact typed request that passed current authorization.
    #[must_use]
    pub(crate) const fn decoded_request(&self) -> &DecodedAuthenticatedCliRequestV1 {
        &self.decoded
    }

    /// Borrows mutation provenance for action-specific fence construction.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError::AuthoritySurfaceMismatch`] when
    /// current protected authorization covered an audit read instead.
    pub(crate) const fn mutation_provenance(
        &self,
    ) -> Result<&RequestProvenanceV1, CliAuthorizationAdapterError> {
        match self.decoded.surface {
            CliAuthorizedSurfaceV1::Mutation => Ok(&self.provenance),
            CliAuthorizedSurfaceV1::AuditRead => {
                Err(CliAuthorizationAdapterError::AuthoritySurfaceMismatch)
            }
        }
    }

    /// Consumes the binding to mint one exactly fenced resolved mutation.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError`] when protected authorization
    /// covered another surface or the resolved mutation has invalid fences.
    pub(crate) fn authorize_mutation(
        self,
        mutation: ResolvedPublicMutationV1,
    ) -> Result<AuthorizedResolvedMutationV1, CliAuthorizationAdapterError> {
        if self.decoded.surface != CliAuthorizedSurfaceV1::Mutation {
            return Err(CliAuthorizationAdapterError::AuthoritySurfaceMismatch);
        }
        if self.decoded.mutation_identity_fence != Some(mutation.authority_binding()) {
            return Err(CliAuthorizationAdapterError::MutationBindingMismatch);
        }

        AuthorizedResolvedMutationV1::from_authenticated(mutation, self.provenance)
            .map_err(Into::into)
    }

    /// Consumes exact mutation-surface authorization for operator recovery.
    pub(crate) fn authorize_operator_recovery(
        self,
        request: super::observation_adapter::OperatorRecoveryRequestV1,
    ) -> Result<
        super::observation_adapter::AuthorizedOperatorRecoveryV1,
        CliAuthorizationAdapterError,
    > {
        if self.decoded.surface != CliAuthorizedSurfaceV1::Mutation
            || self.decoded.mutation_identity_fence != Some(request.authority_binding())
        {
            return Err(CliAuthorizationAdapterError::MutationBindingMismatch);
        }
        Ok(
            super::observation_adapter::AuthorizedOperatorRecoveryV1::from_authenticated(
                request,
                self.provenance,
            ),
        )
    }

    /// Consumes the binding to mint one audit-read authority.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError::AuthoritySurfaceMismatch`] when
    /// current protected authorization covered a mutation instead.
    pub(crate) fn authorize_audit(
        self,
    ) -> Result<AuditAuthorizationV1, CliAuthorizationAdapterError> {
        if self.decoded.surface != CliAuthorizedSurfaceV1::AuditRead {
            return Err(CliAuthorizationAdapterError::AuthoritySurfaceMismatch);
        }

        Ok(AuditAuthorizationV1::from_authorized(
            self.provenance,
            self.authorized_wall_seconds,
            self.policy_generation,
        ))
    }

    /// Consumes exact public mutation authorization for an endpoint-validated fence.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError`] when the protected request was
    /// not a mutation or its exact method/body fence differs.
    pub(crate) fn authorize_public_mutation(
        self,
        expected_fence: ObjectDigest,
    ) -> Result<super::PublicMutationAuthorizationV1, CliAuthorizationAdapterError> {
        if self.decoded.surface != CliAuthorizedSurfaceV1::Mutation
            || self.decoded.mutation_identity_fence != Some(expected_fence)
        {
            return Err(CliAuthorizationAdapterError::MutationBindingMismatch);
        }

        Ok(super::PublicMutationAuthorizationV1::from_authorized(
            self.provenance,
            self.authorized_wall_seconds,
            self.policy_generation,
        )
        .with_original_coordinates(self.original_coordinates))
    }
}

fn canonical_request_commitment(
    canonical_request: &[u8],
) -> Result<ObjectDigest, CliAuthorizationAdapterError> {
    Ok(CanonicalRequestDigestV1::from_authenticated_canonical(canonical_request)?.digest())
}

fn checked_authenticated_bytes(bytes: &[u8]) -> Result<&[u8], CliAuthorizationAdapterError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_AUTHENTICATED_EVIDENCE_BYTES {
        Err(CliAuthorizationAdapterError::InvalidAuthenticatedEvidence)
    } else {
        Ok(bytes)
    }
}

fn authenticated_identity_commitment(
    principal: PrincipalId,
) -> Result<EvidenceCommitmentV1, CliAuthorizationAdapterError> {
    if principal.as_bytes() == &[0; 16] {
        return Err(CliAuthorizationAdapterError::InvalidAuthenticatedEvidence);
    }

    EvidenceCommitmentV1::from_exact_bytes(
        IDENTITY_EVIDENCE_DOMAIN,
        principal.as_bytes(),
        CliAuthorizationAdapterError::InvalidAuthenticatedEvidence,
    )
}

fn authenticated_channel_commitment(
    channel: ChannelBinding,
) -> Result<EvidenceCommitmentV1, CliAuthorizationAdapterError> {
    if channel.as_bytes() == &[0; 32] {
        return Err(CliAuthorizationAdapterError::InvalidAuthenticatedEvidence);
    }

    EvidenceCommitmentV1::from_exact_bytes(
        CHANNEL_EVIDENCE_DOMAIN,
        channel.as_bytes(),
        CliAuthorizationAdapterError::InvalidAuthenticatedEvidence,
    )
}

#[derive(Clone, Copy)]
pub(crate) struct ProtectedTimeFloorRevisionV1 {
    generation: u64,
    clock: RawPairedClockSample,
    previous: ObjectDigest,
    digest: ObjectDigest,
}

/// Owns the exact proposed transaction, commit outcome and readback debt.
/// This is negative custody, never a current decision or a retry capability.
#[derive(Default)]
pub(crate) struct RetainedAuthorizationTimeFloorV1 {
    proposal: Option<JournalTransaction>,
    preflight: Option<Result<(), crate::JournalError>>,
    prepared_revision: Option<ProtectedTimeFloorRevisionV1>,
    commit: Option<Result<crate::journal::CommitResult, crate::JournalError>>,
    expected: Option<(Vec<u8>, Vec<u8>)>,
    unsigned: Option<Vec<u8>>,
    readback: Option<bool>,
    attempted: bool,
}

impl RetainedAuthorizationTimeFloorV1 {
    pub(crate) fn failure(&self) -> Option<&crate::JournalError> {
        self.preflight.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.commit.as_ref().and_then(|result| result.as_ref().err()))
    }

    pub(crate) fn clean_readback(&self) -> bool {
        matches!(self.commit, Some(Ok(_))) && self.readback == Some(true)
    }

    pub(crate) fn compare_original_post_clock(
        &self,
        clock: RawPairedClockSample,
    ) -> Result<(), CliAuthorizationAdapterError> {
        validate_clock_advancement(self.prepared_revision, clock)
    }

    pub(crate) fn prepare_existing_git_read(
        &mut self,
        journal: &Journal,
        clock: RawPairedClockSample,
    ) -> Result<(), CliAuthorizationAdapterError> {
        if self.attempted {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        self.attempted = true;

        let (revision, unsigned, revision_bytes, head_bytes, transaction) =
            prepare_protected_time_floor(journal, clock)?;
        self.prepared_revision = Some(revision);
        self.proposal = Some(transaction);
        self.unsigned = Some(unsigned);
        self.expected = Some((revision_bytes, head_bytes));
        let proposal = self.proposal.as_ref()
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        self.preflight = Some(journal.preflight_transactions(std::slice::from_ref(proposal)));
        self.preflight.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        Ok(())
    }

    fn commit_prepared_existing_git_read(
        &mut self,
        journal: &mut Journal,
    ) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
        let revision = self.prepared_revision
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        let proposal = self.proposal.as_ref()
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        let expected = self.expected.as_ref()
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        commit_prepared_floor(
            journal, proposal, revision, expected, &mut self.preflight,
            &mut self.commit, &mut self.readback,
        )
    }

    fn preflight_existing_git_read(
        &mut self,
        journal: &Journal,
    ) -> Result<(), CliAuthorizationAdapterError> {
        let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
        preflight_prepared_floor(
            journal, self.proposal.as_ref().ok_or_else(refused)?,
            self.prepared_revision.ok_or_else(refused)?, &mut self.preflight, &self.commit,
        )
    }

    pub(crate) fn preflight_initial_issuance_floor(
        &mut self,
        journal: &Journal,
        proposal: &JournalTransaction,
    ) -> Result<(), CliAuthorizationAdapterError> {
        preflight_prepared_floor(
            journal, proposal,
            self.prepared_revision.ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?,
            &mut self.preflight, &self.commit,
        )
    }

    pub(crate) fn park_initial_issuance_prefix(
        &mut self,
        destination: &mut Vec<JournalTransaction>,
    ) -> Result<(), CliAuthorizationAdapterError> {
        if !destination.is_empty() || self.proposal.is_none()
            || !matches!(self.preflight, Some(Ok(())))
        {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        // Allocate while the original proposal is still parked. The only
        // move is then into the caller's resident two-transaction batch.
        destination.reserve_exact(2);
        if let Some(proposal) = self.proposal.take() {
            destination.push(proposal);
        }
        Ok(())
    }

    pub(crate) fn commit_prepared_initial_issuance_floor(
        &mut self,
        journal: &mut Journal,
        proposal: &JournalTransaction,
    ) -> Result<(), CliAuthorizationAdapterError> {
        let revision = self.prepared_revision
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        let expected = self.expected.as_ref()
            .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        commit_prepared_floor(
            journal, proposal, revision, expected, &mut self.preflight,
            &mut self.commit, &mut self.readback,
        ).map(|_| ())
    }
}

// Inspect and initial issuance share this exact staged floor crossing. Its
// proposal is borrowed from the original resident slot or batch, never cloned.
fn commit_prepared_floor(
    journal: &mut Journal,
    proposal: &JournalTransaction,
    revision: ProtectedTimeFloorRevisionV1,
    expected: &(Vec<u8>, Vec<u8>),
    preflight: &mut Option<Result<(), crate::JournalError>>,
    commit: &mut Option<Result<crate::journal::CommitResult, crate::JournalError>>,
    readback: &mut Option<bool>,
) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
    let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
    if commit.is_some() || !matches!(preflight, Some(Ok(()))) {
        return Err(refused());
    }
    *commit = Some(journal.commit(proposal));
    *readback = Some(time_floor_readback(journal, revision.generation, &expected.0, &expected.1));
    if !matches!(commit, Some(Ok(_))) || *readback != Some(true) {
        return Err(refused());
    }
    Ok(revision)
}

// Slow lineage validation and native preflight end before the caller's fresh
// original-clock check; append/readback remain the same single paragraph.
fn preflight_prepared_floor(
    journal: &Journal,
    proposal: &JournalTransaction,
    revision: ProtectedTimeFloorRevisionV1,
    preflight: &mut Option<Result<(), crate::JournalError>>,
    commit: &Option<Result<crate::journal::CommitResult, crate::JournalError>>,
) -> Result<(), CliAuthorizationAdapterError> {
    let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
    if commit.is_some() || !matches!(preflight, Some(Ok(()))) {
        return Err(refused());
    }
    let prior = load_protected_time_floor(journal)?;
    if revision.generation != prior.map_or(Some(1), |value| value.generation.checked_add(1))
        .ok_or_else(refused)?
        || revision.previous != prior.map_or(ObjectDigest::from_bytes([0; 32]), |value| value.digest)
    {
        return Err(refused());
    }

    *preflight = Some(journal.preflight_transactions(std::slice::from_ref(proposal)));
    if !matches!(preflight, Some(Ok(()))) {
        return Err(refused());
    }
    Ok(())
}

fn advance_protected_time_floor(
    journal: &mut Journal,
    clock: RawPairedClockSample,
) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
    advance_protected_time_floor_inner(journal, clock, None)
}

fn advance_protected_time_floor_inner(
    journal: &mut Journal,
    clock: RawPairedClockSample,
    mut retained: Option<&mut RetainedAuthorizationTimeFloorV1>,
) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
    if let Some(destination) = retained.as_deref_mut() {
        if destination.attempted {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        // Interrupted or failed crossings can never be repeated.
        destination.attempted = true;
    }
    let (revision, unsigned, revision_bytes, head_bytes, transaction) =
        prepare_protected_time_floor(journal, clock)?;
    let generation = revision.generation;

    // A journal error can be an acknowledgement loss after durable append.
    // Exact readback below is therefore the sole ordinary success criterion.
    let Some(destination) = retained else {
        let _commit_outcome = journal.commit(&transaction);
        if !time_floor_readback(journal, generation, &revision_bytes, &head_bytes) {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        return Ok(revision);
    };
    destination.proposal = Some(transaction);
    destination.unsigned = Some(unsigned);
    destination.expected = Some((revision_bytes, head_bytes));
    let proposal = destination.proposal.as_ref()
        .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    destination.commit = Some(journal.commit(proposal));
    let (revision_bytes, head_bytes) = destination.expected.as_ref()
        .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    destination.readback = Some(time_floor_readback(
        journal, generation, revision_bytes, head_bytes,
    ));
    if !destination.clean_readback() {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    Ok(revision)
}

fn prepare_protected_time_floor(
    journal: &Journal,
    clock: RawPairedClockSample,
) -> Result<(
    ProtectedTimeFloorRevisionV1, Vec<u8>, Vec<u8>, Vec<u8>, JournalTransaction,
), CliAuthorizationAdapterError> {
    journal
        .ensure_protected_authority()
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    let prior = load_protected_time_floor(journal)?;
    validate_clock_advancement(prior, clock)?;

    let generation = prior
        .map_or(Ok(1), |value| value.generation.checked_add(1).ok_or(()))
        .map_err(|()| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    let previous = prior.map_or(ObjectDigest::from_bytes([0; 32]), |value| value.digest);
    let mut revision = ProtectedTimeFloorRevisionV1 {
        generation,
        clock,
        previous,
        digest: ObjectDigest::from_bytes([0; 32]),
    };
    let unsigned = encode_time_floor_revision(revision, false);
    revision.digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(TIME_FLOOR_DIGEST_DOMAIN)
            .chain_update(&unsigned[..96])
            .finalize()
            .into(),
    );
    let revision_bytes = encode_time_floor_revision(revision, true);
    let head_bytes = encode_time_floor_head(revision);
    let mut transaction_id: [u8; 16] = Sha256::new()
        .chain_update(TIME_FLOOR_TRANSACTION_DOMAIN)
        .chain_update(&revision_bytes)
        .finalize()[..16]
        .try_into()
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    transaction_id[0] |= 0x80;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![
            JournalRecord::put(
                RecordNamespace::CliAuthorizationTime,
                time_floor_revision_key(generation),
                revision_bytes.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::CliAuthorizationTime,
                TIME_FLOOR_CURRENT_KEY.to_vec(),
                head_bytes.clone(),
            ),
        ],
    )
    .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    Ok((revision, unsigned, revision_bytes, head_bytes, transaction))
}

fn time_floor_readback(journal: &Journal, generation: u64, revision: &[u8], head: &[u8]) -> bool {
    let committed_revision = journal.get(
        RecordNamespace::CliAuthorizationTime,
        &time_floor_revision_key(generation),
    );
    let committed_head = journal.get(
        RecordNamespace::CliAuthorizationTime,
        TIME_FLOOR_CURRENT_KEY,
    );
    committed_revision == Some(revision) && committed_head == Some(head)
}

/// Applies the ordinary protected CLI time fence before first capability issuance.
pub(crate) fn advance_initial_issuance_time_floor(
    journal: &mut Journal,
    clock: RawPairedClockSample,
) -> Result<(), CliAuthorizationAdapterError> {
    advance_protected_time_floor(journal, clock).map(|_| ())
}

fn load_protected_time_floor(
    journal: &Journal,
) -> Result<Option<ProtectedTimeFloorRevisionV1>, CliAuthorizationAdapterError> {
    load_protected_time_floor_records(journal.records(RecordNamespace::CliAuthorizationTime))
}

fn load_protected_time_floor_records<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Option<ProtectedTimeFloorRevisionV1>, CliAuthorizationAdapterError> {
    let mut revisions = BTreeMap::new();
    let mut head = None;
    for (key, value) in records {
        if key == TIME_FLOOR_CURRENT_KEY {
            if head.replace(decode_time_floor_head(value)?).is_some() {
                return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
            }
        } else if let Some(generation_bytes) = key.strip_prefix(TIME_FLOOR_REVISION_PREFIX) {
            let generation = decode_u64(generation_bytes)?;
            let revision = decode_time_floor_revision(value)?;
            if generation != revision.generation || revisions.insert(generation, revision).is_some()
            {
                return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
            }
        } else {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
    }

    match (head, revisions.is_empty()) {
        (None, true) => Ok(None),
        (Some((head_generation, head_digest)), false) => {
            let mut prior_digest = ObjectDigest::from_bytes([0; 32]);
            let mut prior_revision = None;
            for expected_generation in 1..=head_generation {
                let revision = revisions
                    .get(&expected_generation)
                    .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
                if revision.previous != prior_digest {
                    return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
                }
                validate_clock_advancement(prior_revision, revision.clock)?;
                prior_digest = revision.digest;
                prior_revision = Some(*revision);
            }
            if u64::try_from(revisions.len()) != Ok(head_generation) || prior_digest != head_digest
            {
                return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
            }
            Ok(revisions.get(&head_generation).copied())
        }
        _ => Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected),
    }
}

// The same fixed codec/clock relation is used by native replay and preflight.
// A parsed transaction supplies no signed-currentness or write permission.
pub(crate) fn require_git_coverage_floor_transaction_v1(
    transaction: &JournalTransaction,
    prior: Option<ProtectedTimeFloorRevisionV1>,
) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
    let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
    let records = transaction.records();
    if records.len() != 2
        || records.iter().any(|record| {
            record.namespace() != RecordNamespace::CliAuthorizationTime
                || record.value().is_none()
        })
    {
        return Err(refused());
    }
    let bytes = records[0].value().ok_or_else(refused)?;
    let revision = decode_time_floor_revision(bytes)?;
    let generation = prior.map_or(Some(1), |prior| prior.generation.checked_add(1))
        .ok_or_else(refused)?;
    if revision.generation != generation
        || revision.previous != prior.map_or(ObjectDigest::from_bytes([0; 32]), |prior| prior.digest)
        || records[0].key() != time_floor_revision_key(generation)
        || records[1].key() != TIME_FLOOR_CURRENT_KEY
        || decode_time_floor_head(records[1].value().ok_or_else(refused)?)?
            != (generation, revision.digest)
    {
        return Err(refused());
    }
    validate_clock_advancement(prior, revision.clock)?;
    let digest = Sha256::new()
        .chain_update(TIME_FLOOR_TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let mut id: [u8; 16] = digest[..16].try_into().map_err(|_| refused())?;
    id[0] |= 0x80;
    if transaction.id() != &id {
        return Err(refused());
    }
    Ok(revision)
}

pub(crate) fn require_git_coverage_floor_from_state_v1(
    transaction: &JournalTransaction,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), CliAuthorizationAdapterError> {
    let prior = load_protected_time_floor_records(state.iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::CliAuthorizationTime)
        .map(|((_, key), value)| (key.as_slice(), value.as_slice())))?;
    require_git_coverage_floor_transaction_v1(transaction, prior).map(|_| ())
}

pub(crate) fn compare_git_coverage_floor_history_v1(
    journal: &Journal,
    observed: Option<ProtectedTimeFloorRevisionV1>,
) -> Result<(), CliAuthorizationAdapterError> {
    match (load_protected_time_floor(journal)?, observed) {
        (None, None) => Ok(()),
        (Some(current), Some(original))
            if encode_time_floor_revision(current, true)
                == encode_time_floor_revision(original, true) => Ok(()),
        _ => Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected),
    }
}

fn validate_clock_advancement(
    prior: Option<ProtectedTimeFloorRevisionV1>,
    clock: RawPairedClockSample,
) -> Result<(), CliAuthorizationAdapterError> {
    let Some(prior) = prior else {
        return Ok(());
    };
    if clock.provenance() != prior.clock.provenance()
        || clock.wall_seconds() < prior.clock.wall_seconds()
    {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    if clock.host_boot_id() != prior.clock.host_boot_id() {
        return Ok(());
    }

    let wall_elapsed = clock
        .wall_seconds()
        .checked_sub(prior.clock.wall_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok())
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    let boottime_elapsed = clock
        .boottime_nanoseconds()
        .checked_sub(prior.clock.boottime_nanoseconds())
        .ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    if wall_elapsed.abs_diff(boottime_elapsed) > CLOCK_PAIR_TOLERANCE_NANOSECONDS {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    Ok(())
}

fn encode_time_floor_revision(
    value: ProtectedTimeFloorRevisionV1,
    include_digest: bool,
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(TIME_FLOOR_REVISION_MAGIC);
    encoded.extend_from_slice(&value.generation.to_be_bytes());
    encoded.extend_from_slice(&value.clock.provenance().as_bytes());
    encoded.extend_from_slice(&value.clock.host_boot_id());
    encoded.extend_from_slice(&value.clock.wall_seconds().to_be_bytes());
    encoded.extend_from_slice(&value.clock.boottime_nanoseconds().to_be_bytes());
    encoded.extend_from_slice(value.previous.as_bytes());
    encoded.extend_from_slice(if include_digest {
        value.digest.as_bytes()
    } else {
        &[0; 32]
    });
    encoded
}

fn decode_time_floor_revision(
    bytes: &[u8],
) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
    if bytes.len() != 128 || &bytes[..8] != TIME_FLOOR_REVISION_MAGIC {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    let generation = decode_u64(&bytes[8..16])?;
    if generation == 0 {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    let provenance_bytes = decode_array::<16>(&bytes[16..32])?;
    let host_boot_id = decode_array::<16>(&bytes[32..48])?;
    let wall_seconds = i64::from_be_bytes(decode_array::<8>(&bytes[48..56])?);
    let boottime_nanoseconds = u64::from_be_bytes(decode_array::<8>(&bytes[56..64])?);
    let previous = ObjectDigest::from_bytes(decode_array::<32>(&bytes[64..96])?);
    let digest = ObjectDigest::from_bytes(decode_array::<32>(&bytes[96..128])?);
    let expected = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(TIME_FLOOR_DIGEST_DOMAIN)
            .chain_update(&bytes[..96])
            .finalize()
            .into(),
    );
    if digest != expected {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    let provenance = aos_sandbox_core::RawClockProvenance::new_untrusted(provenance_bytes)
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    let clock = RawPairedClockSample::new_untrusted(
        provenance,
        host_boot_id,
        wall_seconds,
        boottime_nanoseconds,
    )
    .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
    Ok(ProtectedTimeFloorRevisionV1 {
        generation,
        clock,
        previous,
        digest,
    })
}

fn encode_time_floor_head(value: ProtectedTimeFloorRevisionV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(48);
    encoded.extend_from_slice(TIME_FLOOR_HEAD_MAGIC);
    encoded.extend_from_slice(&value.generation.to_be_bytes());
    encoded.extend_from_slice(value.digest.as_bytes());
    encoded
}

fn decode_time_floor_head(
    bytes: &[u8],
) -> Result<(u64, ObjectDigest), CliAuthorizationAdapterError> {
    if bytes.len() != 48 || &bytes[..8] != TIME_FLOOR_HEAD_MAGIC {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    let generation = decode_u64(&bytes[8..16])?;
    let digest = ObjectDigest::from_bytes(decode_array::<32>(&bytes[16..48])?);
    if generation == 0 || digest.as_bytes() == &[0; 32] {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    Ok((generation, digest))
}

fn time_floor_revision_key(generation: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(TIME_FLOOR_REVISION_PREFIX.len() + 8);
    key.extend_from_slice(TIME_FLOOR_REVISION_PREFIX);
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn decode_u64(bytes: &[u8]) -> Result<u64, CliAuthorizationAdapterError> {
    Ok(u64::from_be_bytes(decode_array::<8>(bytes)?))
}

fn decode_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CliAuthorizationAdapterError> {
    bytes
        .try_into()
        .map_err(|_| CliAuthorizationAdapterError::ProtectedAuthorizationRejected)
}

fn protected_authorization_revision(
    capability: &aos_sandbox_core::CapabilityRecord,
    controller_generation: u64,
    policy_generation: u64,
    time_floor: ProtectedTimeFloorRevisionV1,
) -> AuthorizationRevisionDigestV1 {
    let claims = capability.claims();
    // The 144-byte coordinate prefix is followed by the entire floor digest.
    let mut exact_revision = [0_u8; 176];
    exact_revision[..16].copy_from_slice(claims.id.as_bytes());
    exact_revision[16..32].copy_from_slice(claims.revocation_scope.as_bytes());
    exact_revision[32..40].copy_from_slice(&claims.revocation_generation.get().to_be_bytes());
    exact_revision[40..72].copy_from_slice(claims.policy_digest.as_bytes());
    exact_revision[72..80].copy_from_slice(&controller_generation.to_be_bytes());
    exact_revision[80..88].copy_from_slice(&policy_generation.to_be_bytes());
    exact_revision[88..96].copy_from_slice(&time_floor.generation.to_be_bytes());
    exact_revision[96..112].copy_from_slice(&time_floor.clock.provenance().as_bytes());
    exact_revision[112..128].copy_from_slice(&time_floor.clock.host_boot_id());
    exact_revision[128..136].copy_from_slice(&time_floor.clock.wall_seconds().to_be_bytes());
    exact_revision[136..144]
        .copy_from_slice(&time_floor.clock.boottime_nanoseconds().to_be_bytes());
    exact_revision[144..].copy_from_slice(time_floor.digest.as_bytes());
    AuthorizationRevisionDigestV1::commit(&exact_revision)
}

fn principal_commitment(
    identity: EvidenceCommitmentV1,
    session: EvidenceCommitmentV1,
    channel: EvidenceCommitmentV1,
) -> QueryPrincipalDigestV1 {
    let mut exact_binding = [0_u8; 96];
    exact_binding[..32].copy_from_slice(identity.digest().as_bytes());
    exact_binding[32..64].copy_from_slice(session.digest().as_bytes());
    exact_binding[64..].copy_from_slice(channel.digest().as_bytes());
    QueryPrincipalDigestV1::commit(&exact_binding)
}
