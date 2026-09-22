//! Binds live mutually authenticated public sessions to protected controller authority.
//!
//! The TLS registration supplies principal and project, while the journal
//! supplies capability claims and current policy. Neither a request header nor
//! a certificate registration alone grants authority. RPC admission constructs
//! its canonical authorization envelope from the exact body received on the
//! retained stream.

use aos_sandbox_core::CapabilityId;

use super::{
    AuditAuthorizationV1, AuthenticatedCliChannelEvidenceV1, AuthenticatedCliIdentityEvidenceV1,
    AuthenticatedCliSessionEvidenceV1, CliAuthorizationAdapterError,
    CurrentProtectedCliAuthorizationV1, DORMANT_CLI_OBSERVATION_SCHEMA_V1,
    DecodedAuthenticatedCliRequestV1, DormantAuthenticatedCliRequestV1,
    DormantCliAuthorizationOwnerV1, PublisherAuthorityLimits, PublisherPolicyLimits,
};
use crate::PublicOperationAuthorizationV1;
use crate::cli_model::authorization_adapter::{
    PublicApiAuditMethodV1, canonical_public_audit_request_v2,
};
use crate::public_api_session::PublicApiPeer;

impl DormantCliAuthorizationOwnerV1<'_> {
    /// Reauthorizes an exact public operation read against its admitted scope.
    ///
    /// The server, rather than the caller, supplies the immutable operation
    /// scope. The canonical authorization envelope commits the registered RPC
    /// method and exact decoded protobuf buffer, preventing a capability lookup
    /// header from being reused as authority for another request.
    ///
    /// # Errors
    ///
    /// Rejects project substitution, malformed request bytes, stale transport
    /// evidence, or any current capability, policy, expiry, or revocation
    /// failure.
    pub(crate) fn authorize_public_operation_read(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        scope: &PublicOperationAuthorizationV1,
        protobuf_body: &[u8],
    ) -> Result<AuditAuthorizationV1, CliAuthorizationAdapterError> {
        if peer.project() != scope.project() {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        let authorization_request = canonical_public_audit_request_v2(
            PublicApiAuditMethodV1::GetOperation,
            scope.resource_kind(),
            aos_sandbox_core::Operation::MetadataRead,
            scope.selector().clone(),
            protobuf_body,
        )?;
        self.authenticate_public_request(peer, capability_id, &authorization_request)?
            .authorize_audit()
    }

    /// Reauthorizes one exact public read against current protected state.
    ///
    /// The service selects the closed method, resource kind, operation, and
    /// selector from its decoded request. The exact received protobuf bytes are
    /// committed beside those semantics, so lookup metadata cannot authorize a
    /// different procedure or body.
    ///
    /// # Errors
    ///
    /// Rejects malformed request bytes, stale transport evidence, or any
    /// current capability, policy, expiry, revocation, project, or grant failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_public_read(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: aos_sandbox_core::ResourceKind,
        operation: aos_sandbox_core::Operation,
        selector: aos_sandbox_core::Selector,
        protobuf_body: &[u8],
    ) -> Result<AuditAuthorizationV1, CliAuthorizationAdapterError> {
        let authorization_request = canonical_public_audit_request_v2(
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
        )?;
        self.authenticate_public_request(peer, capability_id, &authorization_request)?
            .authorize_audit()
    }

    /// Authenticates one exact public request against current protected authority.
    ///
    /// The caller must obtain `canonical_request` from the HTTP/2 request on
    /// the stream that owns `peer`; it must not substitute a client-provided
    /// digest or reconstruct a different request after authentication. The
    /// capability handle is only a lookup key, never proof of authorization.
    /// The registered certificate binds the capability's proof-of-possession
    /// key, and the TLS exporter binds the resulting provenance to this session.
    ///
    /// # Errors
    ///
    /// Rejects stale sessions, malformed envelopes, project mismatches, and
    /// any failure of protected capability, policy, expiry, or revocation checks.
    pub(crate) fn authenticate_public_request(
        &mut self,
        peer: &PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
    ) -> Result<DormantAuthenticatedCliRequestV1, CliAuthorizationAdapterError> {
        peer.recheck()
            .map_err(|_| CliAuthorizationAdapterError::InvalidAuthenticatedEvidence)?;

        let decoded = DecodedAuthenticatedCliRequestV1::decode_authenticated(canonical_request)?;
        let principal = peer.principal();
        let session_binding = peer.session_binding();
        let identity =
            AuthenticatedCliIdentityEvidenceV1::from_verified_transport_identity(principal)?;
        let session =
            AuthenticatedCliSessionEvidenceV1::from_verified_session(principal, &session_binding)?;
        let channel = AuthenticatedCliChannelEvidenceV1::from_verified_channel(
            principal,
            &session_binding,
            peer.key_binding(),
            canonical_request,
            DORMANT_CLI_OBSERVATION_SCHEMA_V1,
        )?;
        let authorization = CurrentProtectedCliAuthorizationV1::from_current_protected_capability(
            self.journal,
            PublisherAuthorityLimits::default(),
            PublisherPolicyLimits::default(),
            capability_id,
            peer.project(),
            &mut self.protected_clock,
            &decoded,
            &identity,
            &channel,
        )?;

        // Protected journal reads must not extend the lifetime of transport proof.
        peer.recheck()
            .map_err(|_| CliAuthorizationAdapterError::InvalidAuthenticatedEvidence)?;
        DormantAuthenticatedCliRequestV1::bind(decoded, identity, session, channel, authorization)
    }
}
