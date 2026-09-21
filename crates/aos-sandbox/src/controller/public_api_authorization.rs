//! Binds live mutually authenticated public sessions to protected controller authority.
//!
//! The TLS registration supplies principal and project, while the journal
//! supplies capability claims and current policy. Neither a request header nor
//! a certificate registration alone grants authority. RPC admission must pass
//! the exact canonical authorization envelope received on the retained stream.

use aos_sandbox_core::CapabilityId;

use super::{
    AuthenticatedCliChannelEvidenceV1, AuthenticatedCliIdentityEvidenceV1,
    AuthenticatedCliSessionEvidenceV1, CliAuthorizationAdapterError,
    CurrentProtectedCliAuthorizationV1, DORMANT_CLI_OBSERVATION_SCHEMA_V1,
    DecodedAuthenticatedCliRequestV1, DormantAuthenticatedCliRequestV1,
    DormantCliAuthorizationOwnerV1, PublisherAuthorityLimits, PublisherPolicyLimits,
};
use crate::public_api_session::PublicApiPeer;

impl DormantCliAuthorizationOwnerV1<'_> {
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
