//! Mutual hello verification and client-then-broker transcript binding.
//!
//! A valid pair of signed hellos remains [`BrokerSessionTranscriptPhaseV1::Provisional`].
//! The broker cannot treat it as authority or dispatch effects until a valid
//! sequence-1 ClientRecord proves possession of the separate traffic key. No
//! additional proof message exists.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_core::FeatureRef;
use sha2::{Digest as _, Sha256};

use crate::artifact::{
    BrokerSessionArtifactError, SESSION_BINDING_DOMAIN, complete_signed_client_hello_digest_v1,
};
use crate::context::ProtectedBrokerSessionVerificationContextV1;
use crate::model::{BrokerSessionKeyUsageV1, BrokerSessionValidationError};
use crate::profile::{BrokerSessionNegotiationError, validate_authenticated_negotiation_v1};
use crate::projection::{
    BrokerSessionProjectionError, CanonicalBrokerClientHelloV1, CanonicalBrokerServerHelloV1,
};

/// Identifies whether separate client traffic-key possession has been proved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerSessionTranscriptPhaseV1 {
    /// Both hellos verify, but no sequence-1 ClientRecord has verified.
    Provisional,
    /// The first ClientRecord verified with the distinct traffic key.
    TrafficKeyProved,
}

/// Carries a cryptographically verified transcript without authority claims.
///
/// This result inherits the caller's context assumptions. It does not prove
/// protected-state provenance, descriptor/kernel identity, durable CAS,
/// freshness of caller-generated nonces, or authorization for an effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBrokerSessionTranscriptV1 {
    session_binding: [u8; 32],
    protected_context_digest: [u8; 32],
    protocol: crate::model::BrokerSessionProtocolV1,
    protocol_major: u16,
    protocol_minor: u16,
    audience: Audience,
    client_process: [u8; 16],
    broker_process: [u8; 16],
    required_features: Vec<FeatureRef>,
    advertised_features: Vec<FeatureRef>,
    required_methods: Vec<BrokerMethod>,
    advertised_methods: Vec<BrokerMethod>,
    negotiated_maximum_request_bytes: usize,
    negotiated_maximum_response_bytes: u32,
    phase: BrokerSessionTranscriptPhaseV1,
}

impl VerifiedBrokerSessionTranscriptV1 {
    /// Returns the client-then-broker complete-artifact binding digest.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }
    /// Returns the complete protected-context digest committed by both hellos.
    #[must_use]
    pub const fn protected_context_digest(&self) -> [u8; 32] {
        self.protected_context_digest
    }
    /// Returns the exact negotiated broker protocol.
    #[must_use]
    pub const fn protocol(&self) -> crate::model::BrokerSessionProtocolV1 {
        self.protocol
    }
    /// Returns the exact negotiated major and minor version.
    #[must_use]
    pub const fn protocol_version(&self) -> (u16, u16) {
        (self.protocol_major, self.protocol_minor)
    }
    /// Returns the exact negotiated peer role.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }
    /// Returns the context-pinned client process identity.
    #[must_use]
    pub const fn client_process(&self) -> [u8; 16] {
        self.client_process
    }
    /// Returns the context-pinned broker process identity.
    #[must_use]
    pub const fn broker_process(&self) -> [u8; 16] {
        self.broker_process
    }
    /// Returns whether the separate client traffic key has been proved.
    #[must_use]
    pub const fn phase(&self) -> BrokerSessionTranscriptPhaseV1 {
        self.phase
    }
    /// Returns the authenticated response ceiling selected by BrokerHello.
    #[must_use]
    pub const fn negotiated_maximum_response_bytes(&self) -> u32 {
        self.negotiated_maximum_response_bytes
    }
    /// Returns the broker's signed request-packet ceiling.
    #[must_use]
    pub const fn negotiated_maximum_request_bytes(&self) -> usize {
        self.negotiated_maximum_request_bytes
    }
    /// Returns the canonical feature set required by the client.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
    /// Returns the canonical feature set advertised by the broker.
    #[must_use]
    pub fn advertised_features(&self) -> &[FeatureRef] {
        &self.advertised_features
    }
    /// Returns the canonical method set required by the client.
    #[must_use]
    pub fn required_methods(&self) -> &[BrokerMethod] {
        &self.required_methods
    }
    /// Returns the canonical methods negotiated from the broker advertisement.
    #[must_use]
    pub fn negotiated_methods(&self) -> &[BrokerMethod] {
        &self.advertised_methods
    }

    pub(crate) fn with_traffic_key_proved(&self) -> Self {
        Self {
            phase: BrokerSessionTranscriptPhaseV1::TrafficKeyProved,
            ..self.clone()
        }
    }
}

/// Reports a failed feature, context, cross-link, nonce, or signature check.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionTranscriptError {
    /// Canonical protobuf validation failed.
    #[error("invalid canonical broker hello: {0}")]
    Projection(#[from] BrokerSessionProjectionError),
    /// Closed feature, method, role, version, or ceiling negotiation failed.
    #[error("Broker Session Authentication negotiation failed: {0}")]
    Negotiation(#[from] BrokerSessionNegotiationError),
    /// Fixed subject or caller-supplied context shape differs.
    #[error("Broker Session Authentication hello differs from protected context")]
    ContextMismatch,
    /// A local key is inactive or the received signer reference differs.
    #[error("Broker Session Authentication signer differs from active local context: {0}")]
    Signer(#[from] BrokerSessionValidationError),
    /// Strict signature verification failed.
    #[error("Broker Session Authentication hello signature failed: {0}")]
    Signature(#[from] BrokerSessionArtifactError),
    /// The broker hello does not cross-link the complete signed client hello.
    #[error("Broker Session Authentication hello cross-link mismatch")]
    CrossLink,
    /// The independently generated hello nonces are equal.
    #[error("Broker Session Authentication hello nonces must differ")]
    EqualNonces,
}

/// Verifies two canonical authenticated hellos against one local context.
///
/// The returned transcript is deliberately provisional. Verification is pure:
/// it does not persist currentness, advance replay state, prove protected
/// context provenance, or authorize any operation.
///
/// # Errors
///
/// Returns [`BrokerSessionTranscriptError`] for an inexact protocol version,
/// feature/method/role profile, invalid negotiated ceiling, inactive or
/// mismatched key, context mismatch, failed signature, equal nonce, or
/// cross-link mismatch.
pub fn verify_broker_session_transcript_v1(
    client: &CanonicalBrokerClientHelloV1,
    broker: &CanonicalBrokerServerHelloV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionTranscriptError> {
    context.require_all_active()?;
    let negotiation = validate_authenticated_negotiation_v1(
        client.message(),
        broker.message(),
        context.protocol(),
        context.protocol_major(),
        context.protocol_minor(),
        context.audience(),
    )?;
    let protected_context_digest = context.protected_context_digest();
    let client_subject = client.signed_artifact().subject();
    if client_subject.node_id != context.node_id()
        || client_subject.boot_id != context.boot_id()
        || client_subject.protocol != context.protocol()
        || client_subject.major != context.protocol_major()
        || client_subject.minor != context.protocol_minor()
        || client_subject.audience != context.audience()
        || client_subject.client_process() != context.client_process()
        || client_subject.protected_context_digest() != protected_context_digest
        || client_subject.cleared_fields_digest() != client.cleared_fields_digest()
        || client.message().protocol_major != u32::from(context.protocol_major())
        || client.message().protocol_minor != u32::from(context.protocol_minor())
        || client.message().audience.as_known() != Some(context.audience())
    {
        return Err(BrokerSessionTranscriptError::ContextMismatch);
    }
    let client_key = context.key(BrokerSessionKeyUsageV1::ClientHello);
    client_key.matches_active(client.signed_artifact().signer())?;
    client
        .signed_artifact()
        .verify_with_public_key(client_key.public_key())?;

    let client_digest = complete_signed_client_hello_digest_v1(client.signed_artifact());
    let broker_subject = broker.signed_artifact().subject();
    if broker_subject.node_id != context.node_id()
        || broker_subject.boot_id != context.boot_id()
        || broker_subject.protocol != context.protocol()
        || broker_subject.major != context.protocol_major()
        || broker_subject.minor != context.protocol_minor()
        || broker_subject.audience != context.audience()
        || broker_subject.broker_process() != context.broker_process()
        || broker_subject.protected_context_digest() != protected_context_digest
        || broker_subject.cleared_fields_digest() != broker.cleared_fields_digest()
        || broker.message().protocol_major != u32::from(context.protocol_major())
        || broker.message().protocol_minor != u32::from(context.protocol_minor())
        || broker_subject.signed_client_hello_digest() != client_digest
    {
        return Err(BrokerSessionTranscriptError::ContextMismatch);
    }
    if client_subject.nonce() == broker_subject.nonce() {
        return Err(BrokerSessionTranscriptError::EqualNonces);
    }
    let broker_key = context.key(BrokerSessionKeyUsageV1::BrokerHello);
    broker_key.matches_active(broker.signed_artifact().signer())?;
    broker
        .signed_artifact()
        .verify_with_public_key(broker_key.public_key())?;

    let session_binding = session_binding(
        &client.signed_artifact().to_canonical_bytes(),
        &broker.signed_artifact().to_canonical_bytes(),
    );
    Ok(VerifiedBrokerSessionTranscriptV1 {
        session_binding,
        protected_context_digest,
        protocol: negotiation.protocol,
        protocol_major: negotiation.major,
        protocol_minor: negotiation.minor,
        audience: negotiation.audience,
        client_process: context.client_process(),
        broker_process: context.broker_process(),
        required_features: negotiation.required_features,
        advertised_features: negotiation.advertised_features,
        required_methods: negotiation.required_methods,
        advertised_methods: negotiation.advertised_methods,
        negotiated_maximum_request_bytes: negotiation.maximum_request_bytes,
        negotiated_maximum_response_bytes: negotiation.maximum_response_bytes,
        phase: BrokerSessionTranscriptPhaseV1::Provisional,
    })
}

fn session_binding(client: &[u8], broker: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_BINDING_DOMAIN);
    hasher.update((client.len() as u32).to_be_bytes());
    hasher.update(client);
    hasher.update((broker.len() as u32).to_be_bytes());
    hasher.update(broker);
    hasher.finalize().into()
}
