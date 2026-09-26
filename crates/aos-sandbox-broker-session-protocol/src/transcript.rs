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
use crate::profile::{
    BrokerSessionNegotiationError, ValidatedBrokerSessionNegotiationV1,
    validate_authenticated_negotiation_v1,
};
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

/// Retains a canonical ClientHello after strict locally keyed verification.
///
/// The caller-selected key is checked for active currentness and exact signer
/// reference before strict Ed25519 verification. Only then may
/// [`Self::authenticated_client_process`] be used as the dynamic process input
/// to a locally constructed protected context. This stage alone does not check
/// that context, negotiate a session, or confer authority.
#[derive(Clone, Debug)]
pub struct StrictlyVerifiedClientHelloV1 {
    client: CanonicalBrokerClientHelloV1,
    signer: crate::model::BrokerSessionSignerReferenceV1,
    public_key: [u8; 32],
}

impl StrictlyVerifiedClientHelloV1 {
    /// Returns the process claim authenticated by the locally selected hello key.
    #[must_use]
    pub const fn authenticated_client_process(&self) -> [u8; 16] {
        self.client.signed_artifact().subject().client_process()
    }
}

/// Retains a signed ClientHello after complete local-context comparison.
///
/// This remains non-authorizing and cannot form a transcript without the exact
/// signed BrokerHello and the same protected context.
#[derive(Clone, Debug)]
pub struct ContextVerifiedClientHelloV1 {
    client: StrictlyVerifiedClientHelloV1,
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

/// Strictly verifies a canonical ClientHello with one locally selected key.
///
/// Signature verification happens before the returned process value becomes
/// available. Received signer metadata never selects `key`.
///
/// # Errors
///
/// Returns [`BrokerSessionTranscriptError`] when the key is inactive, the
/// signer reference differs, or strict Ed25519 verification fails.
pub fn verify_client_hello_signature_v1(
    client: &CanonicalBrokerClientHelloV1,
    key: &crate::context::ProtectedBrokerSessionKeyV1,
) -> Result<StrictlyVerifiedClientHelloV1, BrokerSessionTranscriptError> {
    key.matches_active(client.signed_artifact().signer())?;
    client
        .signed_artifact()
        .verify_with_public_key(key.public_key())?;

    Ok(StrictlyVerifiedClientHelloV1 {
        client: client.clone(),
        signer: key.signer().clone(),
        public_key: *key.public_key(),
    })
}

/// Compares a strictly verified ClientHello with one complete local context.
///
/// The context must retain the exact key used by the signature stage. Its
/// dynamic client-process component may be taken from
/// [`StrictlyVerifiedClientHelloV1::authenticated_client_process`]; every
/// route, trust, revocation, protocol, execution, and key value remains locally
/// selected.
///
/// # Errors
///
/// Returns [`BrokerSessionTranscriptError`] for an inactive context key, a key
/// substitution between stages, or any signed/context/projection mismatch.
pub fn verify_client_hello_context_v1(
    client: StrictlyVerifiedClientHelloV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<ContextVerifiedClientHelloV1, BrokerSessionTranscriptError> {
    context.require_all_active()?;
    let context_key = context.key(BrokerSessionKeyUsageV1::ClientHello);
    if context_key.signer() != &client.signer || context_key.public_key() != &client.public_key {
        return Err(BrokerSessionTranscriptError::ContextMismatch);
    }
    require_client_context(&client.client, context)?;

    Ok(ContextVerifiedClientHelloV1 { client })
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
    // This public wrapper preserves the original fail-closed error precedence.
    context.require_all_active()?;
    let negotiation = validate_authenticated_negotiation_v1(
        client.message(),
        broker.message(),
        context.protocol(),
        context.protocol_major(),
        context.protocol_minor(),
        context.audience(),
    )?;
    require_client_context(client, context)?;
    let client_key = context.key(BrokerSessionKeyUsageV1::ClientHello);
    client_key.matches_active(client.signed_artifact().signer())?;
    client
        .signed_artifact()
        .verify_with_public_key(client_key.public_key())?;

    verify_remaining_hello_pair(client, broker, context, negotiation)
}

/// Completes mutual transcript verification after staged ClientHello checks.
///
/// This preserves the signature-first dynamic-process boundary without
/// repeating signature verification. The exact context supplied here must be
/// the one used by [`verify_client_hello_context_v1`].
///
/// # Errors
///
/// Returns [`BrokerSessionTranscriptError`] for a substituted context, invalid
/// negotiation, BrokerHello signature/context/cross-link mismatch, or equal
/// hello nonces.
pub fn verify_broker_session_transcript_after_client_v1(
    verified_client: &ContextVerifiedClientHelloV1,
    broker: &CanonicalBrokerServerHelloV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionTranscriptError> {
    let client = &verified_client.client.client;
    context.require_all_active()?;
    require_client_context(client, context)?;
    let client_key = context.key(BrokerSessionKeyUsageV1::ClientHello);
    if client_key.signer() != &verified_client.client.signer
        || client_key.public_key() != &verified_client.client.public_key
    {
        return Err(BrokerSessionTranscriptError::ContextMismatch);
    }
    let negotiation = validate_authenticated_negotiation_v1(
        client.message(),
        broker.message(),
        context.protocol(),
        context.protocol_major(),
        context.protocol_minor(),
        context.audience(),
    )?;
    verify_remaining_hello_pair(client, broker, context, negotiation)
}

fn verify_remaining_hello_pair(
    client: &CanonicalBrokerClientHelloV1,
    broker: &CanonicalBrokerServerHelloV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    negotiation: ValidatedBrokerSessionNegotiationV1,
) -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionTranscriptError> {
    let protected_context_digest = context.protected_context_digest();
    let client_subject = client.signed_artifact().subject();
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

fn require_client_context(
    client: &CanonicalBrokerClientHelloV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<(), BrokerSessionTranscriptError> {
    let protected_context_digest = context.protected_context_digest();
    let subject = client.signed_artifact().subject();
    if subject.node_id != context.node_id()
        || subject.boot_id != context.boot_id()
        || subject.protocol != context.protocol()
        || subject.major != context.protocol_major()
        || subject.minor != context.protocol_minor()
        || subject.audience != context.audience()
        || subject.client_process() != context.client_process()
        || subject.protected_context_digest() != protected_context_digest
        || subject.cleared_fields_digest() != client.cleared_fields_digest()
        || client.message().protocol_major != u32::from(context.protocol_major())
        || client.message().protocol_minor != u32::from(context.protocol_minor())
        || client.message().audience.as_known() != Some(context.audience())
    {
        return Err(BrokerSessionTranscriptError::ContextMismatch);
    }

    Ok(())
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
