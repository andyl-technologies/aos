//! Canonical protobuf projections and authenticated packet ceilings.
//!
//! A projection clears only the authentication field in its containing
//! message, canonically re-encodes that message, and hashes the independent
//! terminal-NUL domain followed by a four-byte big-endian length and the exact
//! bytes. Full received bytes must equal canonical re-encoding before any
//! signature is checked, closing unknown fields, reordered fields, duplicate
//! known fields, non-minimal varints, and trailing data.
//!
//! These routines validate canonical projection structure and profile-owned
//! packet ceilings, not complete method semantics. The authenticated session
//! composite additionally binds method, audience, authorization carrier,
//! required features, body/header identity, response budget, descriptor table,
//! disposition table, and success-body shape before candidate state advances.
//! Each method adapter must still supply its audience-specific body proof before
//! it may authorize an effect or consume a descriptor.

use aos_proto::aos::sandbox::local::v1::{
    BrokerClientHello, BrokerDescriptorEntry, BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope,
    BrokerResponseEnvelope, BrokerServerHello, MountResult,
};
use aos_sandbox_core::{FeatureRef, validate_required_features};
use buffa::Message as _;

use crate::artifact::{
    BrokerSessionArtifactError, SignedBrokerClientHelloV1, SignedBrokerHelloV1,
    SignedBrokerOutcomeV1, SignedBrokerRequestV1, length_prefixed_digest,
};
use crate::model::{
    SIGNED_BROKER_HELLO_BYTES, SIGNED_BROKER_OUTCOME_BYTES, SIGNED_BROKER_REQUEST_BYTES,
    SIGNED_CLIENT_HELLO_BYTES,
};
use crate::profile::{
    authenticated_broker_method_profile_v1, authenticated_request_predecode_maximum_bytes_v1,
};

/// Existing total ClientHello ceiling retained by the authenticated profile.
pub const CLIENT_HELLO_MAXIMUM_BYTES: usize = 65_536;
/// Largest cleared ClientHello projection after reserving its 357-byte field.
pub const CLIENT_HELLO_CLEARED_MAXIMUM_BYTES: usize = 65_179;
/// Existing total BrokerHello ceiling retained by the authenticated profile.
pub const SERVER_HELLO_MAXIMUM_BYTES: usize = 65_536;
/// Largest cleared BrokerHello projection after reserving its 389-byte field.
pub const SERVER_HELLO_CLEARED_MAXIMUM_BYTES: usize = 65_147;
/// Existing ordinary request ceiling retained by the authenticated profile.
pub const AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES: usize = 1_048_576;
/// Largest ordinary cleared request after reserving its 311-byte field.
pub const AUTHENTICATED_ORDINARY_REQUEST_CLEARED_MAXIMUM_BYTES: usize = 1_048_265;
/// Existing Host query request ceiling retained by the authenticated profile.
pub const AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES: usize = 1_048_640;
/// Largest Host query cleared request after reserving its 311-byte field.
pub const AUTHENTICATED_HOST_QUERY_CLEARED_MAXIMUM_BYTES: usize = 1_048_329;
/// Existing Mount PrepareCatalog request ceiling retained by the profile.
pub const AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES: usize = 1_081_408;
/// Largest cleared Mount PrepareCatalog request after reserving its field.
pub const AUTHENTICATED_MOUNT_PREPARE_CATALOG_CLEARED_MAXIMUM_BYTES: usize = 1_081_097;
/// Authenticated response total encoded ceiling, exactly 15 MiB.
pub const AUTHENTICATED_RESPONSE_MAXIMUM_BYTES: usize = 15_728_640;
/// Minimum response ceiling accepted in authenticated negotiation and headers.
pub const AUTHENTICATED_RESPONSE_MINIMUM_BYTES: u32 = 4_096;
/// Largest cleared response after reserving its 343-byte field.
pub const AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES: usize = 15_728_297;

const CLIENT_HELLO_FIELD_CONTRIBUTION: usize = 357;
const SERVER_HELLO_FIELD_CONTRIBUTION: usize = 389;
const REQUEST_FIELD_CONTRIBUTION: usize = 311;
const RESPONSE_FIELD_CONTRIBUTION: usize = 343;

const _: [(); CLIENT_HELLO_FIELD_CONTRIBUTION] = [(); 1 + 2 + SIGNED_CLIENT_HELLO_BYTES];
const _: [(); SERVER_HELLO_FIELD_CONTRIBUTION] = [(); 1 + 2 + SIGNED_BROKER_HELLO_BYTES];
const _: [(); REQUEST_FIELD_CONTRIBUTION] = [(); 1 + 2 + SIGNED_BROKER_REQUEST_BYTES];
const _: [(); RESPONSE_FIELD_CONTRIBUTION] = [(); 1 + 2 + SIGNED_BROKER_OUTCOME_BYTES];
const _: [(); CLIENT_HELLO_MAXIMUM_BYTES] =
    [(); CLIENT_HELLO_CLEARED_MAXIMUM_BYTES + CLIENT_HELLO_FIELD_CONTRIBUTION];
const _: [(); SERVER_HELLO_MAXIMUM_BYTES] =
    [(); SERVER_HELLO_CLEARED_MAXIMUM_BYTES + SERVER_HELLO_FIELD_CONTRIBUTION];
const _: [(); AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES] =
    [(); AUTHENTICATED_ORDINARY_REQUEST_CLEARED_MAXIMUM_BYTES + REQUEST_FIELD_CONTRIBUTION];
const _: [(); AUTHENTICATED_HOST_QUERY_MAXIMUM_BYTES] =
    [(); AUTHENTICATED_HOST_QUERY_CLEARED_MAXIMUM_BYTES + REQUEST_FIELD_CONTRIBUTION];
const _: [(); AUTHENTICATED_MOUNT_PREPARE_CATALOG_MAXIMUM_BYTES] =
    [(); AUTHENTICATED_MOUNT_PREPARE_CATALOG_CLEARED_MAXIMUM_BYTES + REQUEST_FIELD_CONTRIBUTION];
const _: [(); AUTHENTICATED_RESPONSE_MAXIMUM_BYTES] =
    [(); AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES + RESPONSE_FIELD_CONTRIBUTION];

/// Converts an authenticated total response ceiling to its cleared packet budget.
///
/// The returned budget reserves the exact 343-byte BrokerOutcome protobuf
/// contribution owned by this projection layer.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError::TooLarge`] unless `total_bytes` is
/// within the authenticated response profile and can reserve the full carrier.
pub fn authenticated_response_cleared_budget_v1(
    total_bytes: u32,
) -> Result<u32, BrokerSessionProjectionError> {
    let total = usize::try_from(total_bytes).map_err(|_| BrokerSessionProjectionError::TooLarge)?;
    if !(usize::try_from(AUTHENTICATED_RESPONSE_MINIMUM_BYTES).unwrap_or(usize::MAX)
        ..=AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
        .contains(&total)
    {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    total_bytes
        .checked_sub(u32::try_from(RESPONSE_FIELD_CONTRIBUTION).unwrap_or(u32::MAX))
        .ok_or(BrokerSessionProjectionError::TooLarge)
}

const CLIENT_HELLO_FIELDS_DOMAIN: &[u8] = b"aos-sandbox-broker-session-client-hello-fields-v1\0";
const SERVER_HELLO_FIELDS_DOMAIN: &[u8] = b"aos-sandbox-broker-session-server-hello-fields-v1\0";
const REQUEST_FIELDS_DOMAIN: &[u8] = b"aos-sandbox-broker-session-request-fields-v1\0";
const RESPONSE_FIELDS_DOMAIN: &[u8] = b"aos-sandbox-broker-session-outcome-fields-v1\0";
const MAXIMUM_FEATURES: usize = 64;
const MAXIMUM_METHODS: usize = 22;

/// Reports a malformed, noncanonical, incorrectly bounded, or wrong-sized packet.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionProjectionError {
    /// Protobuf parsing failed.
    #[error("malformed Broker Session Authentication protobuf: {0}")]
    Malformed(String),
    /// The full received message is not its one canonical encoding.
    #[error("noncanonical Broker Session Authentication protobuf")]
    Noncanonical,
    /// A known or nested unknown field is present.
    #[error("unknown Broker Session Authentication protobuf field")]
    UnknownFields,
    /// The containing authentication field is absent or has the wrong exact width.
    #[error("invalid Broker Session Authentication carrier width")]
    InvalidAuthenticationField,
    /// The full or cleared message exceeds its exact profile ceiling.
    #[error("Broker Session Authentication protobuf exceeds its packet ceiling")]
    TooLarge,
    /// A closed enum or ordered descriptor table is invalid.
    #[error("invalid Broker Session Authentication protobuf semantics")]
    InvalidSemantics,
    /// The signed carrier itself is invalid.
    #[error("invalid signed Broker Session Authentication carrier: {0}")]
    Artifact(#[from] BrokerSessionArtifactError),
}

/// Carries one canonical ClientHello and its cleared projection digest.
#[derive(Clone, Debug)]
pub struct CanonicalBrokerClientHelloV1 {
    message: BrokerClientHello,
    signed: SignedBrokerClientHelloV1,
    cleared_digest: [u8; 32],
}

/// Carries one canonical BrokerHello and its cleared projection digest.
#[derive(Clone, Debug)]
pub struct CanonicalBrokerServerHelloV1 {
    message: BrokerServerHello,
    signed: SignedBrokerHelloV1,
    cleared_digest: [u8; 32],
}

/// Carries one canonical request and its complete cleared projection digest.
#[derive(Clone, Debug)]
pub struct CanonicalBrokerRequestEnvelopeV1 {
    message: BrokerRequestEnvelope,
    signed: SignedBrokerRequestV1,
    cleared_digest: [u8; 32],
    encoded_len: usize,
}

/// Carries one canonical response and its complete cleared projection digest.
#[derive(Clone, Debug)]
pub struct CanonicalBrokerResponseEnvelopeV1 {
    message: BrokerResponseEnvelope,
    signed: SignedBrokerOutcomeV1,
    cleared_digest: [u8; 32],
    encoded_len: usize,
    encoded_bytes: Vec<u8>,
}

macro_rules! projection_accessors {
    ($type:ty, $message:ty, $signed:ty) => {
        impl $type {
            /// Returns the canonical decoded protobuf message.
            #[must_use]
            pub const fn message(&self) -> &$message {
                &self.message
            }
            /// Returns the decoded signed authentication carrier.
            #[must_use]
            pub const fn signed_artifact(&self) -> &$signed {
                &self.signed
            }
            /// Returns the domain-separated digest of the cleared canonical message.
            #[must_use]
            pub const fn cleared_fields_digest(&self) -> [u8; 32] {
                self.cleared_digest
            }
        }
    };
}

projection_accessors!(
    CanonicalBrokerClientHelloV1,
    BrokerClientHello,
    SignedBrokerClientHelloV1
);
projection_accessors!(
    CanonicalBrokerServerHelloV1,
    BrokerServerHello,
    SignedBrokerHelloV1
);
projection_accessors!(
    CanonicalBrokerRequestEnvelopeV1,
    BrokerRequestEnvelope,
    SignedBrokerRequestV1
);
projection_accessors!(
    CanonicalBrokerResponseEnvelopeV1,
    BrokerResponseEnvelope,
    SignedBrokerOutcomeV1
);

impl CanonicalBrokerRequestEnvelopeV1 {
    /// Returns the exact total encoded request length including authentication.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

impl CanonicalBrokerResponseEnvelopeV1 {
    /// Returns the exact total encoded response length including authentication.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    /// Returns the exact canonical response packet supplied to the decoder.
    #[must_use]
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.encoded_bytes
    }
}

/// Commits a canonical Mount Apply outcome with its qualification field omitted.
///
/// This acyclic projection lets a signed qualification record bind the rest of
/// the outcome while the full signed outcome independently embeds the digest of
/// that complete qualification record.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] unless `outcome` is a successful
/// Mount Apply result whose nested body is canonical and has no unknown fields.
pub fn mount_qualification_outcome_projection_v1(
    outcome: &CanonicalBrokerResponseEnvelopeV1,
) -> Result<[u8; 32], BrokerSessionProjectionError> {
    if outcome.message.method.as_known() != Some(BrokerMethod::BROKER_METHOD_MOUNT_APPLY)
        || outcome.message.error.as_option().is_some()
    {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    let mut result = MountResult::decode_from_slice(&outcome.message.body)
        .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()))?;
    if !result.__buffa_unknown_fields.is_empty() || result.encode_to_vec() != outcome.message.body {
        return Err(BrokerSessionProjectionError::Noncanonical);
    }
    result.filesystem_worker_qualification_commitment.clear();

    let mut projection = outcome.message.clone();
    projection.body = result.encode_to_vec();
    projection.signed_session_outcome.clear();
    outcome_fields_digest_v1(&projection)
}

/// Digests one outbound ClientHello whose authentication field is still clear.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for a nonempty carrier, unknown
/// nested field, or cleared message above its exact ceiling.
pub fn client_hello_fields_digest_v1(
    message: &BrokerClientHello,
) -> Result<[u8; 32], BrokerSessionProjectionError> {
    if !message.signed_session_hello.is_empty()
        || !message.__buffa_unknown_fields.is_empty()
        || message
            .required_features
            .iter()
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
    {
        return Err(BrokerSessionProjectionError::UnknownFields);
    }
    digest_cleared(
        CLIENT_HELLO_FIELDS_DOMAIN,
        &message.encode_to_vec(),
        CLIENT_HELLO_CLEARED_MAXIMUM_BYTES,
    )
}

/// Digests one outbound BrokerHello whose authentication field is still clear.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for a nonempty carrier, unknown
/// nested field, or cleared message above its exact ceiling.
pub fn server_hello_fields_digest_v1(
    message: &BrokerServerHello,
) -> Result<[u8; 32], BrokerSessionProjectionError> {
    if !message.signed_session_hello.is_empty()
        || !message.__buffa_unknown_fields.is_empty()
        || message
            .features
            .iter()
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
        || message.error.as_option().is_some_and(error_has_unknown)
    {
        return Err(BrokerSessionProjectionError::UnknownFields);
    }
    digest_cleared(
        SERVER_HELLO_FIELDS_DOMAIN,
        &message.encode_to_vec(),
        SERVER_HELLO_CLEARED_MAXIMUM_BYTES,
    )
}

/// Attaches one signed ClientHello artifact and canonically encodes its packet.
///
/// This helper performs no signing and does not establish protected custody.
/// The caller must have computed the artifact over the cleared message.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] unless the cleared message has an
/// empty authentication field and the resulting packet passes the exact
/// canonical authenticated ClientHello decoder.
pub fn encode_signed_client_hello_packet_v1(
    mut message: BrokerClientHello,
    signed: &SignedBrokerClientHelloV1,
) -> Result<Vec<u8>, BrokerSessionProjectionError> {
    if !message.signed_session_hello.is_empty() {
        return Err(BrokerSessionProjectionError::InvalidAuthenticationField);
    }
    message.signed_session_hello = signed.to_canonical_bytes();
    let encoded = message.encode_to_vec();
    decode_canonical_client_hello_v1(&encoded)?;
    Ok(encoded)
}

/// Attaches one signed BrokerHello artifact and canonically encodes its packet.
///
/// This helper performs no signing and does not establish protected custody.
/// The caller must have computed the artifact over the cleared message.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] unless the cleared message has an
/// empty authentication field and the resulting packet passes the exact
/// canonical authenticated BrokerHello decoder.
pub fn encode_signed_server_hello_packet_v1(
    mut message: BrokerServerHello,
    signed: &SignedBrokerHelloV1,
) -> Result<Vec<u8>, BrokerSessionProjectionError> {
    if !message.signed_session_hello.is_empty() {
        return Err(BrokerSessionProjectionError::InvalidAuthenticationField);
    }
    message.signed_session_hello = signed.to_canonical_bytes();
    let encoded = message.encode_to_vec();
    decode_canonical_server_hello_v1(&encoded)?;
    Ok(encoded)
}

/// Attaches one signed ClientRecord artifact and canonically encodes its packet.
///
/// This projection-only helper performs no signing or method authorization. It
/// requires the artifact to commit the exact cleared message and method.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] unless the cleared message has an
/// empty authentication field, exactly matches the signed subject, and the
/// resulting packet passes the canonical authenticated request decoder.
pub fn encode_signed_request_packet_v1(
    mut message: BrokerRequestEnvelope,
    signed: &SignedBrokerRequestV1,
) -> Result<Vec<u8>, BrokerSessionProjectionError> {
    if !message.signed_session_request.is_empty() {
        return Err(BrokerSessionProjectionError::InvalidAuthenticationField);
    }
    if message.method.as_known() != Some(signed.method())
        || request_fields_digest_v1(&message)? != signed.subject().cleared_fields_digest()
    {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }

    message.signed_session_request = signed.to_canonical_bytes();
    let encoded = message.encode_to_vec();
    let canonical = decode_canonical_request_v1(&encoded)?;
    if canonical.cleared_fields_digest() != signed.subject().cleared_fields_digest() {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    Ok(encoded)
}

/// Attaches one signed BrokerOutcome artifact and canonically encodes its packet.
///
/// This projection-only helper performs no signing or method authorization. It
/// requires the artifact to commit the exact cleared message, request ID, and method.
/// The signed-request cross-link is validated later by the traffic state.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] unless the cleared message has an
/// empty authentication field, exactly matches the signed subject, and the
/// resulting packet passes the canonical authenticated response decoder.
pub fn encode_signed_response_packet_v1(
    mut message: BrokerResponseEnvelope,
    signed: &SignedBrokerOutcomeV1,
) -> Result<Vec<u8>, BrokerSessionProjectionError> {
    if !message.signed_session_outcome.is_empty() {
        return Err(BrokerSessionProjectionError::InvalidAuthenticationField);
    }
    if message.method.as_known() != Some(signed.method())
        || message.request_id.as_slice() != signed.subject().request_id()
        || outcome_fields_digest_v1(&message)? != signed.subject().cleared_fields_digest()
    {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }

    message.signed_session_outcome = signed.to_canonical_bytes();
    let encoded = message.encode_to_vec();
    let canonical = decode_canonical_response_v1(&encoded)?;
    if canonical.cleared_fields_digest() != signed.subject().cleared_fields_digest() {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    Ok(encoded)
}

/// Digests one outbound request whose authentication field is still clear.
///
/// The canonical bytes commit the exact body, ordered contiguous descriptor
/// `(index, role)` table, and every byte and presence bit of the authorization
/// quartet.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for a nonempty carrier, invalid
/// nested structure, or cleared message above its method-specific ceiling.
pub fn request_fields_digest_v1(
    message: &BrokerRequestEnvelope,
) -> Result<[u8; 32], BrokerSessionProjectionError> {
    if !message.signed_session_request.is_empty() {
        return Err(BrokerSessionProjectionError::InvalidAuthenticationField);
    }
    let method = message
        .method
        .as_known()
        .ok_or(BrokerSessionProjectionError::InvalidSemantics)?;
    let profile = authenticated_broker_method_profile_v1(method)
        .ok_or(BrokerSessionProjectionError::InvalidSemantics)?;
    validate_request_nested(message)?;
    digest_cleared(
        REQUEST_FIELDS_DOMAIN,
        &message.encode_to_vec(),
        profile.cleared_request_maximum_bytes(),
    )
}

/// Digests one outbound response whose authentication field is still clear.
///
/// The canonical bytes commit request ID, method, body, ordered response
/// descriptor table, every BrokerError field including the exact missing
/// feature triple, and ordered request-descriptor dispositions.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for a nonempty carrier, invalid
/// nested structure, or cleared response above 15,728,297 bytes.
pub fn outcome_fields_digest_v1(
    message: &BrokerResponseEnvelope,
) -> Result<[u8; 32], BrokerSessionProjectionError> {
    if !message.signed_session_outcome.is_empty() {
        return Err(BrokerSessionProjectionError::InvalidAuthenticationField);
    }
    validate_response_nested(message)?;
    digest_cleared(
        RESPONSE_FIELDS_DOMAIN,
        &message.encode_to_vec(),
        AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES,
    )
}

/// Decodes a canonical authenticated ClientHello at its exact total/cleared ceilings.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for malformed, noncanonical,
/// unknown, oversized, or wrong-sized authentication bytes.
pub fn decode_canonical_client_hello_v1(
    bytes: &[u8],
) -> Result<CanonicalBrokerClientHelloV1, BrokerSessionProjectionError> {
    if bytes.len() > CLIENT_HELLO_MAXIMUM_BYTES {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let mut message = BrokerClientHello::decode_from_slice(bytes)
        .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()))?;
    require_canonical(bytes, &message)?;
    if !message.__buffa_unknown_fields.is_empty()
        || message
            .required_features
            .iter()
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
    {
        return Err(BrokerSessionProjectionError::UnknownFields);
    }
    validate_feature_set(&message.required_features)?;
    validate_method_set(&message.required_methods)?;
    let signed = SignedBrokerClientHelloV1::from_canonical_bytes(&message.signed_session_hello)?;
    message.signed_session_hello.clear();
    let cleared = message.encode_to_vec();
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        CLIENT_HELLO_CLEARED_MAXIMUM_BYTES,
        CLIENT_HELLO_FIELD_CONTRIBUTION,
    )?;
    Ok(CanonicalBrokerClientHelloV1 {
        message,
        signed,
        cleared_digest: length_prefixed_digest(CLIENT_HELLO_FIELDS_DOMAIN, &cleared),
    })
}

/// Decodes a canonical authenticated BrokerHello at its exact total/cleared ceilings.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for malformed, noncanonical,
/// unknown, oversized, or wrong-sized authentication bytes.
pub fn decode_canonical_server_hello_v1(
    bytes: &[u8],
) -> Result<CanonicalBrokerServerHelloV1, BrokerSessionProjectionError> {
    if bytes.len() > SERVER_HELLO_MAXIMUM_BYTES {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let mut message = BrokerServerHello::decode_from_slice(bytes)
        .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()))?;
    require_canonical(bytes, &message)?;
    if !message.__buffa_unknown_fields.is_empty()
        || message
            .features
            .iter()
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
        || message.error.as_option().is_some_and(error_has_unknown)
    {
        return Err(BrokerSessionProjectionError::UnknownFields);
    }
    validate_feature_set(&message.features)?;
    validate_method_set(&message.methods)?;
    let signed = SignedBrokerHelloV1::from_canonical_bytes(&message.signed_session_hello)?;
    message.signed_session_hello.clear();
    let cleared = message.encode_to_vec();
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        SERVER_HELLO_CLEARED_MAXIMUM_BYTES,
        SERVER_HELLO_FIELD_CONTRIBUTION,
    )?;
    Ok(CanonicalBrokerServerHelloV1 {
        message,
        signed,
        cleared_digest: length_prefixed_digest(SERVER_HELLO_FIELDS_DOMAIN, &cleared),
    })
}

/// Decodes a canonical authenticated request and commits all body, descriptor,
/// and authorization-quartet bytes and presence.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for malformed, noncanonical,
/// unknown, oversized, or semantically invalid request bytes.
pub fn decode_canonical_request_v1(
    bytes: &[u8],
) -> Result<CanonicalBrokerRequestEnvelopeV1, BrokerSessionProjectionError> {
    if bytes.len() > authenticated_request_predecode_maximum_bytes_v1() {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let mut message = BrokerRequestEnvelope::decode_from_slice(bytes)
        .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()))?;
    let method = message
        .method
        .as_known()
        .ok_or(BrokerSessionProjectionError::InvalidSemantics)?;
    let profile = authenticated_broker_method_profile_v1(method)
        .ok_or(BrokerSessionProjectionError::InvalidSemantics)?;
    if bytes.len() > profile.total_request_maximum_bytes() {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    require_canonical(bytes, &message)?;
    validate_request_nested(&message)?;
    let signed = SignedBrokerRequestV1::from_canonical_bytes(&message.signed_session_request)?;
    if message.method.as_known() != Some(signed.method()) {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    message.signed_session_request.clear();
    let cleared = message.encode_to_vec();
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        profile.cleared_request_maximum_bytes(),
        REQUEST_FIELD_CONTRIBUTION,
    )?;
    Ok(CanonicalBrokerRequestEnvelopeV1 {
        message,
        signed,
        cleared_digest: length_prefixed_digest(REQUEST_FIELDS_DOMAIN, &cleared),
        encoded_len: bytes.len(),
    })
}

/// Decodes a canonical authenticated response and commits its exact body,
/// ordered descriptor table, complete error, and ordered dispositions.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] for malformed, noncanonical,
/// unknown, oversized, or semantically invalid response bytes.
pub fn decode_canonical_response_v1(
    bytes: &[u8],
) -> Result<CanonicalBrokerResponseEnvelopeV1, BrokerSessionProjectionError> {
    if bytes.len() > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let mut message = BrokerResponseEnvelope::decode_from_slice(bytes)
        .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()))?;
    require_canonical(bytes, &message)?;
    validate_response_nested(&message)?;
    let signed = SignedBrokerOutcomeV1::from_canonical_bytes(&message.signed_session_outcome)?;
    if message.method.as_known() != Some(signed.method()) {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    message.signed_session_outcome.clear();
    let cleared = message.encode_to_vec();
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES,
        RESPONSE_FIELD_CONTRIBUTION,
    )?;
    Ok(CanonicalBrokerResponseEnvelopeV1 {
        message,
        signed,
        cleared_digest: length_prefixed_digest(RESPONSE_FIELDS_DOMAIN, &cleared),
        encoded_len: bytes.len(),
        encoded_bytes: bytes.to_vec(),
    })
}

/// Validates authenticated negotiated/request response ceilings.
///
/// # Errors
///
/// Returns [`BrokerSessionProjectionError`] unless both ceilings are nonzero,
/// the request ceiling is no larger than the negotiated ceiling, and both fit
/// the authenticated 15 MiB total response limit.
pub fn validate_authenticated_response_budget_v1(
    negotiated_maximum: u32,
    request_maximum: u32,
) -> Result<(), BrokerSessionProjectionError> {
    let ceiling = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
        .map_err(|_| BrokerSessionProjectionError::TooLarge)?;
    if negotiated_maximum < AUTHENTICATED_RESPONSE_MINIMUM_BYTES
        || request_maximum < AUTHENTICATED_RESPONSE_MINIMUM_BYTES
        || negotiated_maximum > ceiling
        || request_maximum > negotiated_maximum
    {
        Err(BrokerSessionProjectionError::TooLarge)
    } else {
        Ok(())
    }
}

fn require_canonical<M: buffa::Message>(
    bytes: &[u8],
    message: &M,
) -> Result<(), BrokerSessionProjectionError> {
    if message.encode_to_vec() == bytes {
        Ok(())
    } else {
        Err(BrokerSessionProjectionError::Noncanonical)
    }
}

fn digest_cleared(
    domain: &[u8],
    bytes: &[u8],
    maximum: usize,
) -> Result<[u8; 32], BrokerSessionProjectionError> {
    if bytes.len() > maximum {
        Err(BrokerSessionProjectionError::TooLarge)
    } else {
        Ok(length_prefixed_digest(domain, bytes))
    }
}

fn require_projection_sizes(
    total: usize,
    cleared: usize,
    cleared_maximum: usize,
    contribution: usize,
) -> Result<(), BrokerSessionProjectionError> {
    if cleared > cleared_maximum || cleared.checked_add(contribution) != Some(total) {
        Err(BrokerSessionProjectionError::TooLarge)
    } else {
        Ok(())
    }
}

fn validate_request_nested(
    message: &BrokerRequestEnvelope,
) -> Result<(), BrokerSessionProjectionError> {
    if !message.__buffa_unknown_fields.is_empty()
        || message
            .method
            .as_known()
            .is_none_or(|method| method == BrokerMethod::BROKER_METHOD_UNSPECIFIED)
        || message.body.is_empty()
        || message
            .descriptors
            .iter()
            .enumerate()
            .any(|(index, entry)| {
                !entry.__buffa_unknown_fields.is_empty()
                    || usize::try_from(entry.index) != Ok(index)
                    || entry.role.as_known().is_none_or(|role| {
                        role == aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED
                    })
            })
        || descriptor_roles_repeat(&message.descriptors)
        || message
            .authorization
            .as_option()
            .is_some_and(|authorization| !authorization.__buffa_unknown_fields.is_empty())
    {
        Err(BrokerSessionProjectionError::InvalidSemantics)
    } else {
        Ok(())
    }
}

fn validate_response_nested(
    message: &BrokerResponseEnvelope,
) -> Result<(), BrokerSessionProjectionError> {
    if !message.__buffa_unknown_fields.is_empty()
        || message.request_id.len() != 16
        || message.request_id.iter().all(|byte| *byte == 0)
        || message
            .method
            .as_known()
            .is_none_or(|method| method == BrokerMethod::BROKER_METHOD_UNSPECIFIED)
        || message
            .descriptors
            .iter()
            .enumerate()
            .any(|(index, entry)| {
                !entry.__buffa_unknown_fields.is_empty()
                    || usize::try_from(entry.index) != Ok(index)
                    || entry.role.as_known().is_none_or(|role| {
                        role == aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED
                    })
            })
        || descriptor_roles_repeat(&message.descriptors)
        || message
            .request_descriptor_dispositions
            .iter()
            .enumerate()
            .any(|(index, entry)| {
                !entry.__buffa_unknown_fields.is_empty()
                    || usize::try_from(entry.request_index) != Ok(index)
                    || entry.role.as_known().is_none_or(|role| {
                        role == aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED
                    })
                    || entry.disposition.as_known().is_none_or(|disposition| {
                        disposition == aos_proto::aos::sandbox::local::v1::BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_UNSPECIFIED
                    })
            })
        || message.error.as_option().is_some_and(error_has_unknown)
    {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    if let Some(error) = message.error.as_option() {
        let has_missing = error.missing_feature.as_option().is_some();
        if error
            .code
            .as_known()
            .is_none_or(|code| code == BrokerErrorCode::BROKER_ERROR_CODE_UNSPECIFIED)
            || (error.code.as_known()
                == Some(BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE))
                != has_missing
        {
            return Err(BrokerSessionProjectionError::InvalidSemantics);
        }
    }
    Ok(())
}

fn descriptor_roles_repeat(entries: &[BrokerDescriptorEntry]) -> bool {
    entries.iter().enumerate().any(|(index, entry)| {
        entries[..index]
            .iter()
            .any(|prior| prior.role == entry.role)
    })
}

fn error_has_unknown(error: &aos_proto::aos::sandbox::local::v1::BrokerError) -> bool {
    !error.__buffa_unknown_fields.is_empty()
        || error
            .missing_feature
            .as_option()
            .is_some_and(|feature| !feature.__buffa_unknown_fields.is_empty())
}

fn validate_feature_set(
    features: &[aos_proto::aos::sandbox::local::v1::Feature],
) -> Result<(), BrokerSessionProjectionError> {
    if features.len() > MAXIMUM_FEATURES {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    let values = features
        .iter()
        .map(|feature| FeatureRef::new(feature.namespace.clone(), feature.major, feature.minor))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BrokerSessionProjectionError::InvalidSemantics)?;
    if values.windows(2).any(|window| window[0] >= window[1])
        || validate_required_features(&values).is_err()
    {
        Err(BrokerSessionProjectionError::InvalidSemantics)
    } else {
        Ok(())
    }
}

fn validate_method_set(
    methods: &[buffa::EnumValue<BrokerMethod>],
) -> Result<(), BrokerSessionProjectionError> {
    if methods.is_empty()
        || methods.len() > MAXIMUM_METHODS
        || methods.iter().any(|method| {
            method
                .as_known()
                .is_none_or(|value| value == BrokerMethod::BROKER_METHOD_UNSPECIFIED)
        })
        || methods.windows(2).any(|window| {
            window[0].as_known().map_or(i32::MAX, |value| value as i32)
                >= window[1].as_known().map_or(i32::MAX, |value| value as i32)
        })
    {
        Err(BrokerSessionProjectionError::InvalidSemantics)
    } else {
        Ok(())
    }
}
